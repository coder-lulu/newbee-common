// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package audit 高性能审计中间件 - 精简版
package audit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// 高性能对象池和全局状态
var (
	auditEventPool = sync.Pool{
		New: func() interface{} { return &AuditEvent{} },
	}
	responseWriterPool = sync.Pool{
		New: func() interface{} { return &AuditResponseWriter{} },
	}
	droppedEvents int64
)

// 上下文键
type contextKey string

const (
	userIDKey   contextKey = "audit_user_id"
	tenantIDKey contextKey = "audit_tenant_id"
)

// 上下文辅助函数
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

func GetUserID(ctx context.Context) (string, bool) {
	// 首先尝试审计专用的context key
	if userID, ok := ctx.Value(userIDKey).(string); ok && userID != "" {
		return userID, true
	}
	
	// 回退到认证中间件设置的通用key
	if userID, ok := ctx.Value("userID").(string); ok && userID != "" {
		return userID, true
	}
	if userID, ok := ctx.Value("userId").(string); ok && userID != "" {
		return userID, true
	}
	if userID, ok := ctx.Value("user_id").(string); ok && userID != "" {
		return userID, true
	}
	
	return "", false
}

func GetTenantID(ctx context.Context) (string, bool) {
	// 首先尝试审计专用的context key
	if tenantID, ok := ctx.Value(tenantIDKey).(string); ok && tenantID != "" {
		return tenantID, true
	}
	
	// 回退到认证中间件设置的通用key
	if tenantID, ok := ctx.Value("tenantID").(string); ok && tenantID != "" {
		return tenantID, true
	}
	if tenantID, ok := ctx.Value("tenantId").(string); ok && tenantID != "" {
		return tenantID, true
	}
	if tenantID, ok := ctx.Value("tenant_id").(string); ok && tenantID != "" {
		return tenantID, true
	}
	
	// 也尝试数字类型的tenant ID
	if tenantID, ok := ctx.Value("tenantId").(uint64); ok && tenantID != 0 {
		return fmt.Sprintf("%d", tenantID), true
	}
	
	return "", false
}

// 高效ID验证（预编译危险字符检查）
func isValidID(id string) bool {
	return id != "" && len(id) <= 64 && !strings.ContainsAny(id, ";'\"\\<>(){}[]")
}

// AuditConfig 审计配置
type AuditConfig struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	SkipPaths  []string `yaml:"skip_paths" json:"skip_paths"`
	BufferSize int      `yaml:"buffer_size" json:"buffer_size"`
}

// DefaultConfig 默认配置
func DefaultConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:    true,
		SkipPaths:  []string{"/health", "/metrics", "/ping"},
		BufferSize: 1000,
	}
}

// AuditEvent 审计事件
type AuditEvent struct {
	Timestamp int64  `json:"timestamp"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Duration  int64  `json:"duration"`
	IP        string `json:"ip"`
	UserID    string `json:"user_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// Reset 重置事件
func (ae *AuditEvent) Reset() {
	*ae = AuditEvent{}
}

// AuditStorage 存储接口
type AuditStorage interface {
	Save(ctx context.Context, events []AuditEvent) error
	Close() error
}

// AuditMiddleware 审计中间件
type AuditMiddleware struct {
	name      string
	priority  int
	enabled   bool
	config    *AuditConfig
	storage   AuditStorage
	eventChan chan AuditEvent
	skipPaths map[string]bool
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// New 创建审计中间件
func New(config *AuditConfig, storage AuditStorage) *AuditMiddleware {
	if config == nil {
		config = DefaultConfig()
	}
	if storage == nil {
		panic("audit: storage cannot be nil")
	}

	skipPaths := make(map[string]bool, len(config.SkipPaths))
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	audit := &AuditMiddleware{
		name:      "audit",
		priority:  50,
		enabled:   config.Enabled,
		config:    config,
		storage:   storage,
		eventChan: make(chan AuditEvent, config.BufferSize),
		skipPaths: skipPaths,
		stopChan:  make(chan struct{}),
	}

	if config.Enabled {
		audit.wg.Add(1)
		go audit.processEvents()
	}

	return audit
}

// Handle HTTP处理函数
func (am *AuditMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !am.config.Enabled || am.skipPaths[r.URL.Path] {
			next(w, r)
			return
		}

		startTime := time.Now()
		wrapper := responseWriterPool.Get().(*AuditResponseWriter)
		wrapper.ResponseWriter = w
		wrapper.Reset()
		defer responseWriterPool.Put(wrapper)

		next(wrapper, r)

		event := AuditEvent{
			Timestamp: startTime.Unix(),
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    wrapper.GetStatusCode(),
			Duration:  time.Since(startTime).Milliseconds(),
			IP:        extractClientIP(r),
		}

		if ctx := r.Context(); ctx != nil {
			if userID, ok := GetUserID(ctx); ok && isValidID(userID) {
				event.UserID = userID
			}
			if tenantID, ok := GetTenantID(ctx); ok && isValidID(tenantID) {
				event.TenantID = tenantID
			}
		}

		select {
		case am.eventChan <- event:
		default:
			atomic.AddInt64(&droppedEvents, 1)
		}
	}
}

// extractClientIP 高效安全的IP提取
func extractClientIP(r *http.Request) string {
	// 优先级：X-Forwarded-For > X-Real-IP > RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && len(xff) < 256 {
		if ip := strings.TrimSpace(strings.Split(xff, ",")[0]); isValidIP(ip) {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" && len(xri) < 128 && isValidIP(xri) {
		return xri
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && isValidIP(host) {
		return host
	}
	return "unknown"
}

// isValidIP 安全高效的IP验证
func isValidIP(ip string) bool {
	// 快速路径：长度和危险字符检查
	if ip == "" || len(ip) > 45 || strings.ContainsAny(ip, ";'\"\\<>(){}[]") {
		return false
	}
	return net.ParseIP(ip) != nil
}

// processEvents 事件处理循环
func (am *AuditMiddleware) processEvents() {
	defer am.wg.Done()
	events := make([]AuditEvent, 0, 100)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event := <-am.eventChan:
			events = append(events, event)
			if len(events) >= 100 {
				am.flushBatch(events)
				events = events[:0]
			}
		case <-ticker.C:
			if len(events) > 0 {
				am.flushBatch(events)
				events = events[:0]
			}
		case <-am.stopChan:
			for len(am.eventChan) > 0 {
				events = append(events, <-am.eventChan)
			}
			if len(events) > 0 {
				am.flushBatch(events)
			}
			return
		}
	}
}

// SaveEventDirectly 直接保存单个事件（绕过事件通道）
func (am *AuditMiddleware) SaveEventDirectly(event AuditEvent) error {
	if !am.config.Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return am.storage.Save(ctx, []AuditEvent{event})
}

// flushBatch 批量刷新事件
func (am *AuditMiddleware) flushBatch(batch []AuditEvent) {
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := am.storage.Save(ctx, batch); err != nil {
		logx.Errorw("Failed to save audit events", logx.Field("error", err))
	}
}

// Stop 停止中间件
func (am *AuditMiddleware) Stop() error {
	close(am.stopChan)
	am.wg.Wait()
	return am.storage.Close()
}

// 标准中间件接口
func (am *AuditMiddleware) Name() string    { return am.name }
func (am *AuditMiddleware) Priority() int   { return am.priority }
func (am *AuditMiddleware) IsEnabled() bool { return am.enabled }
func (am *AuditMiddleware) SetEnabled(enabled bool) {
	am.enabled = enabled
	am.config.Enabled = enabled
}

// GetDroppedEventsCount 获取丢弃事件数
func (am *AuditMiddleware) GetDroppedEventsCount() int64 {
	return atomic.LoadInt64(&droppedEvents)
}

// AuditResponseWriter 响应包装器
type AuditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// Reset 重置包装器
func (w *AuditResponseWriter) Reset() {
	w.statusCode = 200
	w.written = false
}

func (w *AuditResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *AuditResponseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.statusCode = 200
		w.written = true
	}
	return w.ResponseWriter.Write(data)
}

func (w *AuditResponseWriter) GetStatusCode() int {
	if w.statusCode == 0 {
		return 200
	}
	return w.statusCode
}

