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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/audit/filter"
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

// AuditConfig 增强审计配置
type AuditConfig struct {
	Enabled                 bool     `yaml:"enabled" json:"enabled"`
	SkipPaths              []string `yaml:"skip_paths" json:"skip_paths"`
	BufferSize             int      `yaml:"buffer_size" json:"buffer_size"`
	
	// 增强数据捕获配置
	CaptureRequestData     bool     `yaml:"capture_request_data" json:"capture_request_data"`
	CaptureResponseData    bool     `yaml:"capture_response_data" json:"capture_response_data"`
	MaxRequestDataSize     int      `yaml:"max_request_data_size" json:"max_request_data_size"`
	MaxResponseDataSize    int      `yaml:"max_response_data_size" json:"max_response_data_size"`
	SensitiveFields        []string `yaml:"sensitive_fields" json:"sensitive_fields"`
	EnableDataFiltering    bool     `yaml:"enable_data_filtering" json:"enable_data_filtering"`
}

// DefaultConfig 默认配置 - 包含增强数据捕获
func DefaultConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:                true,
		SkipPaths:             []string{"/health", "/metrics", "/ping"},
		BufferSize:            1000,
		
		// 增强数据捕获默认配置
		CaptureRequestData:    true,
		CaptureResponseData:   false, // 默认不捕获响应，避免性能影响
		MaxRequestDataSize:    2000,
		MaxResponseDataSize:   2000,
		SensitiveFields:       []string{"password", "passwd", "token", "secret", "key", "auth", "credential", "private", "confidential"},
		EnableDataFiltering:   true,
	}
}

// AuditEvent 增强审计事件 - 包含完整的请求/响应数据
type AuditEvent struct {
	Timestamp int64  `json:"timestamp"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Duration  int64  `json:"duration"`
	IP        string `json:"ip"`
	UserID    string `json:"user_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	
	// 增强字段 - 请求/响应数据
	UserAgent    string `json:"user_agent,omitempty"`
	UserName     string `json:"user_name,omitempty"`
	RequestData  string `json:"request_data,omitempty"`
	ResponseData string `json:"response_data,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
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

// AuditMiddleware 增强审计中间件
type AuditMiddleware struct {
	name             string
	priority         int
	enabled          bool
	config           *AuditConfig
	storage          AuditStorage
	eventChan        chan AuditEvent
	skipPaths        map[string]bool
	stopChan         chan struct{}
	wg               sync.WaitGroup
	
	// 增强功能
	sensitiveFilter  *filter.SensitiveFilter
}

// New 创建增强审计中间件
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

	// 初始化敏感数据过滤器
	var sensitiveFilter *filter.SensitiveFilter
	if config.EnableDataFiltering {
		filterConfig := &filter.FilterConfig{
			SensitiveFields: config.SensitiveFields,
			MaskCharacter:   "***FILTERED***",
		}
		var err error
		sensitiveFilter, err = filter.NewSensitiveFilter(filterConfig)
		if err != nil {
			logx.Errorw("Failed to create sensitive filter, data filtering disabled", logx.Field("error", err))
		}
	}

	audit := &AuditMiddleware{
		name:             "enhanced-audit",
		priority:         50,
		enabled:          config.Enabled,
		config:           config,
		storage:          storage,
		eventChan:        make(chan AuditEvent, config.BufferSize),
		skipPaths:        skipPaths,
		stopChan:         make(chan struct{}),
		sensitiveFilter:  sensitiveFilter,
	}

	if config.Enabled {
		audit.wg.Add(1)
		go audit.processEvents()
	}

	return audit
}

// Handle 增强 HTTP处理函数 - 支持完整数据捕获
func (am *AuditMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !am.config.Enabled || am.skipPaths[r.URL.Path] {
			next(w, r)
			return
		}

		startTime := time.Now()
		
		// 捕获请求数据
		requestData := ""
		if am.config.CaptureRequestData {
			requestData = am.captureRequestData(r)
		}
		
		// 创建增强响应包装器
		var wrapper *EnhancedResponseWriter
		if am.config.CaptureResponseData {
			wrapper = &EnhancedResponseWriter{
				ResponseWriter: w,
				body:          strings.Builder{},
				status:        200,
			}
		} else {
			// 使用基本响应包装器
			basicWrapper := responseWriterPool.Get().(*AuditResponseWriter)
			basicWrapper.ResponseWriter = w
			basicWrapper.Reset()
			defer responseWriterPool.Put(basicWrapper)
			
			next(basicWrapper, r)
			
			// 创建基本审计事件
			event := AuditEvent{
				Timestamp: startTime.Unix(),
				Method:    r.Method,
				Path:      r.URL.Path,
				Status:    basicWrapper.GetStatusCode(),
				Duration:  time.Since(startTime).Milliseconds(),
				IP:        extractClientIP(r),
				UserAgent: r.Header.Get("User-Agent"),
				RequestData: requestData,
			}
			
			am.fillUserInfo(&event, r.Context())
			am.sendEvent(event)
			return
		}
		
		// 处理增强响应捕获
		next(wrapper, r)
		
		// 捕获响应数据
		responseData := ""
		if am.config.CaptureResponseData && wrapper.body.Len() > 0 {
			responseData = am.captureResponseData(wrapper.body.String())
		}
		
		// 创建完整审计事件
		event := AuditEvent{
			Timestamp:    startTime.Unix(),
			Method:       r.Method,
			Path:         r.URL.Path,
			Status:       wrapper.status,
			Duration:     time.Since(startTime).Milliseconds(),
			IP:           extractClientIP(r),
			UserAgent:    r.Header.Get("User-Agent"),
			RequestData:  requestData,
			ResponseData: responseData,
		}
		
		am.fillUserInfo(&event, r.Context())
		am.sendEvent(event)
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

// ================== 增强功能实现 ==================

// EnhancedResponseWriter 增强响应包装器 - 支持响应体捕获
type EnhancedResponseWriter struct {
	http.ResponseWriter
	body   strings.Builder
	status int
}

func (w *EnhancedResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *EnhancedResponseWriter) Write(data []byte) (int, error) {
	// 捕获响应数据（有大小限制）
	if w.body.Len() < 5000 { // 限制捕获的响应大小
		w.body.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

// fillUserInfo 填充用户信息到审计事件
func (am *AuditMiddleware) fillUserInfo(event *AuditEvent, ctx context.Context) {
	if ctx == nil {
		return
	}
	
	if userID, ok := GetUserID(ctx); ok && isValidID(userID) {
		event.UserID = userID
	}
	if tenantID, ok := GetTenantID(ctx); ok && isValidID(tenantID) {
		event.TenantID = tenantID
	}
	
	// 提取用户名
	if username, ok := am.extractUsername(ctx); ok {
		event.UserName = username
	}
}

// sendEvent 发送审计事件
func (am *AuditMiddleware) sendEvent(event AuditEvent) {
	select {
	case am.eventChan <- event:
	default:
		atomic.AddInt64(&droppedEvents, 1)
	}
}

// extractUsername 从上下文提取用户名
func (am *AuditMiddleware) extractUsername(ctx context.Context) (string, bool) {
	if username, ok := ctx.Value("username").(string); ok && username != "" {
		return username, true
	}
	if username, ok := ctx.Value("userName").(string); ok && username != "" {
		return username, true
	}
	if username, ok := ctx.Value("user_name").(string); ok && username != "" {
		return username, true
	}
	return "", false
}

// captureRequestData 捕获请求数据
func (am *AuditMiddleware) captureRequestData(r *http.Request) string {
	data := make(map[string]interface{})
	
	// 捕获 GET 查询参数
	if len(r.URL.RawQuery) > 0 {
		data["query"] = r.URL.Query()
	}
	
	// 捕获 POST/PUT/PATCH 请求体
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			if r.Body != nil {
				bodyBytes, err := io.ReadAll(r.Body)
				if err == nil && len(bodyBytes) > 0 {
					// 恢复 Body 供实际请求处理
					r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
					
					// 解析 JSON 并过滤敏感数据
					var bodyData interface{}
					if err := json.Unmarshal(bodyBytes, &bodyData); err == nil {
						data["body"] = am.filterSensitiveData(bodyData)
					} else {
						// 如果不是有效的 JSON，存储为字符串
						bodyStr := string(bodyBytes)
						if len(bodyStr) > 1000 {
							bodyStr = bodyStr[:1000] + "...(truncated)"
						}
						data["body"] = bodyStr
					}
				}
			}
		} else if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			// 解析表单数据
			if err := r.ParseForm(); err == nil {
				formData := make(map[string]interface{})
				for key, values := range r.PostForm {
					if len(values) == 1 {
						formData[key] = am.maskSensitiveField(key, values[0])
					} else {
						formData[key] = values
					}
				}
				data["form"] = formData
			}
		}
	}
	
	// 转换为 JSON 字符串
	if len(data) == 0 {
		return ""
	}
	
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("Error marshaling request data: %v", err)
	}
	
	result := string(jsonBytes)
	if len(result) > am.config.MaxRequestDataSize {
		result = result[:am.config.MaxRequestDataSize] + "...(truncated)"
	}
	
	return result
}

// captureResponseData 捕获响应数据
func (am *AuditMiddleware) captureResponseData(responseBody string) string {
	if responseBody == "" {
		return ""
	}
	
	// 尝试解析为 JSON 并过滤敏感数据
	var responseData interface{}
	if err := json.Unmarshal([]byte(responseBody), &responseData); err == nil {
		filteredData := am.filterSensitiveData(responseData)
		if jsonBytes, err := json.Marshal(filteredData); err == nil {
			result := string(jsonBytes)
			if len(result) > am.config.MaxResponseDataSize {
				result = result[:am.config.MaxResponseDataSize] + "...(truncated)"
			}
			return result
		}
	}
	
	// 如果不是 JSON，直接存储为截断字符串
	if len(responseBody) > am.config.MaxResponseDataSize {
		responseBody = responseBody[:am.config.MaxResponseDataSize] + "...(truncated)"
	}
	return responseBody
}

// filterSensitiveData 过滤敏感数据
func (am *AuditMiddleware) filterSensitiveData(data interface{}) interface{} {
	if !am.config.EnableDataFiltering || am.sensitiveFilter == nil {
		return data
	}
	
	switch v := data.(type) {
	case map[string]interface{}:
		filtered := make(map[string]interface{})
		for key, value := range v {
			if am.isSensitiveField(key) {
				filtered[key] = "***FILTERED***"
			} else {
				filtered[key] = am.filterSensitiveData(value)
			}
		}
		return filtered
	case []interface{}:
		filtered := make([]interface{}, len(v))
		for i, item := range v {
			filtered[i] = am.filterSensitiveData(item)
		}
		return filtered
	default:
		return v
	}
}

// isSensitiveField 检查字段名是否包含敏感信息
func (am *AuditMiddleware) isSensitiveField(fieldName string) bool {
	fieldLower := strings.ToLower(fieldName)
	for _, sensitive := range am.config.SensitiveFields {
		if strings.Contains(fieldLower, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}

// maskSensitiveField 遮蔽敏感字段值
func (am *AuditMiddleware) maskSensitiveField(fieldName, value string) string {
	if am.isSensitiveField(fieldName) {
		return "***FILTERED***"
	}
	return value
}

// NewEnhancedConfig 创建增强配置 - 启用完整数据捕获
func NewEnhancedConfig() *AuditConfig {
	config := DefaultConfig()
	config.CaptureRequestData = true
	config.CaptureResponseData = true
	return config
}

// NewBasicConfig 创建基础配置 - 只捕获请求数据
func NewBasicConfig() *AuditConfig {
	config := DefaultConfig()
	config.CaptureRequestData = true
	config.CaptureResponseData = false
	return config
}
