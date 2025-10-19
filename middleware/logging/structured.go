// Copyright 2024 The NewBee Authors. All Rights Reserved.

package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/zeromicro/go-zero/core/logx"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
	LogLevelFatal LogLevel = "FATAL"
)

// StructuredLog 结构化日志条目
type StructuredLog struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       LogLevel               `json:"level"`
	Component   string                 `json:"component"`
	Message     string                 `json:"message"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
	Error       *ErrorInfo             `json:"error,omitempty"`
	Request     *RequestInfo           `json:"request,omitempty"`
	Response    *ResponseInfo          `json:"response,omitempty"`
	Performance *PerformanceInfo       `json:"performance,omitempty"`
	Context     *ContextInfo           `json:"context,omitempty"`
}

// ErrorInfo 错误信息
type ErrorInfo struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
	Stack   string `json:"stack,omitempty"`
}

// RequestInfo 请求信息
type RequestInfo struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	RequestID  string            `json:"request_id,omitempty"`
}

// ResponseInfo 响应信息
type ResponseInfo struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Size       int64             `json:"size,omitempty"`
}

// PerformanceInfo 性能信息
type PerformanceInfo struct {
	DurationMs    float64           `json:"duration_ms"`
	Operation     string            `json:"operation"`
	Metrics       map[string]string `json:"metrics,omitempty"`
	IsSlowRequest bool              `json:"is_slow_request,omitempty"`
	Threshold     float64           `json:"threshold_ms,omitempty"`
}

// ContextInfo 上下文信息
type ContextInfo struct {
	TenantID   string `json:"tenant_id,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	DeptID     string `json:"dept_id,omitempty"`
	DataScope  string `json:"data_scope,omitempty"`
	RoleCodes  string `json:"role_codes,omitempty"`
	TraceID    string `json:"trace_id,omitempty"`
	SpanID     string `json:"span_id,omitempty"`
}

// StructuredLogger 结构化日志记录器
type StructuredLogger struct {
	component string
	ctx       context.Context
}

// NewStructuredLogger 创建结构化日志记录器
func NewStructuredLogger(component string) *StructuredLogger {
	return &StructuredLogger{
		component: component,
	}
}

// WithContext 设置上下文
func (s *StructuredLogger) WithContext(ctx context.Context) *StructuredLogger {
	return &StructuredLogger{
		component: s.component,
		ctx:       ctx,
	}
}

// LogStructured 记录结构化日志
func (s *StructuredLogger) LogStructured(level LogLevel, message string, entry *StructuredLog) {
	// 设置基本信息
	if entry == nil {
		entry = &StructuredLog{}
	}
	
	entry.Timestamp = time.Now()
	entry.Level = level
	entry.Component = s.component
	entry.Message = message
	
	// 从上下文提取信息
	if s.ctx != nil {
		entry.Context = s.extractContextInfo(s.ctx)
	}
	
	// 序列化为JSON
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// 如果序列化失败，记录简单日志
		s.logFallback(level, message, err)
		return
	}
	
	// 输出JSON日志
	jsonStr := string(jsonBytes)
	if s.ctx != nil {
		logx.WithContext(s.ctx).Info(jsonStr)
	} else {
		logx.Info(jsonStr)
	}
}

// LogMiddlewareStart 记录中间件开始执行
func (s *StructuredLogger) LogMiddlewareStart(operation string, req *RequestInfo) {
	entry := &StructuredLog{
		Request: req,
		Performance: &PerformanceInfo{
			Operation: operation,
		},
		Fields: map[string]interface{}{
			"phase": "start",
		},
	}
	
	s.LogStructured(LogLevelInfo, fmt.Sprintf("middleware %s started", operation), entry)
}

// LogMiddlewareSuccess 记录中间件成功执行
func (s *StructuredLogger) LogMiddlewareSuccess(operation string, duration time.Duration, resp *ResponseInfo) {
	entry := &StructuredLog{
		Response: resp,
		Performance: &PerformanceInfo{
			Operation:  operation,
			DurationMs: float64(duration.Nanoseconds()) / 1e6,
		},
		Fields: map[string]interface{}{
			"phase": "success",
		},
	}
	
	s.LogStructured(LogLevelInfo, fmt.Sprintf("middleware %s completed successfully", operation), entry)
}

// LogMiddlewareError 记录中间件错误
func (s *StructuredLogger) LogMiddlewareError(operation string, duration time.Duration, err error, errorCode int) {
	entry := &StructuredLog{
		Error: &ErrorInfo{
			Type:    fmt.Sprintf("%T", err),
			Message: err.Error(),
			Code:    errorCode,
		},
		Performance: &PerformanceInfo{
			Operation:  operation,
			DurationMs: float64(duration.Nanoseconds()) / 1e6,
		},
		Fields: map[string]interface{}{
			"phase": "error",
		},
	}
	
	s.LogStructured(LogLevelError, fmt.Sprintf("middleware %s failed", operation), entry)
}

// LogSlowOperation 记录慢操作
func (s *StructuredLogger) LogSlowOperation(operation string, duration time.Duration, threshold time.Duration) {
	entry := &StructuredLog{
		Performance: &PerformanceInfo{
			Operation:     operation,
			DurationMs:    float64(duration.Nanoseconds()) / 1e6,
			IsSlowRequest: true,
			Threshold:     float64(threshold.Nanoseconds()) / 1e6,
		},
		Fields: map[string]interface{}{
			"phase": "slow_operation",
		},
	}
	
	s.LogStructured(LogLevelWarn, fmt.Sprintf("slow operation detected: %s", operation), entry)
}

// LogSecurityEvent 记录安全事件
func (s *StructuredLogger) LogSecurityEvent(eventType string, details map[string]interface{}) {
	entry := &StructuredLog{
		Fields: map[string]interface{}{
			"security_event_type": eventType,
			"details":             details,
		},
	}
	
	s.LogStructured(LogLevelWarn, fmt.Sprintf("security event: %s", eventType), entry)
}

// LogHealthCheck 记录健康检查
func (s *StructuredLogger) LogHealthCheck(status string, metrics map[string]string) {
	entry := &StructuredLog{
		Fields: map[string]interface{}{
			"health_status": status,
			"metrics":       metrics,
		},
	}
	
	level := LogLevelInfo
	if status != "healthy" {
		level = LogLevelError
	}
	
	s.LogStructured(level, fmt.Sprintf("health check: %s", status), entry)
}

// 内部方法

// extractContextInfo 从上下文提取信息
func (s *StructuredLogger) extractContextInfo(ctx context.Context) *ContextInfo {
	// 使用标准化的ContextManager来提取信息
	// 这确保了一致性并且避免了直接调用ctx.Value()
	
	cm := &keys.ContextManager{}
	info := &ContextInfo{}
	
	// 使用ContextManager的标准方法提取信息
	info.TenantID = cm.GetTenantID(ctx)
	info.UserID = cm.GetUserID(ctx)
	info.DeptID = cm.GetDeptID(ctx)
	info.DataScope = cm.GetDataScope(ctx)
	
	// 对于其他上下文值，使用标准化的keys
	if roleCodes, ok := ctx.Value(keys.RoleCodesKey).(string); ok {
		info.RoleCodes = roleCodes
	}
	
	if traceID, ok := ctx.Value(keys.TraceIDKey).(string); ok {
		info.TraceID = traceID
	}
	
	return info
}

// logFallback 日志序列化失败时的后备方案
func (s *StructuredLogger) logFallback(level LogLevel, message string, err error) {
	fallbackMsg := fmt.Sprintf("[%s] %s (JSON serialization failed: %v)", s.component, message, err)
	
	if s.ctx != nil {
		logx.WithContext(s.ctx).Error(fallbackMsg)
	} else {
		logx.Error(fallbackMsg)
	}
}

// 预定义的结构化日志记录器

// AuthStructuredLogger 认证中间件结构化日志记录器
func AuthStructuredLogger() *StructuredLogger {
	return NewStructuredLogger("auth")
}

// TenantStructuredLogger 租户检查中间件结构化日志记录器
func TenantStructuredLogger() *StructuredLogger {
	return NewStructuredLogger("tenant")
}

// DataPermStructuredLogger 数据权限中间件结构化日志记录器
func DataPermStructuredLogger() *StructuredLogger {
	return NewStructuredLogger("dataperm")
}

// AuditStructuredLogger 审计中间件结构化日志记录器
func AuditStructuredLogger() *StructuredLogger {
	return NewStructuredLogger("audit")
}

// FrameworkStructuredLogger 框架结构化日志记录器
func FrameworkStructuredLogger() *StructuredLogger {
	return NewStructuredLogger("framework")
}

// LogEventBuilder 日志事件构建器
type LogEventBuilder struct {
	logger *StructuredLogger
	entry  *StructuredLog
}

// NewLogEvent 创建日志事件构建器
func NewLogEvent(logger *StructuredLogger) *LogEventBuilder {
	return &LogEventBuilder{
		logger: logger,
		entry:  &StructuredLog{},
	}
}

// WithField 添加字段
func (b *LogEventBuilder) WithField(key string, value interface{}) *LogEventBuilder {
	if b.entry.Fields == nil {
		b.entry.Fields = make(map[string]interface{})
	}
	b.entry.Fields[key] = value
	return b
}

// WithError 设置错误信息
func (b *LogEventBuilder) WithError(err error, code int) *LogEventBuilder {
	b.entry.Error = &ErrorInfo{
		Type:    fmt.Sprintf("%T", err),
		Message: err.Error(),
		Code:    code,
	}
	return b
}

// WithRequest 设置请求信息
func (b *LogEventBuilder) WithRequest(req *RequestInfo) *LogEventBuilder {
	b.entry.Request = req
	return b
}

// WithResponse 设置响应信息
func (b *LogEventBuilder) WithResponse(resp *ResponseInfo) *LogEventBuilder {
	b.entry.Response = resp
	return b
}

// WithPerformance 设置性能信息
func (b *LogEventBuilder) WithPerformance(perf *PerformanceInfo) *LogEventBuilder {
	b.entry.Performance = perf
	return b
}

// Log 记录日志
func (b *LogEventBuilder) Log(level LogLevel, message string) {
	b.logger.LogStructured(level, message, b.entry)
}