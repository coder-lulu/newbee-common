// Copyright 2024 The NewBee Authors. All Rights Reserved.

package logging

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/zeromicro/go-zero/core/logx"
)

// MiddlewareLogger 中间件专用日志器
type MiddlewareLogger struct {
	component string
	ctx       context.Context
	fields    map[string]interface{}
}

// NewMiddlewareLogger 创建中间件日志器
func NewMiddlewareLogger(component string) *MiddlewareLogger {
	return &MiddlewareLogger{
		component: component,
		fields:    make(map[string]interface{}),
	}
}

// WithContext 设置上下文
func (l *MiddlewareLogger) WithContext(ctx context.Context) *MiddlewareLogger {
	newLogger := &MiddlewareLogger{
		component: l.component,
		ctx:       ctx,
		fields:    make(map[string]interface{}),
	}

	// 复制现有字段
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// 从上下文中提取公共字段
	newLogger.extractContextFields(ctx)
	return newLogger
}

// WithField 添加字段
func (l *MiddlewareLogger) WithField(key string, value interface{}) *MiddlewareLogger {
	newLogger := &MiddlewareLogger{
		component: l.component,
		ctx:       l.ctx,
		fields:    make(map[string]interface{}, len(l.fields)+1),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	newLogger.fields[key] = value
	return newLogger
}

// WithFields 添加多个字段
func (l *MiddlewareLogger) WithFields(fields map[string]interface{}) *MiddlewareLogger {
	newLogger := &MiddlewareLogger{
		component: l.component,
		ctx:       l.ctx,
		fields:    make(map[string]interface{}, len(l.fields)+len(fields)),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	for k, v := range fields {
		newLogger.fields[k] = v
	}
	return newLogger
}

// WithError 添加错误信息
func (l *MiddlewareLogger) WithError(err error) *MiddlewareLogger {
	newLogger := &MiddlewareLogger{
		component: l.component,
		ctx:       l.ctx,
		fields:    make(map[string]interface{}, len(l.fields)+3),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	if err != nil {
		newLogger.fields["error"] = err.Error()
		newLogger.fields["error_type"] = fmt.Sprintf("%T", err)

		// 获取调用栈信息
		if pc, file, line, ok := runtime.Caller(1); ok {
			newLogger.fields["caller_file"] = file
			newLogger.fields["caller_line"] = line
			if fn := runtime.FuncForPC(pc); fn != nil {
				newLogger.fields["caller_func"] = fn.Name()
			}
		}
	}
	return newLogger
}

// WithRequest 添加请求信息
func (l *MiddlewareLogger) WithRequest(r *http.Request) *MiddlewareLogger {
	l.fields["method"] = r.Method
	l.fields["path"] = r.URL.Path
	l.fields["query"] = r.URL.RawQuery
	l.fields["user_agent"] = r.Header.Get("User-Agent")
	l.fields["remote_addr"] = getClientIP(r)

	// 添加请求ID（如果存在）
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		l.fields["request_id"] = requestID
	}

	return l
}

// WithDuration 添加执行时长
func (l *MiddlewareLogger) WithDuration(start time.Time) *MiddlewareLogger {
	duration := time.Since(start)
	newLogger := &MiddlewareLogger{
		component: l.component,
		ctx:       l.ctx,
		fields:    make(map[string]interface{}, len(l.fields)+1),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	newLogger.fields["duration_ms"] = float64(duration.Nanoseconds()) / 1e6
	return newLogger
}

// 日志输出方法

// Debug 调试日志
func (l *MiddlewareLogger) Debug(msg string) {
	l.log(logx.DebugLevel, msg)
}

// Info 信息日志
func (l *MiddlewareLogger) Info(msg string) {
	l.log(logx.InfoLevel, msg)
}

// Warn 警告日志
func (l *MiddlewareLogger) Warn(msg string) {
	l.log(logx.ErrorLevel, msg) // go-zero没有Warn级别，使用Error
}

// Error 错误日志
func (l *MiddlewareLogger) Error(msg string) {
	l.log(logx.ErrorLevel, msg)
}

// Fatal 致命错误日志
func (l *MiddlewareLogger) Fatal(msg string) {
	l.log(logx.ErrorLevel, msg)
	// 注意：不调用os.Exit，让调用方决定
}

// 内部方法

// log 统一日志输出方法
func (l *MiddlewareLogger) log(level uint32, msg string) {
	// 构建完整的日志消息
	fullMsg := l.buildLogMessage(msg)

	// 构建字段列表
	fields := l.buildLogFields()

	// 根据级别输出日志
	if l.ctx != nil {
		logx.WithContext(l.ctx).Infow(fullMsg, fields)
	} else {
		logx.Infow(fullMsg, fields)
	}
}

// buildLogMessage 构建日志消息
func (l *MiddlewareLogger) buildLogMessage(msg string) string {
	return fmt.Sprintf("[%s] %s", l.component, msg)
}

// buildLogFields 构建日志字段
func (l *MiddlewareLogger) buildLogFields() logx.LogField {
	// 合并所有字段到一个map中
	allFields := make(map[string]interface{})

	// 复制用户字段
	for key, value := range l.fields {
		allFields[key] = value
	}

	// 添加组件标识
	allFields["component"] = l.component
	allFields["timestamp"] = time.Now().Format(time.RFC3339Nano)

	// 返回单个复合字段
	return logx.Field("middleware_context", allFields)
}

// extractContextFields 从上下文提取字段
func (l *MiddlewareLogger) extractContextFields(ctx context.Context) {
	if ctx == nil {
		return
	}

	// 使用ContextManager提取标准字段
	cm := keys.NewContextManager()

	if tenantID := cm.GetTenantID(ctx); tenantID != "" {
		l.fields["tenant_id"] = tenantID
	}

	if userID := cm.GetUserID(ctx); userID != "" {
		l.fields["user_id"] = userID
	}

	if deptID := cm.GetDeptID(ctx); deptID != "" {
		l.fields["dept_id"] = deptID
	}

	if dataScope := cm.GetDataScope(ctx); dataScope != "" {
		l.fields["data_scope"] = dataScope
	}

	// roleCodes通过context直接获取
	if roleCodes, ok := ctx.Value(keys.RoleCodesKey).(string); ok && roleCodes != "" {
		l.fields["role_codes"] = roleCodes
	}
}

// getClientIP 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 检查X-Forwarded-For头
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查X-Real-IP头
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx]
	}

	return ip
}

// 预定义的组件日志器

// AuthLogger 认证中间件日志器
func AuthLogger() *MiddlewareLogger {
	return NewMiddlewareLogger("auth")
}

// TenantLogger 租户检查中间件日志器
func TenantLogger() *MiddlewareLogger {
	return NewMiddlewareLogger("tenant")
}

// DataPermLogger 数据权限中间件日志器
func DataPermLogger() *MiddlewareLogger {
	return NewMiddlewareLogger("dataperm")
}

// AuditLogger 审计中间件日志器
func AuditLogger() *MiddlewareLogger {
	return NewMiddlewareLogger("audit")
}

// FrameworkLogger 框架日志器
func FrameworkLogger() *MiddlewareLogger {
	return NewMiddlewareLogger("framework")
}

// PerformanceLogger 性能监控日志器
type PerformanceLogger struct {
	*MiddlewareLogger
	startTime time.Time
}

// NewPerformanceLogger 创建性能监控日志器
func NewPerformanceLogger(component string) *PerformanceLogger {
	return &PerformanceLogger{
		MiddlewareLogger: NewMiddlewareLogger(component),
		startTime:        time.Now(),
	}
}

// Start 开始性能监控
func (p *PerformanceLogger) Start() {
	p.startTime = time.Now()
}

// End 结束性能监控并记录
func (p *PerformanceLogger) End(operation string) {
	duration := time.Since(p.startTime)
	p.WithField("operation", operation).
		WithField("duration_ms", float64(duration.Nanoseconds())/1e6).
		Info("operation completed")
}

// EndWithError 结束性能监控并记录错误
func (p *PerformanceLogger) EndWithError(operation string, err error) {
	duration := time.Since(p.startTime)
	p.WithField("operation", operation).
		WithField("duration_ms", float64(duration.Nanoseconds())/1e6).
		WithError(err).
		Error("operation failed")
}

// LogSlowOperation 记录慢操作
func (p *PerformanceLogger) LogSlowOperation(operation string, threshold time.Duration) {
	duration := time.Since(p.startTime)
	if duration > threshold {
		p.WithField("operation", operation).
			WithField("duration_ms", float64(duration.Nanoseconds())/1e6).
			WithField("threshold_ms", float64(threshold.Nanoseconds())/1e6).
			Warn("slow operation detected")
	}
}

// 统计信息记录器
type StatsLogger struct {
	*MiddlewareLogger
	stats map[string]interface{}
}

// NewStatsLogger 创建统计信息日志器
func NewStatsLogger(component string) *StatsLogger {
	return &StatsLogger{
		MiddlewareLogger: NewMiddlewareLogger(component),
		stats:            make(map[string]interface{}),
	}
}

// IncrementCounter 增加计数器
func (s *StatsLogger) IncrementCounter(name string) {
	if val, ok := s.stats[name]; ok {
		if count, ok := val.(int64); ok {
			s.stats[name] = count + 1
		}
	} else {
		s.stats[name] = int64(1)
	}
}

// SetGauge 设置仪表值
func (s *StatsLogger) SetGauge(name string, value interface{}) {
	s.stats[name] = value
}

// LogStats 记录统计信息
func (s *StatsLogger) LogStats(operation string) {
	s.WithField("operation", operation).
		WithFields(s.stats).
		Info("middleware statistics")
}
