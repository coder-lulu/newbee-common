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

package errors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// ErrorHandler 错误处理器接口
type ErrorHandler interface {
	Handle(ctx context.Context, err error) error
	Register(handler ErrorHandlerFunc)
	SetFallback(handler ErrorHandlerFunc)
}

// ErrorHandlerFunc 错误处理函数类型
type ErrorHandlerFunc func(ctx context.Context, err *UnifiedError) error

// ErrorReporter 错误报告器接口
type ErrorReporter interface {
	Report(ctx context.Context, err *UnifiedError) error
}

// ErrorMetrics 错误指标接口
type ErrorMetrics interface {
	RecordError(code ErrorCode, severity ErrorSeverity)
	GetErrorCount(code ErrorCode) int64
	GetErrorRate() float64
}

// StandardErrorHandler 标准错误处理器
type StandardErrorHandler struct {
	handlers []ErrorHandlerFunc
	fallback ErrorHandlerFunc
	reporter ErrorReporter
	metrics  ErrorMetrics
	mu       sync.RWMutex
}

// NewStandardErrorHandler 创建标准错误处理器
func NewStandardErrorHandler() *StandardErrorHandler {
	return &StandardErrorHandler{
		handlers: make([]ErrorHandlerFunc, 0),
		fallback: defaultFallbackHandler,
	}
}

// Handle 处理错误
func (h *StandardErrorHandler) Handle(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}

	// 转换为统一错误格式
	var unifiedErr *UnifiedError
	if ue, ok := err.(*UnifiedError); ok {
		unifiedErr = ue
	} else {
		unifiedErr = Wrap(err, ErrCodeInternal, "unhandled error")
	}

	// 记录指标
	if h.metrics != nil {
		h.metrics.RecordError(unifiedErr.Code, unifiedErr.Severity)
	}

	// 运行处理器链
	h.mu.RLock()
	handlers := make([]ErrorHandlerFunc, len(h.handlers))
	copy(handlers, h.handlers)
	fallback := h.fallback
	h.mu.RUnlock()

	for _, handler := range handlers {
		if handlerErr := handler(ctx, unifiedErr); handlerErr != nil {
			logx.Errorw("Error handler failed",
				logx.Field("error", handlerErr),
				logx.Field("original_error", unifiedErr.Error()))
		}
	}

	// 报告错误
	if h.reporter != nil {
		if reportErr := h.reporter.Report(ctx, unifiedErr); reportErr != nil {
			logx.Errorw("Error reporting failed", logx.Field("error", reportErr))
		}
	}

	// 运行回退处理器
	if fallback != nil {
		if fallbackErr := fallback(ctx, unifiedErr); fallbackErr != nil {
			logx.Errorw("Fallback handler failed", logx.Field("error", fallbackErr))
		}
	}

	return unifiedErr
}

// Register 注册错误处理器
func (h *StandardErrorHandler) Register(handler ErrorHandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers = append(h.handlers, handler)
}

// SetFallback 设置回退处理器
func (h *StandardErrorHandler) SetFallback(handler ErrorHandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fallback = handler
}

// SetReporter 设置错误报告器
func (h *StandardErrorHandler) SetReporter(reporter ErrorReporter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reporter = reporter
}

// SetMetrics 设置错误指标
func (h *StandardErrorHandler) SetMetrics(metrics ErrorMetrics) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metrics = metrics
}

// 默认回退处理器
func defaultFallbackHandler(ctx context.Context, err *UnifiedError) error {
	// 根据严重程度选择日志级别
	switch err.Severity {
	case SeverityCritical, SeverityHigh:
		logx.Errorw("Critical/High severity error occurred",
			logx.Field("code", string(err.Code)),
			logx.Field("message", err.Message),
			logx.Field("details", err.Details),
			logx.Field("context", err.Context),
			logx.Field("trace_id", err.TraceID),
			logx.Field("span_id", err.SpanID),
			logx.Field("stack_trace", err.StackTrace))
	case SeverityMedium:
		logx.Infow("Medium severity error occurred",
			logx.Field("code", string(err.Code)),
			logx.Field("message", err.Message),
			logx.Field("trace_id", err.TraceID))
	case SeverityLow:
		logx.Debugw("Low severity error occurred",
			logx.Field("code", string(err.Code)),
			logx.Field("message", err.Message))
	}

	return nil
}

// LoggingErrorReporter 日志错误报告器
type LoggingErrorReporter struct{}

// Report 报告错误到日志
func (r *LoggingErrorReporter) Report(ctx context.Context, err *UnifiedError) error {
	logx.Errorw("Error reported",
		logx.Field("error_code", string(err.Code)),
		logx.Field("error_message", err.Message),
		logx.Field("error_details", err.Details),
		logx.Field("severity", string(err.Severity)),
		logx.Field("retryable", err.Retryable),
		logx.Field("context", err.Context),
		logx.Field("trace_id", err.TraceID),
		logx.Field("span_id", err.SpanID),
		logx.Field("timestamp", err.Timestamp))

	return nil
}

// MemoryErrorMetrics 内存错误指标
type MemoryErrorMetrics struct {
	errorCounts map[ErrorCode]int64
	totalErrors int64
	startTime   time.Time
	mu          sync.RWMutex
}

// NewMemoryErrorMetrics 创建内存错误指标
func NewMemoryErrorMetrics() *MemoryErrorMetrics {
	return &MemoryErrorMetrics{
		errorCounts: make(map[ErrorCode]int64),
		startTime:   time.Now(),
	}
}

// RecordError 记录错误
func (m *MemoryErrorMetrics) RecordError(code ErrorCode, severity ErrorSeverity) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.errorCounts[code]++
	m.totalErrors++
}

// GetErrorCount 获取错误计数
func (m *MemoryErrorMetrics) GetErrorCount(code ErrorCode) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.errorCounts[code]
}

// GetErrorRate 获取错误率
func (m *MemoryErrorMetrics) GetErrorRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	duration := time.Since(m.startTime).Minutes()
	if duration == 0 {
		return 0
	}

	return float64(m.totalErrors) / duration
}

// GetAllErrorCounts 获取所有错误计数
func (m *MemoryErrorMetrics) GetAllErrorCounts() map[ErrorCode]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[ErrorCode]int64)
	for code, count := range m.errorCounts {
		result[code] = count
	}

	return result
}

// 全局错误处理器
var globalErrorHandler = NewStandardErrorHandler()

func init() {
	// 设置默认报告器和指标
	globalErrorHandler.SetReporter(&LoggingErrorReporter{})
	globalErrorHandler.SetMetrics(NewMemoryErrorMetrics())
}

// 全局函数

// Handle 处理错误
func Handle(ctx context.Context, err error) error {
	return globalErrorHandler.Handle(ctx, err)
}

// RegisterHandler 注册全局错误处理器
func RegisterHandler(handler ErrorHandlerFunc) {
	globalErrorHandler.Register(handler)
}

// SetGlobalReporter 设置全局错误报告器
func SetGlobalReporter(reporter ErrorReporter) {
	globalErrorHandler.SetReporter(reporter)
}

// SetGlobalMetrics 设置全局错误指标
func SetGlobalMetrics(metrics ErrorMetrics) {
	globalErrorHandler.SetMetrics(metrics)
}

// GetGlobalHandler 获取全局错误处理器
func GetGlobalHandler() ErrorHandler {
	return globalErrorHandler
}

// 便捷处理函数

// HandleAndLog 处理错误并记录日志
func HandleAndLog(ctx context.Context, err error, message string) {
	if err == nil {
		return
	}

	wrappedErr := Wrap(err, ErrCodeInternal, message)
	Handle(ctx, wrappedErr)
}

// HandleValidation 处理验证错误
func HandleValidation(ctx context.Context, field, message string) error {
	err := ValidationWithDetails(fmt.Sprintf("validation failed for field: %s", field), message)
	return Handle(ctx, err)
}

// HandleDatabase 处理数据库错误
func HandleDatabase(ctx context.Context, operation string, cause error) error {
	err := DatabaseWithCause(fmt.Sprintf("database operation failed: %s", operation), cause)
	return Handle(ctx, err)
}

// HandleBusiness 处理业务错误
func HandleBusiness(ctx context.Context, message string) error {
	err := Business(message)
	return Handle(ctx, err)
}

// HandleConfig 处理配置错误
func HandleConfig(ctx context.Context, message string) error {
	err := Config(message)
	return Handle(ctx, err)
}

// Recovery 错误恢复处理器（用于 panic 恢复）
func Recovery(ctx context.Context) {
	if r := recover(); r != nil {
		var err error
		if e, ok := r.(error); ok {
			err = e
		} else {
			err = fmt.Errorf("panic: %v", r)
		}

		panicErr := InternalWithCause("panic recovered", err).WithStackTrace()
		Handle(ctx, panicErr)
	}
}

// WithErrorHandling 带错误处理的函数包装器
func WithErrorHandling(fn func() error) func() {
	return func() {
		ctx := context.Background()
		defer Recovery(ctx)

		if err := fn(); err != nil {
			Handle(ctx, err)
		}
	}
}

// RetryWithBackoff 带退避的重试机制
func RetryWithBackoff(ctx context.Context, fn func() error, maxRetries int) error {
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// 检查是否可重试
		if !IsRetryable(err) {
			break
		}

		// 计算退避时间
		retryAfter := GetRetryAfter(err)
		if retryAfter == 0 {
			retryAfter = time.Duration(i+1) * time.Second
		}

		select {
		case <-ctx.Done():
			return Wrap(ctx.Err(), ErrCodeTimeout, "retry cancelled")
		case <-time.After(retryAfter):
			continue
		}
	}

	return Handle(ctx, Wrap(lastErr, ErrCodeInternal, "max retries exceeded"))
}
