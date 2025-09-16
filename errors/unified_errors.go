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
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

// ErrorCode 错误代码类型
type ErrorCode string

// 预定义错误代码
const (
	// 通用错误代码
	ErrCodeInternal     ErrorCode = "INTERNAL_ERROR"
	ErrCodeValidation   ErrorCode = "VALIDATION_ERROR"
	ErrCodeNotFound     ErrorCode = "NOT_FOUND"
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden    ErrorCode = "FORBIDDEN"
	ErrCodeConflict     ErrorCode = "CONFLICT"
	ErrCodeTimeout      ErrorCode = "TIMEOUT"
	ErrCodeRateLimit    ErrorCode = "RATE_LIMIT"

	// 数据库相关错误
	ErrCodeDatabase    ErrorCode = "DATABASE_ERROR"
	ErrCodeConnection  ErrorCode = "CONNECTION_ERROR"
	ErrCodeTransaction ErrorCode = "TRANSACTION_ERROR"
	ErrCodeConstraint  ErrorCode = "CONSTRAINT_ERROR"

	// 配置相关错误
	ErrCodeConfig        ErrorCode = "CONFIG_ERROR"
	ErrCodeConfigFormat  ErrorCode = "CONFIG_FORMAT_ERROR"
	ErrCodeConfigMissing ErrorCode = "CONFIG_MISSING"

	// 业务逻辑错误
	ErrCodeBusiness       ErrorCode = "BUSINESS_ERROR"
	ErrCodeDataPermission ErrorCode = "DATA_PERMISSION_ERROR"
	ErrCodeWorkflow       ErrorCode = "WORKFLOW_ERROR"

	// 网络相关错误
	ErrCodeNetwork ErrorCode = "NETWORK_ERROR"
	ErrCodeHTTP    ErrorCode = "HTTP_ERROR"
	ErrCodeRPC     ErrorCode = "RPC_ERROR"
)

// ErrorSeverity 错误严重程度
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// UnifiedError 统一错误结构
type UnifiedError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Cause      error                  `json:"-"`
	Severity   ErrorSeverity          `json:"severity"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	StackTrace string                 `json:"stack_trace,omitempty"`

	// 可重试性
	Retryable  bool          `json:"retryable"`
	RetryAfter time.Duration `json:"retry_after,omitempty"`

	// 用户友好信息
	UserMessage string `json:"user_message,omitempty"`

	// 追踪信息
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
}

// Error 实现 error 接口
func (e *UnifiedError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap 实现 errors.Unwrap 接口
func (e *UnifiedError) Unwrap() error {
	return e.Cause
}

// Is 实现 errors.Is 接口
func (e *UnifiedError) Is(target error) bool {
	if t, ok := target.(*UnifiedError); ok {
		return e.Code == t.Code
	}
	return false
}

// WithContext 添加上下文信息
func (e *UnifiedError) WithContext(key string, value interface{}) *UnifiedError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithTrace 添加追踪信息
func (e *UnifiedError) WithTrace(traceID, spanID string) *UnifiedError {
	e.TraceID = traceID
	e.SpanID = spanID
	return e
}

// WithRetry 设置重试信息
func (e *UnifiedError) WithRetry(retryable bool, retryAfter time.Duration) *UnifiedError {
	e.Retryable = retryable
	e.RetryAfter = retryAfter
	return e
}

// WithUserMessage 设置用户友好消息
func (e *UnifiedError) WithUserMessage(message string) *UnifiedError {
	e.UserMessage = message
	return e
}

// ToJSON 转换为 JSON 字符串
func (e *UnifiedError) ToJSON() string {
	data, _ := json.Marshal(e)
	return string(data)
}

// New 创建新的统一错误
func New(code ErrorCode, message string) *UnifiedError {
	return &UnifiedError{
		Code:      code,
		Message:   message,
		Severity:  SeverityMedium,
		Timestamp: time.Now(),
		Retryable: false,
	}
}

// NewWithCause 创建带原因的统一错误
func NewWithCause(code ErrorCode, message string, cause error) *UnifiedError {
	err := New(code, message)
	err.Cause = cause
	if cause != nil {
		err.Details = cause.Error()
	}
	return err
}

// Wrap 包装现有错误
func Wrap(err error, code ErrorCode, message string) *UnifiedError {
	if err == nil {
		return nil
	}

	// 如果已经是 UnifiedError，则更新信息
	if ue, ok := err.(*UnifiedError); ok {
		return &UnifiedError{
			Code:       code,
			Message:    message,
			Details:    ue.Error(),
			Cause:      ue,
			Severity:   ue.Severity,
			Context:    ue.Context,
			Timestamp:  time.Now(),
			StackTrace: ue.StackTrace,
			Retryable:  ue.Retryable,
			RetryAfter: ue.RetryAfter,
			TraceID:    ue.TraceID,
			SpanID:     ue.SpanID,
		}
	}

	return NewWithCause(code, message, err)
}

// WrapWithSeverity 包装错误并设置严重程度
func WrapWithSeverity(err error, code ErrorCode, message string, severity ErrorSeverity) *UnifiedError {
	ue := Wrap(err, code, message)
	if ue != nil {
		ue.Severity = severity
	}
	return ue
}

// WithStackTrace 添加堆栈追踪
func (e *UnifiedError) WithStackTrace() *UnifiedError {
	if e.StackTrace == "" {
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		e.StackTrace = string(buf[:n])
	}
	return e
}

// 便捷函数

// Internal 创建内部错误
func Internal(message string) *UnifiedError {
	return New(ErrCodeInternal, message).WithStackTrace()
}

// InternalWithCause 创建带原因的内部错误
func InternalWithCause(message string, cause error) *UnifiedError {
	return NewWithCause(ErrCodeInternal, message, cause).WithStackTrace()
}

// Validation 创建验证错误
func Validation(message string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeValidation,
		Message:     message,
		Severity:    SeverityLow,
		Timestamp:   time.Now(),
		Retryable:   false,
		UserMessage: "输入数据格式不正确，请检查后重试",
	}
}

// ValidationWithDetails 创建带详细信息的验证错误
func ValidationWithDetails(message, details string) *UnifiedError {
	err := Validation(message)
	err.Details = details
	return err
}

// NotFound 创建未找到错误
func NotFound(resource string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeNotFound,
		Message:     fmt.Sprintf("%s not found", resource),
		Severity:    SeverityLow,
		Timestamp:   time.Now(),
		Retryable:   false,
		UserMessage: "请求的资源不存在",
	}
}

// Unauthorized 创建未授权错误
func Unauthorized(message string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeUnauthorized,
		Message:     message,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Retryable:   false,
		UserMessage: "您没有访问权限，请先登录",
	}
}

// Forbidden 创建禁止访问错误
func Forbidden(message string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeForbidden,
		Message:     message,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Retryable:   false,
		UserMessage: "您没有执行此操作的权限",
	}
}

// Database 创建数据库错误
func Database(message string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeDatabase,
		Message:     message,
		Severity:    SeverityHigh,
		Timestamp:   time.Now(),
		Retryable:   true,
		RetryAfter:  time.Second * 5,
		UserMessage: "数据处理异常，请稍后重试",
	}
}

// DatabaseWithCause 创建带原因的数据库错误
func DatabaseWithCause(message string, cause error) *UnifiedError {
	err := Database(message)
	err.Cause = cause
	if cause != nil {
		err.Details = cause.Error()
	}
	return err
}

// Config 创建配置错误
func Config(message string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeConfig,
		Message:     message,
		Severity:    SeverityCritical,
		Timestamp:   time.Now(),
		Retryable:   false,
		UserMessage: "系统配置异常，请联系管理员",
	}
}

// Business 创建业务逻辑错误
func Business(message string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeBusiness,
		Message:     message,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Retryable:   false,
		UserMessage: message, // 业务错误通常可以直接显示给用户
	}
}

// Timeout 创建超时错误
func Timeout(operation string) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeTimeout,
		Message:     fmt.Sprintf("%s timeout", operation),
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Retryable:   true,
		RetryAfter:  time.Second * 3,
		UserMessage: "操作超时，请稍后重试",
	}
}

// RateLimit 创建限流错误
func RateLimit(message string, retryAfter time.Duration) *UnifiedError {
	return &UnifiedError{
		Code:        ErrCodeRateLimit,
		Message:     message,
		Severity:    SeverityLow,
		Timestamp:   time.Now(),
		Retryable:   true,
		RetryAfter:  retryAfter,
		UserMessage: "请求过于频繁，请稍后重试",
	}
}

// IsRetryable 检查错误是否可重试
func IsRetryable(err error) bool {
	if ue, ok := err.(*UnifiedError); ok {
		return ue.Retryable
	}
	return false
}

// GetRetryAfter 获取重试间隔
func GetRetryAfter(err error) time.Duration {
	if ue, ok := err.(*UnifiedError); ok {
		return ue.RetryAfter
	}
	return 0
}

// GetSeverity 获取错误严重程度
func GetSeverity(err error) ErrorSeverity {
	if ue, ok := err.(*UnifiedError); ok {
		return ue.Severity
	}
	return SeverityMedium
}

// GetUserMessage 获取用户友好消息
func GetUserMessage(err error) string {
	if ue, ok := err.(*UnifiedError); ok && ue.UserMessage != "" {
		return ue.UserMessage
	}
	return "系统异常，请稍后重试"
}

// GetTraceInfo 获取追踪信息
func GetTraceInfo(err error) (traceID, spanID string) {
	if ue, ok := err.(*UnifiedError); ok {
		return ue.TraceID, ue.SpanID
	}
	return "", ""
}
