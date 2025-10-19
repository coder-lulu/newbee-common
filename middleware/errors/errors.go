// Copyright 2024 The NewBee Authors. All Rights Reserved.

package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MiddlewareError 中间件统一错误类型
type MiddlewareError struct {
	Code      int               `json:"code"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	RequestID string            `json:"request_id,omitempty"`
	Cause     error             `json:"-"` // 内部错误，不序列化
}

func (e *MiddlewareError) Error() string {
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Unwrap 支持错误链
func (e *MiddlewareError) Unwrap() error {
	return e.Cause
}

// ToJSON 转换为JSON响应
func (e *MiddlewareError) ToJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"code":       e.Code,
		"message":    e.Message,
		"data":       nil,
		"timestamp":  e.Timestamp.Format(time.RFC3339),
		"request_id": e.RequestID,
	})
}

// WriteHTTPResponse 写入HTTP响应
func (e *MiddlewareError) WriteHTTPResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	
	// 根据错误码设置HTTP状态码
	httpStatus := e.getHTTPStatus()
	w.WriteHeader(httpStatus)
	
	response, _ := e.ToJSON()
	w.Write(response)
}

// getHTTPStatus 根据业务错误码映射HTTP状态码
func (e *MiddlewareError) getHTTPStatus() int {
	switch {
	case e.Code >= 40001 && e.Code <= 40099: // 认证错误
		return http.StatusUnauthorized
	case e.Code >= 40301 && e.Code <= 40399: // 权限错误
		return http.StatusForbidden
	case e.Code >= 42901 && e.Code <= 42999: // 频率限制
		return http.StatusTooManyRequests
	case e.Code >= 50001 && e.Code <= 50099: // 内部错误
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// 预定义错误码常量
const (
    // 认证相关错误 (40001-40099)
    CodeAuthTokenMissing     = 40001
    CodeAuthTokenInvalid     = 40002
    CodeAuthTokenExpired     = 40003
    CodeAuthSecretMismatch   = 40004
    CodeAuthUserNotFound     = 40005

    // 租户相关错误 (40301-40399)
    CodeTenantMissing        = 40301
    CodeTenantInactive       = 40302
    CodeTenantSuspended      = 40303
    CodeTenantNotFound       = 40304

    // 接口权限（RBAC）错误 (40321)
    CodeRBACPermissionDenied = 40321

    // 数据权限错误 (40351-40399)
    CodeDataPermDenied       = 40351
    CodeDataPermInvalidScope = 40352
    CodeDataPermRoleNotFound = 40353

	// 频率限制错误 (42901-42999)
	CodeRateLimitExceeded    = 42901
	CodeConcurrencyExceeded  = 42902

	// 加密相关错误 (40401-40499)
	CodeEncryptionFailed     = 40401
	CodeDecryptionFailed     = 40402
	CodeBadRequest           = 40000

	// 内部错误 (50001-50099)
	CodeInternalError        = 50001
	CodeDatabaseError        = 50002
	CodeRedisError           = 50003
	CodeRPCError             = 50004
	CodeConfigError          = 50005
)

// 错误信息映射
var errorMessages = map[int]string{
	// 认证错误
	CodeAuthTokenMissing:     "认证Token缺失",
	CodeAuthTokenInvalid:     "认证Token无效",
	CodeAuthTokenExpired:     "认证Token已过期",
	CodeAuthSecretMismatch:   "认证密钥不匹配",
	CodeAuthUserNotFound:     "用户不存在",

	// 租户错误
	CodeTenantMissing:        "租户信息缺失",
	CodeTenantInactive:       "租户未激活",
	CodeTenantSuspended:      "租户已被暂停",
    CodeTenantNotFound:       "租户不存在",

    // 接口权限（RBAC）错误
    CodeRBACPermissionDenied: "接口权限不足",

	// 数据权限错误
	CodeDataPermDenied:       "数据权限不足",
	CodeDataPermInvalidScope: "数据权限范围无效",
	CodeDataPermRoleNotFound: "角色不存在",

	// 频率限制错误
	CodeRateLimitExceeded:    "请求频率超限",
	CodeConcurrencyExceeded:  "并发数超限",

	// 加密错误
	CodeEncryptionFailed:     "加密失败",
	CodeDecryptionFailed:     "解密失败",
	CodeBadRequest:           "请求参数错误",

	// 内部错误
	CodeInternalError:        "系统内部错误",
	CodeDatabaseError:        "数据库错误",
	CodeRedisError:           "缓存服务错误",
	CodeRPCError:             "远程调用错误",
	CodeConfigError:          "配置错误",
}

// ErrorBuilder 错误构建器
type ErrorBuilder struct {
	code      int
	message   string
	details   map[string]string
	cause     error
	requestID string
}

// NewError 创建新的错误构建器
func NewError(code int) *ErrorBuilder {
	message, exists := errorMessages[code]
	if !exists {
		message = "未知错误"
	}
	
	return &ErrorBuilder{
		code:    code,
		message: message,
		details: make(map[string]string),
	}
}

// WithMessage 自定义错误消息
func (b *ErrorBuilder) WithMessage(message string) *ErrorBuilder {
	b.message = message
	return b
}

// WithDetail 添加错误详情
func (b *ErrorBuilder) WithDetail(key, value string) *ErrorBuilder {
	b.details[key] = value
	return b
}

// WithCause 设置原因错误
func (b *ErrorBuilder) WithCause(err error) *ErrorBuilder {
	b.cause = err
	return b
}

// WithRequestID 设置请求ID
func (b *ErrorBuilder) WithRequestID(requestID string) *ErrorBuilder {
	b.requestID = requestID
	return b
}

// Build 构建最终错误
func (b *ErrorBuilder) Build() *MiddlewareError {
	return &MiddlewareError{
		Code:      b.code,
		Message:   b.message,
		Details:   b.details,
		Timestamp: time.Now(),
		RequestID: b.requestID,
		Cause:     b.cause,
	}
}

// 便捷函数

// NewAuthError 创建认证错误
func NewAuthError(code int, cause error) *MiddlewareError {
	return NewError(code).WithCause(cause).Build()
}

// NewTenantError 创建租户错误
func NewTenantError(code int, tenantID string) *MiddlewareError {
	return NewError(code).WithDetail("tenant_id", tenantID).Build()
}

// NewDataPermError 创建数据权限错误
func NewDataPermError(code int, userID, scope string) *MiddlewareError {
	return NewError(code).
		WithDetail("user_id", userID).
		WithDetail("scope", scope).
		Build()
}

// NewRateLimitError 创建频率限制错误
func NewRateLimitError(code int, limit int, window string) *MiddlewareError {
	return NewError(code).
		WithDetail("limit", fmt.Sprintf("%d", limit)).
		WithDetail("window", window).
		Build()
}

// NewInternalError 创建内部错误
func NewInternalError(code int, cause error) *MiddlewareError {
	return NewError(code).WithCause(cause).Build()
}

// IsAuthError 判断是否为认证错误
func IsAuthError(err error) bool {
	if mErr, ok := err.(*MiddlewareError); ok {
		return mErr.Code >= 40001 && mErr.Code <= 40099
	}
	return false
}

// IsTenantError 判断是否为租户错误
func IsTenantError(err error) bool {
	if mErr, ok := err.(*MiddlewareError); ok {
		return mErr.Code >= 40301 && mErr.Code <= 40399
	}
	return false
}

// IsDataPermError 判断是否为数据权限错误
func IsDataPermError(err error) bool {
	if mErr, ok := err.(*MiddlewareError); ok {
		return mErr.Code >= 40351 && mErr.Code <= 40399
	}
	return false
}

// IsRateLimitError 判断是否为频率限制错误
func IsRateLimitError(err error) bool {
	if mErr, ok := err.(*MiddlewareError); ok {
		return mErr.Code >= 42901 && mErr.Code <= 42999
	}
	return false
}

// IsInternalError 判断是否为内部错误
func IsInternalError(err error) bool {
	if mErr, ok := err.(*MiddlewareError); ok {
		return mErr.Code >= 50001 && mErr.Code <= 50099
	}
	return false
}
