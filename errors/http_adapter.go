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
	"net/http"
	"time"
)

// HTTPErrorResponse HTTP 错误响应格式
type HTTPErrorResponse struct {
	Success   bool                   `json:"success"`
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   string                 `json:"details,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Timestamp int64                  `json:"timestamp"`
	TraceID   string                 `json:"trace_id,omitempty"`

	// 重试相关信息
	Retryable  bool  `json:"retryable,omitempty"`
	RetryAfter int64 `json:"retry_after_seconds,omitempty"`
}

// HTTPErrorAdapter HTTP 错误适配器
type HTTPErrorAdapter struct {
	includeDetails bool
	includeContext bool
	includeTrace   bool
}

// NewHTTPErrorAdapter 创建 HTTP 错误适配器
func NewHTTPErrorAdapter() *HTTPErrorAdapter {
	return &HTTPErrorAdapter{
		includeDetails: true,
		includeContext: false,
		includeTrace:   false,
	}
}

// WithDetails 设置是否包含详细信息
func (a *HTTPErrorAdapter) WithDetails(include bool) *HTTPErrorAdapter {
	a.includeDetails = include
	return a
}

// WithContext 设置是否包含上下文信息
func (a *HTTPErrorAdapter) WithContext(include bool) *HTTPErrorAdapter {
	a.includeContext = include
	return a
}

// WithTrace 设置是否包含追踪信息
func (a *HTTPErrorAdapter) WithTrace(include bool) *HTTPErrorAdapter {
	a.includeTrace = include
	return a
}

// ToHTTPResponse 将错误转换为 HTTP 响应
func (a *HTTPErrorAdapter) ToHTTPResponse(err error) (int, *HTTPErrorResponse) {
	if err == nil {
		return http.StatusOK, nil
	}

	var unifiedErr *UnifiedError
	if ue, ok := err.(*UnifiedError); ok {
		unifiedErr = ue
	} else {
		unifiedErr = Wrap(err, ErrCodeInternal, "internal server error")
	}

	statusCode := a.getHTTPStatusCode(unifiedErr.Code)

	response := &HTTPErrorResponse{
		Success:   false,
		Code:      string(unifiedErr.Code),
		Message:   unifiedErr.Message,
		Timestamp: unifiedErr.Timestamp.Unix(),
		Retryable: unifiedErr.Retryable,
	}

	// 设置重试间隔
	if unifiedErr.RetryAfter > 0 {
		response.RetryAfter = int64(unifiedErr.RetryAfter.Seconds())
	}

	// 包含详细信息
	if a.includeDetails && unifiedErr.Details != "" {
		response.Details = unifiedErr.Details
	}

	// 包含上下文信息
	if a.includeContext && len(unifiedErr.Context) > 0 {
		response.Context = unifiedErr.Context
	}

	// 包含追踪信息
	if a.includeTrace && unifiedErr.TraceID != "" {
		response.TraceID = unifiedErr.TraceID
	}

	return statusCode, response
}

// WriteHTTPError 写入 HTTP 错误响应
func (a *HTTPErrorAdapter) WriteHTTPError(w http.ResponseWriter, err error) {
	statusCode, response := a.ToHTTPResponse(err)

	w.Header().Set("Content-Type", "application/json")

	// 设置重试相关的 HTTP 头
	if response != nil && response.Retryable && response.RetryAfter > 0 {
		w.Header().Set("Retry-After", string(rune(response.RetryAfter)))
	}

	w.WriteHeader(statusCode)

	if response != nil {
		json.NewEncoder(w).Encode(response)
	}
}

// getHTTPStatusCode 根据错误代码获取 HTTP 状态码
func (a *HTTPErrorAdapter) getHTTPStatusCode(code ErrorCode) int {
	switch code {
	case ErrCodeValidation:
		return http.StatusBadRequest
	case ErrCodeNotFound:
		return http.StatusNotFound
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeConflict:
		return http.StatusConflict
	case ErrCodeTimeout:
		return http.StatusRequestTimeout
	case ErrCodeRateLimit:
		return http.StatusTooManyRequests
	case ErrCodeDatabase, ErrCodeConnection:
		return http.StatusServiceUnavailable
	case ErrCodeConfig:
		return http.StatusInternalServerError
	case ErrCodeBusiness:
		return http.StatusUnprocessableEntity
	case ErrCodeDataPermission:
		return http.StatusForbidden
	case ErrCodeNetwork, ErrCodeHTTP, ErrCodeRPC:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// HTTPErrorMiddleware HTTP 错误处理中间件
func HTTPErrorMiddleware(adapter *HTTPErrorAdapter) func(http.Handler) http.Handler {
	if adapter == nil {
		adapter = NewHTTPErrorAdapter()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					var err error
					if e, ok := rec.(error); ok {
						err = e
					} else {
						err = InternalWithCause("panic in HTTP handler", nil)
					}

					adapter.WriteHTTPError(w, err)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// ErrorHandlerHTTPMiddleware 错误处理 HTTP 中间件
func ErrorHandlerHTTPMiddleware(handler ErrorHandler, adapter *HTTPErrorAdapter) func(http.Handler) http.Handler {
	if adapter == nil {
		adapter = NewHTTPErrorAdapter()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					var err error
					if e, ok := rec.(error); ok {
						err = e
					} else {
						err = InternalWithCause("panic in HTTP handler", nil)
					}

					// 使用错误处理器处理错误
					if handler != nil {
						err = handler.Handle(r.Context(), err)
					}

					adapter.WriteHTTPError(w, err)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// 全局 HTTP 适配器
var globalHTTPAdapter = NewHTTPErrorAdapter().WithDetails(false).WithTrace(true)

// WriteHTTPError 使用全局适配器写入 HTTP 错误
func WriteHTTPError(w http.ResponseWriter, err error) {
	globalHTTPAdapter.WriteHTTPError(w, err)
}

// ToHTTPResponse 使用全局适配器转换 HTTP 响应
func ToHTTPResponse(err error) (int, *HTTPErrorResponse) {
	return globalHTTPAdapter.ToHTTPResponse(err)
}

// SetGlobalHTTPAdapter 设置全局 HTTP 适配器
func SetGlobalHTTPAdapter(adapter *HTTPErrorAdapter) {
	globalHTTPAdapter = adapter
}

// GetGlobalHTTPAdapter 获取全局 HTTP 适配器
func GetGlobalHTTPAdapter() *HTTPErrorAdapter {
	return globalHTTPAdapter
}

// HTTPErrorHandler HTTP 错误处理器类型
type HTTPErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultHTTPErrorHandler 默认 HTTP 错误处理器
func DefaultHTTPErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	// 使用错误处理器处理错误
	processedErr := Handle(r.Context(), err)

	// 写入 HTTP 响应
	WriteHTTPError(w, processedErr)
}

// HTTPResponseWriter 自定义响应写入器，用于捕获响应状态
type HTTPResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// NewHTTPResponseWriter 创建响应写入器
func NewHTTPResponseWriter(w http.ResponseWriter) *HTTPResponseWriter {
	return &HTTPResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader 写入响应头
func (w *HTTPResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
		w.ResponseWriter.WriteHeader(code)
	}
}

// Write 写入响应体
func (w *HTTPResponseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// StatusCode 获取状态码
func (w *HTTPResponseWriter) StatusCode() int {
	return w.statusCode
}

// AccessLogMiddleware 访问日志中间件（包含错误记录）
func AccessLogMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapper := NewHTTPResponseWriter(w)

			defer func() {
				duration := time.Since(start)

				// 记录访问日志
				if wrapper.StatusCode() >= 400 {
					// 错误响应
					Handle(r.Context(), &UnifiedError{
						Code:      ErrCodeHTTP,
						Message:   "HTTP error response",
						Severity:  SeverityMedium,
						Timestamp: time.Now(),
						Context: map[string]interface{}{
							"method":      r.Method,
							"url":         r.URL.String(),
							"status_code": wrapper.StatusCode(),
							"duration_ms": duration.Milliseconds(),
							"user_agent":  r.UserAgent(),
							"remote_addr": r.RemoteAddr,
						},
					})
				}
			}()

			next.ServeHTTP(wrapper, r)
		})
	}
}
