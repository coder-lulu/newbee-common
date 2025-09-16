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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPErrorAdapter_ToHTTPResponse(t *testing.T) {
	adapter := NewHTTPErrorAdapter()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "nil error",
			err:            nil,
			expectedStatus: http.StatusOK,
			expectedCode:   "",
		},
		{
			name:           "validation error",
			err:            Validation("invalid input"),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "VALIDATION_ERROR",
		},
		{
			name:           "not found error",
			err:            NotFound("user"),
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NOT_FOUND",
		},
		{
			name:           "unauthorized error",
			err:            Unauthorized("access denied"),
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "UNAUTHORIZED",
		},
		{
			name:           "forbidden error",
			err:            Forbidden("insufficient permissions"),
			expectedStatus: http.StatusForbidden,
			expectedCode:   "FORBIDDEN",
		},
		{
			name:           "database error",
			err:            Database("connection failed"),
			expectedStatus: http.StatusServiceUnavailable,
			expectedCode:   "DATABASE_ERROR",
		},
		{
			name:           "timeout error",
			err:            Timeout("operation"),
			expectedStatus: http.StatusRequestTimeout,
			expectedCode:   "TIMEOUT",
		},
		{
			name:           "rate limit error",
			err:            RateLimit("too many requests", 30*time.Second),
			expectedStatus: http.StatusTooManyRequests,
			expectedCode:   "RATE_LIMIT",
		},
		{
			name:           "business error",
			err:            Business("business rule violation"),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedCode:   "BUSINESS_ERROR",
		},
		{
			name:           "config error",
			err:            Config("configuration missing"),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "CONFIG_ERROR",
		},
		{
			name:           "standard error",
			err:            fmt.Errorf("standard error"),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode, response := adapter.ToHTTPResponse(tt.err)

			if statusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, statusCode)
			}

			if tt.err == nil {
				if response != nil {
					t.Error("Response should be nil for nil error")
				}
				return
			}

			if response == nil {
				t.Error("Response should not be nil for non-nil error")
				return
			}

			if response.Code != tt.expectedCode {
				t.Errorf("Expected code %s, got %s", tt.expectedCode, response.Code)
			}

			if response.Success {
				t.Error("Success should be false for error response")
			}
		})
	}
}

func TestHTTPErrorAdapter_WithOptions(t *testing.T) {
	err := Validation("validation failed")
	err.Details = "email format is invalid"
	err.WithContext("field", "email")
	err.WithTrace("trace-123", "span-456")

	tests := []struct {
		name       string
		adapter    *HTTPErrorAdapter
		hasDetails bool
		hasContext bool
		hasTrace   bool
	}{
		{
			name:       "default adapter",
			adapter:    NewHTTPErrorAdapter(),
			hasDetails: true,
			hasContext: false,
			hasTrace:   false,
		},
		{
			name:       "adapter with all options",
			adapter:    NewHTTPErrorAdapter().WithDetails(true).WithContext(true).WithTrace(true),
			hasDetails: true,
			hasContext: true,
			hasTrace:   true,
		},
		{
			name:       "adapter without details",
			adapter:    NewHTTPErrorAdapter().WithDetails(false),
			hasDetails: false,
			hasContext: false,
			hasTrace:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, response := tt.adapter.ToHTTPResponse(err)

			if response == nil {
				t.Error("Response should not be nil")
				return
			}

			if tt.hasDetails && response.Details == "" {
				t.Error("Response should include details")
			}
			if !tt.hasDetails && response.Details != "" {
				t.Error("Response should not include details")
			}

			if tt.hasContext && len(response.Context) == 0 {
				t.Error("Response should include context")
			}
			if !tt.hasContext && len(response.Context) > 0 {
				t.Error("Response should not include context")
			}

			if tt.hasTrace && response.TraceID == "" {
				t.Error("Response should include trace ID")
			}
			if !tt.hasTrace && response.TraceID != "" {
				t.Error("Response should not include trace ID")
			}
		})
	}
}

func TestHTTPErrorAdapter_RetryInfo(t *testing.T) {
	adapter := NewHTTPErrorAdapter()

	// Test retryable error
	retryableErr := RateLimit("too many requests", 30*time.Second)
	_, response := adapter.ToHTTPResponse(retryableErr)

	if response == nil {
		t.Error("Response should not be nil")
		return
	}

	if !response.Retryable {
		t.Error("Response should indicate retryable")
	}

	if response.RetryAfter != 30 {
		t.Errorf("Expected retry after 30 seconds, got %d", response.RetryAfter)
	}

	// Test non-retryable error
	nonRetryableErr := Validation("invalid input")
	_, response = adapter.ToHTTPResponse(nonRetryableErr)

	if response == nil {
		t.Error("Response should not be nil")
		return
	}

	if response.Retryable {
		t.Error("Response should not indicate retryable")
	}

	if response.RetryAfter != 0 {
		t.Errorf("Expected retry after 0 seconds, got %d", response.RetryAfter)
	}
}

func TestHTTPErrorAdapter_WriteHTTPError(t *testing.T) {
	adapter := NewHTTPErrorAdapter()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedHeader string
	}{
		{
			name:           "validation error",
			err:            Validation("invalid input"),
			expectedStatus: http.StatusBadRequest,
			expectedHeader: "",
		},
		{
			name:           "rate limit error",
			err:            RateLimit("too many requests", 30*time.Second),
			expectedStatus: http.StatusTooManyRequests,
			expectedHeader: "30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			adapter.WriteHTTPError(recorder, tt.err)

			if recorder.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}

			contentType := recorder.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", contentType)
			}

			if tt.expectedHeader != "" {
				retryAfter := recorder.Header().Get("Retry-After")
				if retryAfter != tt.expectedHeader {
					t.Errorf("Expected Retry-After %s, got %s", tt.expectedHeader, retryAfter)
				}
			}

			// Test JSON response
			var response HTTPErrorResponse
			err := json.Unmarshal(recorder.Body.Bytes(), &response)
			if err != nil {
				t.Errorf("Failed to unmarshal response: %v", err)
			}

			if response.Success {
				t.Error("Success should be false")
			}
		})
	}
}

func TestHTTPErrorMiddleware(t *testing.T) {
	adapter := NewHTTPErrorAdapter()
	middleware := HTTPErrorMiddleware(adapter)

	t.Run("normal request", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", recorder.Code)
		}

		if recorder.Body.String() != "success" {
			t.Errorf("Expected body 'success', got %s", recorder.Body.String())
		}
	})

	t.Run("panic recovery", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		// Should not panic
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", recorder.Code)
		}

		var response HTTPErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal error response: %v", err)
		}

		if response.Success {
			t.Error("Success should be false for panic")
		}
	})
}

func TestErrorHandlerHTTPMiddleware(t *testing.T) {
	handler := NewStandardErrorHandler()
	adapter := NewHTTPErrorAdapter()
	middleware := ErrorHandlerHTTPMiddleware(handler, adapter)

	var handledError *UnifiedError
	handler.Register(func(ctx context.Context, err *UnifiedError) error {
		handledError = err
		return nil
	})

	t.Run("panic with error handling", func(t *testing.T) {
		httpHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(fmt.Errorf("test error"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		httpHandler.ServeHTTP(recorder, req)

		if handledError == nil {
			t.Error("Error should be handled by error handler")
		}

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", recorder.Code)
		}
	})
}

func TestHTTPResponseWriter(t *testing.T) {
	t.Run("normal write", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		writer := NewHTTPResponseWriter(recorder)

		writer.Write([]byte("test"))

		if writer.StatusCode() != http.StatusOK {
			t.Errorf("Expected status 200, got %d", writer.StatusCode())
		}

		if recorder.Body.String() != "test" {
			t.Errorf("Expected body 'test', got %s", recorder.Body.String())
		}
	})

	t.Run("write header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		writer := NewHTTPResponseWriter(recorder)

		writer.WriteHeader(http.StatusNotFound)
		writer.Write([]byte("not found"))

		if writer.StatusCode() != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", writer.StatusCode())
		}
	})

	t.Run("multiple write headers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		writer := NewHTTPResponseWriter(recorder)

		writer.WriteHeader(http.StatusNotFound)
		writer.WriteHeader(http.StatusInternalServerError) // Should be ignored

		if writer.StatusCode() != http.StatusNotFound {
			t.Errorf("Expected status 404 (first call), got %d", writer.StatusCode())
		}
	})
}

func TestAccessLogMiddleware(t *testing.T) {
	middleware := AccessLogMiddleware()

	t.Run("successful request", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", recorder.Code)
		}
	})

	t.Run("error request", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		}))

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("User-Agent", "test-agent")
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", recorder.Code)
		}
	})
}

func TestGlobalHTTPAdapter(t *testing.T) {
	// Test global WriteHTTPError function
	recorder := httptest.NewRecorder()
	err := Validation("test error")

	WriteHTTPError(recorder, err)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", recorder.Code)
	}

	// Test global ToHTTPResponse function
	statusCode, response := ToHTTPResponse(err)
	if statusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", statusCode)
	}

	if response.Code != "VALIDATION_ERROR" {
		t.Errorf("Expected code VALIDATION_ERROR, got %s", response.Code)
	}
}

func TestSetGlobalHTTPAdapter(t *testing.T) {
	// Save original adapter
	originalAdapter := GetGlobalHTTPAdapter()
	defer SetGlobalHTTPAdapter(originalAdapter)

	// Set custom adapter
	customAdapter := NewHTTPErrorAdapter().WithDetails(false).WithTrace(true)
	SetGlobalHTTPAdapter(customAdapter)

	// Test that global functions use the custom adapter
	err := Validation("test error")
	err.Details = "detailed message"
	err.WithTrace("trace-123", "span-456")

	_, response := ToHTTPResponse(err)

	// Details should be excluded (WithDetails(false))
	if response.Details != "" {
		t.Error("Details should be excluded with custom adapter")
	}

	// Trace should be included (WithTrace(true))
	if response.TraceID == "" {
		t.Error("Trace ID should be included with custom adapter")
	}
}

func TestDefaultHTTPErrorHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()
	err := Business("business error")

	DefaultHTTPErrorHandler(recorder, req, err)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422, got %d", recorder.Code)
	}

	var response HTTPErrorResponse
	jsonErr := json.Unmarshal(recorder.Body.Bytes(), &response)
	if jsonErr != nil {
		t.Errorf("Failed to unmarshal response: %v", jsonErr)
	}

	if response.Code != "BUSINESS_ERROR" {
		t.Errorf("Expected code BUSINESS_ERROR, got %s", response.Code)
	}
}
