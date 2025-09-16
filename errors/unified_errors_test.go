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
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestUnifiedError_Error(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		message  string
		details  string
		expected string
	}{
		{
			name:     "error without details",
			code:     ErrCodeValidation,
			message:  "validation failed",
			details:  "",
			expected: "[VALIDATION_ERROR] validation failed",
		},
		{
			name:     "error with details",
			code:     ErrCodeDatabase,
			message:  "connection failed",
			details:  "timeout after 30s",
			expected: "[DATABASE_ERROR] connection failed: timeout after 30s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &UnifiedError{
				Code:    tt.code,
				Message: tt.message,
				Details: tt.details,
			}
			if got := err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUnifiedError_Unwrap(t *testing.T) {
	original := fmt.Errorf("original error")
	err := NewWithCause(ErrCodeInternal, "wrapped error", original)

	if unwrapped := err.Unwrap(); unwrapped != original {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, original)
	}
}

func TestUnifiedError_Is(t *testing.T) {
	err1 := New(ErrCodeValidation, "test error")
	err2 := New(ErrCodeValidation, "another test error")
	err3 := New(ErrCodeDatabase, "database error")

	if !err1.Is(err2) {
		t.Error("err1.Is(err2) should be true (same code)")
	}

	if err1.Is(err3) {
		t.Error("err1.Is(err3) should be false (different code)")
	}
}

func TestUnifiedError_WithContext(t *testing.T) {
	err := New(ErrCodeBusiness, "business error")
	err.WithContext("user_id", "12345")
	err.WithContext("action", "delete_order")

	if len(err.Context) != 2 {
		t.Errorf("Expected 2 context items, got %d", len(err.Context))
	}

	if err.Context["user_id"] != "12345" {
		t.Errorf("Expected user_id=12345, got %v", err.Context["user_id"])
	}

	if err.Context["action"] != "delete_order" {
		t.Errorf("Expected action=delete_order, got %v", err.Context["action"])
	}
}

func TestUnifiedError_WithTrace(t *testing.T) {
	err := New(ErrCodeInternal, "internal error")
	err.WithTrace("trace-123", "span-456")

	if err.TraceID != "trace-123" {
		t.Errorf("Expected TraceID=trace-123, got %s", err.TraceID)
	}

	if err.SpanID != "span-456" {
		t.Errorf("Expected SpanID=span-456, got %s", err.SpanID)
	}
}

func TestUnifiedError_WithRetry(t *testing.T) {
	err := New(ErrCodeNetwork, "network error")
	err.WithRetry(true, 5*time.Second)

	if !err.Retryable {
		t.Error("Expected error to be retryable")
	}

	if err.RetryAfter != 5*time.Second {
		t.Errorf("Expected RetryAfter=5s, got %v", err.RetryAfter)
	}
}

func TestUnifiedError_WithUserMessage(t *testing.T) {
	err := New(ErrCodeTimeout, "operation timeout")
	err.WithUserMessage("请求超时，请稍后重试")

	if err.UserMessage != "请求超时，请稍后重试" {
		t.Errorf("Expected user message, got %s", err.UserMessage)
	}
}

func TestUnifiedError_WithStackTrace(t *testing.T) {
	err := New(ErrCodeInternal, "internal error")
	err.WithStackTrace()

	if err.StackTrace == "" {
		t.Error("Expected stack trace to be set")
	}

	// Stack trace should contain function names
	if !contains(err.StackTrace, "TestUnifiedError_WithStackTrace") {
		t.Error("Stack trace should contain test function name")
	}
}

func TestNew(t *testing.T) {
	err := New(ErrCodeValidation, "validation error")

	if err.Code != ErrCodeValidation {
		t.Errorf("Expected code %s, got %s", ErrCodeValidation, err.Code)
	}

	if err.Message != "validation error" {
		t.Errorf("Expected message 'validation error', got %s", err.Message)
	}

	if err.Severity != SeverityMedium {
		t.Errorf("Expected default severity %s, got %s", SeverityMedium, err.Severity)
	}

	if err.Retryable {
		t.Error("Expected default retryable to be false")
	}
}

func TestNewWithCause(t *testing.T) {
	cause := fmt.Errorf("original error")
	err := NewWithCause(ErrCodeDatabase, "database error", cause)

	if err.Cause != cause {
		t.Errorf("Expected cause to be set, got %v", err.Cause)
	}

	if err.Details != "original error" {
		t.Errorf("Expected details to be cause message, got %s", err.Details)
	}
}

func TestWrap(t *testing.T) {
	original := fmt.Errorf("network connection failed")
	wrapped := Wrap(original, ErrCodeNetwork, "external service unavailable")

	if wrapped.Code != ErrCodeNetwork {
		t.Errorf("Expected code %s, got %s", ErrCodeNetwork, wrapped.Code)
	}

	if wrapped.Message != "external service unavailable" {
		t.Errorf("Expected message 'external service unavailable', got %s", wrapped.Message)
	}

	if wrapped.Cause != original {
		t.Errorf("Expected cause to be original error, got %v", wrapped.Cause)
	}
}

func TestWrapUnifiedError(t *testing.T) {
	original := New(ErrCodeValidation, "validation failed")
	original.WithContext("field", "email")

	wrapped := Wrap(original, ErrCodeBusiness, "business logic error")

	if wrapped.Code != ErrCodeBusiness {
		t.Errorf("Expected code %s, got %s", ErrCodeBusiness, wrapped.Code)
	}

	if wrapped.Cause != original {
		t.Errorf("Expected cause to be original unified error, got %v", wrapped.Cause)
	}

	// Should preserve context from original
	if len(wrapped.Context) != 1 {
		t.Error("Context should be preserved when wrapping UnifiedError")
	}

	if wrapped.Context["field"] != "email" {
		t.Error("Context values should be preserved when wrapping UnifiedError")
	}
}

func TestWrapWithSeverity(t *testing.T) {
	original := fmt.Errorf("critical system error")
	wrapped := WrapWithSeverity(original, ErrCodeInternal, "system failure", SeverityCritical)

	if wrapped.Severity != SeverityCritical {
		t.Errorf("Expected severity %s, got %s", SeverityCritical, wrapped.Severity)
	}
}

func TestConvenienceConstructors(t *testing.T) {
	tests := []struct {
		name     string
		creator  func() *UnifiedError
		code     ErrorCode
		severity ErrorSeverity
	}{
		{
			name:     "Internal",
			creator:  func() *UnifiedError { return Internal("internal error") },
			code:     ErrCodeInternal,
			severity: SeverityMedium,
		},
		{
			name:     "Validation",
			creator:  func() *UnifiedError { return Validation("validation error") },
			code:     ErrCodeValidation,
			severity: SeverityLow,
		},
		{
			name:     "NotFound",
			creator:  func() *UnifiedError { return NotFound("user") },
			code:     ErrCodeNotFound,
			severity: SeverityLow,
		},
		{
			name:     "Unauthorized",
			creator:  func() *UnifiedError { return Unauthorized("access denied") },
			code:     ErrCodeUnauthorized,
			severity: SeverityMedium,
		},
		{
			name:     "Forbidden",
			creator:  func() *UnifiedError { return Forbidden("insufficient permissions") },
			code:     ErrCodeForbidden,
			severity: SeverityMedium,
		},
		{
			name:     "Database",
			creator:  func() *UnifiedError { return Database("connection error") },
			code:     ErrCodeDatabase,
			severity: SeverityHigh,
		},
		{
			name:     "Config",
			creator:  func() *UnifiedError { return Config("config missing") },
			code:     ErrCodeConfig,
			severity: SeverityCritical,
		},
		{
			name:     "Business",
			creator:  func() *UnifiedError { return Business("business rule violation") },
			code:     ErrCodeBusiness,
			severity: SeverityMedium,
		},
		{
			name:     "Timeout",
			creator:  func() *UnifiedError { return Timeout("operation") },
			code:     ErrCodeTimeout,
			severity: SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.creator()

			if err.Code != tt.code {
				t.Errorf("Expected code %s, got %s", tt.code, err.Code)
			}

			if err.Severity != tt.severity {
				t.Errorf("Expected severity %s, got %s", tt.severity, err.Severity)
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	retryAfter := 30 * time.Second
	err := RateLimit("too many requests", retryAfter)

	if err.Code != ErrCodeRateLimit {
		t.Errorf("Expected code %s, got %s", ErrCodeRateLimit, err.Code)
	}

	if !err.Retryable {
		t.Error("Rate limit error should be retryable")
	}

	if err.RetryAfter != retryAfter {
		t.Errorf("Expected retry after %v, got %v", retryAfter, err.RetryAfter)
	}

	if err.Severity != SeverityLow {
		t.Errorf("Expected severity %s, got %s", SeverityLow, err.Severity)
	}
}

func TestInternalWithCause(t *testing.T) {
	cause := fmt.Errorf("system panic")
	err := InternalWithCause("unexpected error", cause)

	if err.Code != ErrCodeInternal {
		t.Errorf("Expected code %s, got %s", ErrCodeInternal, err.Code)
	}

	if err.Cause != cause {
		t.Errorf("Expected cause to be set, got %v", err.Cause)
	}

	if err.StackTrace == "" {
		t.Error("Internal error should include stack trace")
	}
}

func TestValidationWithDetails(t *testing.T) {
	err := ValidationWithDetails("field validation failed", "email format is invalid")

	if err.Code != ErrCodeValidation {
		t.Errorf("Expected code %s, got %s", ErrCodeValidation, err.Code)
	}

	if err.Details != "email format is invalid" {
		t.Errorf("Expected details 'email format is invalid', got %s", err.Details)
	}
}

func TestDatabaseWithCause(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	err := DatabaseWithCause("database operation failed", cause)

	if err.Code != ErrCodeDatabase {
		t.Errorf("Expected code %s, got %s", ErrCodeDatabase, err.Code)
	}

	if err.Cause != cause {
		t.Errorf("Expected cause to be set, got %v", err.Cause)
	}

	if !err.Retryable {
		t.Error("Database error should be retryable")
	}

	if err.RetryAfter != 5*time.Second {
		t.Errorf("Expected retry after 5s, got %v", err.RetryAfter)
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("IsRetryable", func(t *testing.T) {
		retryableErr := Database("connection error")
		nonRetryableErr := Validation("invalid input")

		if !IsRetryable(retryableErr) {
			t.Error("Database error should be retryable")
		}

		if IsRetryable(nonRetryableErr) {
			t.Error("Validation error should not be retryable")
		}

		// Test with non-UnifiedError
		if IsRetryable(fmt.Errorf("standard error")) {
			t.Error("Standard error should not be retryable")
		}
	})

	t.Run("GetRetryAfter", func(t *testing.T) {
		retryAfter := 10 * time.Second
		err := RateLimit("rate limited", retryAfter)

		if GetRetryAfter(err) != retryAfter {
			t.Errorf("Expected retry after %v, got %v", retryAfter, GetRetryAfter(err))
		}

		// Test with non-UnifiedError
		if GetRetryAfter(fmt.Errorf("standard error")) != 0 {
			t.Error("Standard error should have zero retry after")
		}
	})

	t.Run("GetSeverity", func(t *testing.T) {
		err := Config("critical config error")

		if GetSeverity(err) != SeverityCritical {
			t.Errorf("Expected severity %s, got %s", SeverityCritical, GetSeverity(err))
		}

		// Test with non-UnifiedError
		if GetSeverity(fmt.Errorf("standard error")) != SeverityMedium {
			t.Error("Standard error should have medium severity")
		}
	})

	t.Run("GetUserMessage", func(t *testing.T) {
		err := Business("order cannot be cancelled")

		if GetUserMessage(err) != "order cannot be cancelled" {
			t.Errorf("Expected user message to be business message, got %s", GetUserMessage(err))
		}

		// Test with error without user message
		internalErr := Internal("internal error")
		if GetUserMessage(internalErr) != "系统异常，请稍后重试" {
			t.Error("Internal error should have default user message")
		}

		// Test with non-UnifiedError
		if GetUserMessage(fmt.Errorf("standard error")) != "系统异常，请稍后重试" {
			t.Error("Standard error should have default user message")
		}
	})

	t.Run("GetTraceInfo", func(t *testing.T) {
		err := New(ErrCodeInternal, "test error")
		err.WithTrace("trace-123", "span-456")

		traceID, spanID := GetTraceInfo(err)
		if traceID != "trace-123" {
			t.Errorf("Expected trace ID 'trace-123', got %s", traceID)
		}
		if spanID != "span-456" {
			t.Errorf("Expected span ID 'span-456', got %s", spanID)
		}

		// Test with non-UnifiedError
		traceID, spanID = GetTraceInfo(fmt.Errorf("standard error"))
		if traceID != "" || spanID != "" {
			t.Error("Standard error should have empty trace info")
		}
	})
}

func TestToJSON(t *testing.T) {
	err := New(ErrCodeValidation, "validation failed")
	err.WithContext("field", "email")
	err.WithTrace("trace-123", "span-456")

	jsonStr := err.ToJSON()
	if jsonStr == "" {
		t.Error("JSON serialization should not be empty")
	}

	// Should contain key fields
	if !contains(jsonStr, "VALIDATION_ERROR") {
		t.Error("JSON should contain error code")
	}
	if !contains(jsonStr, "validation failed") {
		t.Error("JSON should contain error message")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				strings.Contains(s, substr))))
}
