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
	"testing"
	"time"
)

func TestStandardErrorHandler_Handle(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	// Test handling nil error
	err := handler.Handle(ctx, nil)
	if err != nil {
		t.Error("Handling nil error should return nil")
	}

	// Test handling standard error
	standardErr := fmt.Errorf("standard error")
	processedErr := handler.Handle(ctx, standardErr)

	unifiedErr, ok := processedErr.(*UnifiedError)
	if !ok {
		t.Error("Standard error should be converted to UnifiedError")
	}

	if unifiedErr.Code != ErrCodeInternal {
		t.Errorf("Expected code %s, got %s", ErrCodeInternal, unifiedErr.Code)
	}

	// Test handling UnifiedError
	originalErr := Validation("validation failed")
	processedErr = handler.Handle(ctx, originalErr)

	if processedErr != originalErr {
		t.Error("UnifiedError should be returned as-is")
	}
}

func TestStandardErrorHandler_RegisterHandler(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	var handlerCalled bool
	var handlerError *UnifiedError

	// Register a test handler
	handler.Register(func(ctx context.Context, err *UnifiedError) error {
		handlerCalled = true
		handlerError = err
		return nil
	})

	// Handle an error
	testErr := Validation("test error")
	handler.Handle(ctx, testErr)

	if !handlerCalled {
		t.Error("Registered handler should be called")
	}

	if handlerError != testErr {
		t.Error("Handler should receive the original error")
	}
}

func TestStandardErrorHandler_MultipleHandlers(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	var callOrder []int

	// Register multiple handlers
	for i := 1; i <= 3; i++ {
		id := i
		handler.Register(func(ctx context.Context, err *UnifiedError) error {
			callOrder = append(callOrder, id)
			return nil
		})
	}

	// Handle an error
	testErr := Validation("test error")
	handler.Handle(ctx, testErr)

	if len(callOrder) != 3 {
		t.Errorf("Expected 3 handlers to be called, got %d", len(callOrder))
	}

	// Handlers should be called in registration order
	for i, id := range callOrder {
		if id != i+1 {
			t.Errorf("Handler %d should be called at position %d, got position %d", id, id-1, i)
		}
	}
}

func TestStandardErrorHandler_HandlerError(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	// Register a handler that returns an error
	handler.Register(func(ctx context.Context, err *UnifiedError) error {
		return fmt.Errorf("handler failed")
	})

	// This should not panic or fail
	testErr := Validation("test error")
	processedErr := handler.Handle(ctx, testErr)

	if processedErr == nil {
		t.Error("Should still return the original error even if handler fails")
	}
}

func TestStandardErrorHandler_SetFallback(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	var fallbackCalled bool
	var fallbackError *UnifiedError

	// Set custom fallback handler
	handler.SetFallback(func(ctx context.Context, err *UnifiedError) error {
		fallbackCalled = true
		fallbackError = err
		return nil
	})

	// Handle an error
	testErr := Validation("test error")
	handler.Handle(ctx, testErr)

	if !fallbackCalled {
		t.Error("Fallback handler should be called")
	}

	if fallbackError != testErr {
		t.Error("Fallback should receive the original error")
	}
}

func TestStandardErrorHandler_WithMetrics(t *testing.T) {
	handler := NewStandardErrorHandler()
	metrics := NewMemoryErrorMetrics()
	handler.SetMetrics(metrics)

	ctx := context.Background()

	// Handle different types of errors
	handler.Handle(ctx, Validation("validation error"))
	handler.Handle(ctx, Database("database error"))
	handler.Handle(ctx, Validation("another validation error"))

	// Check metrics
	validationCount := metrics.GetErrorCount(ErrCodeValidation)
	if validationCount != 2 {
		t.Errorf("Expected 2 validation errors, got %d", validationCount)
	}

	databaseCount := metrics.GetErrorCount(ErrCodeDatabase)
	if databaseCount != 1 {
		t.Errorf("Expected 1 database error, got %d", databaseCount)
	}
}

func TestStandardErrorHandler_WithReporter(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	var reportedErrors []*UnifiedError

	// Mock reporter
	mockReporter := &MockErrorReporter{
		reportFunc: func(ctx context.Context, err *UnifiedError) error {
			reportedErrors = append(reportedErrors, err)
			return nil
		},
	}

	handler.SetReporter(mockReporter)

	// Handle errors
	testErr1 := Validation("validation error")
	testErr2 := Database("database error")

	handler.Handle(ctx, testErr1)
	handler.Handle(ctx, testErr2)

	if len(reportedErrors) != 2 {
		t.Errorf("Expected 2 reported errors, got %d", len(reportedErrors))
	}
}

func TestStandardErrorHandler_ConcurrentAccess(t *testing.T) {
	handler := NewStandardErrorHandler()
	metrics := NewMemoryErrorMetrics()
	handler.SetMetrics(metrics)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Test concurrent registration and handling
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Register a handler
			handler.Register(func(ctx context.Context, err *UnifiedError) error {
				return nil
			})

			// Handle multiple errors
			for j := 0; j < 100; j++ {
				err := Validation(fmt.Sprintf("error from goroutine %d", id))
				handler.Handle(ctx, err)
			}
		}(i)
	}

	wg.Wait()

	// Check that all errors were recorded
	count := metrics.GetErrorCount(ErrCodeValidation)
	if count != 1000 {
		t.Errorf("Expected 1000 errors, got %d", count)
	}
}

func TestMemoryErrorMetrics(t *testing.T) {
	metrics := NewMemoryErrorMetrics()

	// Test initial state
	if metrics.GetErrorCount(ErrCodeValidation) != 0 {
		t.Error("Initial error count should be 0")
	}

	if metrics.GetErrorRate() != 0 {
		t.Error("Initial error rate should be 0")
	}

	// Record some errors
	metrics.RecordError(ErrCodeValidation, SeverityLow)
	metrics.RecordError(ErrCodeValidation, SeverityLow)
	metrics.RecordError(ErrCodeDatabase, SeverityHigh)

	// Check counts
	if metrics.GetErrorCount(ErrCodeValidation) != 2 {
		t.Errorf("Expected 2 validation errors, got %d", metrics.GetErrorCount(ErrCodeValidation))
	}

	if metrics.GetErrorCount(ErrCodeDatabase) != 1 {
		t.Errorf("Expected 1 database error, got %d", metrics.GetErrorCount(ErrCodeDatabase))
	}

	// Check error rate (should be > 0 since time has passed)
	rate := metrics.GetErrorRate()
	if rate <= 0 {
		t.Errorf("Error rate should be > 0, got %f", rate)
	}

	// Test GetAllErrorCounts
	allCounts := metrics.GetAllErrorCounts()
	if len(allCounts) != 2 {
		t.Errorf("Expected 2 error types, got %d", len(allCounts))
	}
}

func TestMemoryErrorMetrics_ConcurrentAccess(t *testing.T) {
	metrics := NewMemoryErrorMetrics()
	var wg sync.WaitGroup

	// Test concurrent error recording
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				metrics.RecordError(ErrCodeValidation, SeverityLow)
			}
		}()
	}

	wg.Wait()

	// Check final count
	count := metrics.GetErrorCount(ErrCodeValidation)
	if count != 1000 {
		t.Errorf("Expected 1000 errors, got %d", count)
	}
}

func TestGlobalFunctions(t *testing.T) {
	ctx := context.Background()

	// Test global Handle function
	err := Validation("test error")
	processedErr := Handle(ctx, err)

	if processedErr != err {
		t.Error("Global Handle should process the error")
	}

	// Test convenience functions
	t.Run("HandleAndLog", func(t *testing.T) {
		HandleAndLog(ctx, fmt.Errorf("test error"), "operation failed")
		// This should not panic
	})

	t.Run("HandleValidation", func(t *testing.T) {
		err := HandleValidation(ctx, "email", "invalid format")
		unifiedErr, ok := err.(*UnifiedError)
		if !ok {
			t.Error("Should return UnifiedError")
		}
		if unifiedErr.Code != ErrCodeValidation {
			t.Error("Should have validation error code")
		}
	})

	t.Run("HandleDatabase", func(t *testing.T) {
		cause := fmt.Errorf("connection failed")
		err := HandleDatabase(ctx, "user query", cause)
		unifiedErr, ok := err.(*UnifiedError)
		if !ok {
			t.Error("Should return UnifiedError")
		}
		if unifiedErr.Code != ErrCodeDatabase {
			t.Error("Should have database error code")
		}
	})

	t.Run("HandleBusiness", func(t *testing.T) {
		err := HandleBusiness(ctx, "business rule violated")
		unifiedErr, ok := err.(*UnifiedError)
		if !ok {
			t.Error("Should return UnifiedError")
		}
		if unifiedErr.Code != ErrCodeBusiness {
			t.Error("Should have business error code")
		}
	})

	t.Run("HandleConfig", func(t *testing.T) {
		err := HandleConfig(ctx, "config missing")
		unifiedErr, ok := err.(*UnifiedError)
		if !ok {
			t.Error("Should return UnifiedError")
		}
		if unifiedErr.Code != ErrCodeConfig {
			t.Error("Should have config error code")
		}
	})
}

func TestRetryWithBackoff(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulRetry", func(t *testing.T) {
		attempts := 0
		err := RetryWithBackoff(ctx, func() error {
			attempts++
			if attempts < 3 {
				return Database("connection failed").WithRetry(true, time.Millisecond)
			}
			return nil
		}, 5)

		if err != nil {
			t.Errorf("Expected success after retries, got error: %v", err)
		}

		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("NonRetryableError", func(t *testing.T) {
		attempts := 0
		err := RetryWithBackoff(ctx, func() error {
			attempts++
			return Validation("invalid input") // Not retryable
		}, 5)

		if err == nil {
			t.Error("Expected error for non-retryable failure")
		}

		if attempts != 1 {
			t.Errorf("Expected 1 attempt for non-retryable error, got %d", attempts)
		}
	})

	t.Run("MaxRetriesExceeded", func(t *testing.T) {
		attempts := 0
		err := RetryWithBackoff(ctx, func() error {
			attempts++
			return Database("connection failed").WithRetry(true, time.Millisecond)
		}, 3)

		if err == nil {
			t.Error("Expected error when max retries exceeded")
		}

		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		attempts := 0
		errChan := make(chan error, 1)

		go func() {
			err := RetryWithBackoff(ctx, func() error {
				attempts++
				return Database("connection failed").WithRetry(true, time.Second)
			}, 10)
			errChan <- err
		}()

		// Cancel context after a short delay
		time.Sleep(10 * time.Millisecond)
		cancel()

		// Wait for completion
		err := <-errChan

		if err == nil {
			t.Error("Expected error when context is cancelled")
		}

		unifiedErr, ok := err.(*UnifiedError)
		if ok && unifiedErr.Code != ErrCodeTimeout {
			t.Error("Expected timeout error code for cancelled context")
		}
	})
}

func TestWithErrorHandling(t *testing.T) {
	// Test successful function
	fn1 := WithErrorHandling(func() error {
		return nil
	})
	fn1() // Should not panic

	// Test function with error
	fn2 := WithErrorHandling(func() error {
		return fmt.Errorf("test error")
	})
	fn2() // Should not panic, error should be handled

	// Test function that panics
	fn3 := WithErrorHandling(func() error {
		panic("test panic")
	})
	fn3() // Should not panic, should recover and handle error
}

func TestRecovery(t *testing.T) {
	ctx := context.Background()

	// Test recovery with error
	func() {
		defer Recovery(ctx)
		panic(fmt.Errorf("test error"))
	}() // Should not panic

	// Test recovery with string
	func() {
		defer Recovery(ctx)
		panic("test panic")
	}() // Should not panic
}

// MockErrorReporter for testing
type MockErrorReporter struct {
	reportFunc func(ctx context.Context, err *UnifiedError) error
}

func (m *MockErrorReporter) Report(ctx context.Context, err *UnifiedError) error {
	if m.reportFunc != nil {
		return m.reportFunc(ctx, err)
	}
	return nil
}

// Test reporter error handling
func TestErrorReporter_Error(t *testing.T) {
	handler := NewStandardErrorHandler()
	ctx := context.Background()

	// Mock reporter that returns error
	mockReporter := &MockErrorReporter{
		reportFunc: func(ctx context.Context, err *UnifiedError) error {
			return fmt.Errorf("reporter failed")
		},
	}

	handler.SetReporter(mockReporter)

	// This should not panic even if reporter fails
	testErr := Validation("test error")
	processedErr := handler.Handle(ctx, testErr)

	if processedErr == nil {
		t.Error("Should still return error even if reporter fails")
	}
}

func TestLoggingErrorReporter(t *testing.T) {
	reporter := &LoggingErrorReporter{}
	ctx := context.Background()

	err := Validation("test error")
	err.WithContext("field", "email")
	err.WithTrace("trace-123", "span-456")

	// This should not panic
	reportErr := reporter.Report(ctx, err)
	if reportErr != nil {
		t.Errorf("LoggingErrorReporter should not return error, got: %v", reportErr)
	}
}
