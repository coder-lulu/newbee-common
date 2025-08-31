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

package middleware

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker_Basic(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "test-breaker"
	config.FailureThreshold = 3
	config.MinimumRequestThreshold = 5
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Initially closed
	if cb.State() != StateClosed {
		t.Errorf("Expected initial state to be CLOSED, got %v", cb.State())
	}

	// Successful calls should keep it closed
	for i := 0; i < 10; i++ {
		err := cb.Execute(ctx, func(ctx context.Context) error {
			return nil
		})
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	if cb.State() != StateClosed {
		t.Errorf("Expected state to remain CLOSED after successes, got %v", cb.State())
	}

	// Failed calls should open the breaker
	for i := 0; i < 5; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return fmt.Errorf("test error %d", i)
		})
	}

	if cb.State() != StateOpen {
		t.Errorf("Expected state to be OPEN after failures, got %v", cb.State())
	}

	// Further calls should be rejected
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})
	if !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Errorf("Expected ErrCircuitBreakerOpen, got %v", err)
	}
}

func TestCircuitBreaker_HalfOpen(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "test-breaker-halfopen"
	config.FailureThreshold = 2
	config.MinimumRequestThreshold = 3
	config.Timeout = 100 * time.Millisecond // Short timeout for testing
	config.ReadyToTrip = func(counts Counts) bool {
		return counts.Requests >= 3 && counts.Failures >= 2
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Trigger failure to open the breaker
	// Need at least 3 requests and 2 failures to meet threshold
	for i := 0; i < 5; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return errors.New("test error")
		})
	}

	if cb.State() != StateOpen {
		t.Errorf("Expected state to be OPEN, got %v", cb.State())
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Next call should transition to HALF_OPEN
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Errorf("Unexpected error in half-open state: %v", err)
	}

	// State should eventually become CLOSED again
	for i := 0; i < 10; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return nil
		})
	}

	if cb.State() != StateClosed {
		t.Errorf("Expected state to be CLOSED after successes, got %v", cb.State())
	}
}

func TestCircuitBreaker_Concurrent(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "test-breaker-concurrent"
	config.FailureThreshold = 10
	config.MinimumRequestThreshold = 20
	cb := NewCircuitBreaker(config)

	ctx := context.Background()
	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64

	// Concurrent successful calls
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cb.Execute(ctx, func(ctx context.Context) error {
				time.Sleep(1 * time.Millisecond)
				return nil
			})
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 50 {
		t.Errorf("Expected 50 successes, got %d", successCount)
	}

	if errorCount != 0 {
		t.Errorf("Expected 0 errors, got %d", errorCount)
	}

	if cb.State() != StateClosed {
		t.Errorf("Expected state to be CLOSED, got %v", cb.State())
	}
}

func TestWithTimeout_Success(t *testing.T) {
	ctx := context.Background()

	err := WithTimeout(ctx, 100*time.Millisecond, func(ctx context.Context) error {
		time.Sleep(50 * time.Millisecond)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestWithTimeout_Timeout(t *testing.T) {
	ctx := context.Background()

	err := WithTimeout(ctx, 50*time.Millisecond, func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})

	if !errors.Is(err, ErrCircuitBreakerTimeout) {
		t.Errorf("Expected ErrCircuitBreakerTimeout, got %v", err)
	}
}

func TestWithTimeout_Panic(t *testing.T) {
	ctx := context.Background()

	err := WithTimeout(ctx, 100*time.Millisecond, func(ctx context.Context) error {
		panic("test panic")
	})

	if err == nil {
		t.Error("Expected error when function panics")
	}

	if err.Error() != "panic in timeout function" {
		t.Errorf("Expected 'panic in timeout function' error, got: %v", err)
	}
}

func TestCircuitBreaker_StateCallback(t *testing.T) {
	var stateChanges []string
	config := DefaultCircuitBreakerConfig()
	config.Name = "test-callback"
	config.FailureThreshold = 2
	config.MinimumRequestThreshold = 3
	config.ReadyToTrip = func(counts Counts) bool {
		return counts.Requests >= 3 && counts.Failures >= 2
	}
	config.OnStateChange = func(name string, from, to CircuitBreakerState) {
		stateChanges = append(stateChanges, fmt.Sprintf("%s: %s -> %s", name, from.String(), to.String()))
	}

	cb := NewCircuitBreaker(config)
	ctx := context.Background()

	// Trigger failures to open
	// Need at least 3 requests and 2 failures to meet threshold
	for i := 0; i < 5; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return errors.New("test error")
		})
	}

	// Wait for callback goroutine to complete
	time.Sleep(10 * time.Millisecond)

	if len(stateChanges) == 0 {
		t.Error("Expected state change callbacks")
	}

	found := false
	for _, change := range stateChanges {
		if change == "test-callback: CLOSED -> OPEN" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected 'CLOSED -> OPEN' state change, got: %v", stateChanges)
	}
}

func TestCircuitBreaker_Counts(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "test-counts"
	cb := NewCircuitBreaker(config)
	ctx := context.Background()

	// Make some successful calls
	for i := 0; i < 5; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return nil
		})
	}

	// Make some failed calls
	for i := 0; i < 3; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return errors.New("test error")
		})
	}

	counts := cb.Counts()

	if counts.Requests != 8 {
		t.Errorf("Expected 8 requests, got %d", counts.Requests)
	}

	if counts.Successes != 5 {
		t.Errorf("Expected 5 successes, got %d", counts.Successes)
	}

	if counts.Failures != 3 {
		t.Errorf("Expected 3 failures, got %d", counts.Failures)
	}

	expectedRate := 3.0 / 8.0
	actualRate := counts.FailureRate()
	if actualRate != expectedRate {
		t.Errorf("Expected failure rate %.2f, got %.2f", expectedRate, actualRate)
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "test-reset"
	config.FailureThreshold = 2
	config.MinimumRequestThreshold = 3
	config.ReadyToTrip = func(counts Counts) bool {
		return counts.Requests >= 3 && counts.Failures >= 2
	}
	cb := NewCircuitBreaker(config)
	ctx := context.Background()

	// Open the breaker
	// Need at least 3 requests and 2 failures to meet threshold
	for i := 0; i < 5; i++ {
		cb.Execute(ctx, func(ctx context.Context) error {
			return errors.New("test error")
		})
	}

	if cb.State() != StateOpen {
		t.Errorf("Expected state to be OPEN, got %v", cb.State())
	}

	// Reset should close it
	cb.Reset()

	if cb.State() != StateClosed {
		t.Errorf("Expected state to be CLOSED after reset, got %v", cb.State())
	}

	// Counts should be reset
	counts := cb.Counts()
	if counts.Requests != 0 || counts.Successes != 0 || counts.Failures != 0 {
		t.Errorf("Expected all counts to be 0 after reset, got: %+v", counts)
	}
}
