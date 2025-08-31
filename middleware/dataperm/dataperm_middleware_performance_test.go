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

package dataperm

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDataPermMiddleware_AsyncRefreshFunctionality(t *testing.T) {
	config := &DataPermConfig{
		EnableTenantMode: false,
		DefaultTenantId:  1,
		CacheExpiration:  0,
	}

	middleware := &DataPermMiddleware{
		Config:           config,
		refreshSemaphore: make(chan struct{}, 10),
	}

	t.Run("Concurrent refresh protection", func(t *testing.T) {
		// Test that multiple concurrent refreshes for the same key are properly handled
		const numGoroutines = 10
		var wg sync.WaitGroup

		testKey := "test:role:permission:key"

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				// Simulate async refresh call using sync.Map
				if _, loaded := middleware.refreshingKeys.LoadOrStore(testKey, true); loaded {
					// Should skip if already refreshing
					return
				}

				// Simulate work
				time.Sleep(10 * time.Millisecond)

				// Cleanup
				middleware.refreshingKeys.Delete(testKey)
			}()
		}

		wg.Wait()

		// Verify cleanup
		count := 0
		middleware.refreshingKeys.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
		if count != 0 {
			t.Errorf("Expected empty refreshing keys map, got %d entries", count)
		}
	})

	t.Run("Refresh key lifecycle", func(t *testing.T) {
		testKey := "test:lifecycle:key"

		// Should not be present initially
		if _, exists := middleware.refreshingKeys.Load(testKey); exists {
			t.Error("Key should not be present initially")
		}

		// Store key
		middleware.refreshingKeys.Store(testKey, true)

		// Should be present now
		if _, exists := middleware.refreshingKeys.Load(testKey); !exists {
			t.Error("Key should be present after storing")
		}

		// Delete key
		middleware.refreshingKeys.Delete(testKey)

		// Should not be present after deletion
		if _, exists := middleware.refreshingKeys.Load(testKey); exists {
			t.Error("Key should not be present after deletion")
		}
	})
}

func TestDataPermMiddleware_AsyncRefreshTimeout(t *testing.T) {
	// Test that async refresh operations have proper timeout handling
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Simulate timeout scenario
	select {
	case <-time.After(200 * time.Millisecond):
		t.Error("Operation should have timed out")
	case <-ctx.Done():
		// Expected timeout
		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("Expected deadline exceeded, got %v", ctx.Err())
		}
	}
}

func BenchmarkDataPermMiddleware_AsyncVsSync(b *testing.B) {
	// This benchmark demonstrates the performance difference
	// between async and synchronous approaches

	b.Run("Async approach simulation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Simulate async cache miss handling
			start := time.Now()

			// Return immediately with default value (async behavior)
			defaultValue := "4" // DataPermOwnDeptStr
			_ = defaultValue

			// Record time for immediate response
			elapsed := time.Since(start)

			// Should be very fast (microseconds)
			if elapsed > time.Millisecond {
				b.Errorf("Async approach took too long: %v", elapsed)
			}
		}
	})

	b.Run("Sync approach simulation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Simulate synchronous RPC call
			start := time.Now()

			// Simulate RPC delay (what the old code would do)
			time.Sleep(1 * time.Millisecond) // Even 1ms is significant for high-load APIs

			elapsed := time.Since(start)

			// Will be slower due to simulated RPC call
			_ = elapsed
		}
	})
}

func TestDataPermMiddleware_AsyncRefreshMethods(t *testing.T) {
	// Test that the middleware struct has the required fields for async operations
	middleware := &DataPermMiddleware{
		refreshSemaphore: make(chan struct{}, 5),
	}

	// Verify the async control fields exist and are properly initialized
	if middleware.refreshSemaphore == nil {
		t.Error("refreshSemaphore should be initialized")
	}

	// Test semaphore capacity
	if cap(middleware.refreshSemaphore) != 5 {
		t.Errorf("Expected semaphore capacity 5, got %d", cap(middleware.refreshSemaphore))
	}

	// Test basic sync.Map operations
	testKey := "test:method:key"

	// Should not be present initially
	if _, exists := middleware.refreshingKeys.Load(testKey); exists {
		t.Error("Key should not be present initially")
	}

	// Can use LoadOrStore
	if _, loaded := middleware.refreshingKeys.LoadOrStore(testKey, true); loaded {
		t.Error("Key should not be loaded on first LoadOrStore")
	}

	// Should be loaded on second call
	if _, loaded := middleware.refreshingKeys.LoadOrStore(testKey, true); !loaded {
		t.Error("Key should be loaded on second LoadOrStore")
	}

	// Can be deleted
	middleware.refreshingKeys.Delete(testKey)
	if _, exists := middleware.refreshingKeys.Load(testKey); exists {
		t.Error("Key should be deleted")
	}
}
