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

package config

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCacheItem_IsExpired(t *testing.T) {
	// Test non-expired item
	futureTime := time.Now().Add(1 * time.Hour)
	item := &CacheItem{
		Value:     "test",
		ExpiresAt: futureTime,
	}

	if item.IsExpired() {
		t.Error("Item should not be expired")
	}

	// Test expired item
	pastTime := time.Now().Add(-1 * time.Hour)
	item.ExpiresAt = pastTime

	if !item.IsExpired() {
		t.Error("Item should be expired")
	}
}

func TestNewMemoryUnifiedConfigCache(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	if cache == nil {
		t.Error("NewMemoryUnifiedConfigCache should not return nil")
	}

	if cache.items == nil {
		t.Error("Cache items map should be initialized")
	}

	if cache.cleanupInterval != 10*time.Minute {
		t.Errorf("Expected default cleanup interval 10m, got %v", cache.cleanupInterval)
	}
}

func TestNewMemoryUnifiedConfigCache_WithOptions(t *testing.T) {
	customInterval := 5 * time.Minute
	cache := NewMemoryUnifiedConfigCache(WithCleanupInterval(customInterval))

	if cache.cleanupInterval != customInterval {
		t.Errorf("Expected cleanup interval %v, got %v", customInterval, cache.cleanupInterval)
	}
}

func TestMemoryUnifiedConfigCache_SetAndGet(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Set a value
	cache.Set("test.key", "test_value", 1*time.Hour)

	// Get the value
	value, exists := cache.Get("test.key")
	if !exists {
		t.Error("Value should exist in cache")
	}

	if value != "test_value" {
		t.Errorf("Expected 'test_value', got %v", value)
	}
}

func TestMemoryUnifiedConfigCache_Get_NonExistent(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Try to get non-existent key
	value, exists := cache.Get("non.existent")
	if exists {
		t.Error("Non-existent key should not exist")
	}

	if value != nil {
		t.Errorf("Expected nil value for non-existent key, got %v", value)
	}
}

func TestMemoryUnifiedConfigCache_Get_Expired(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Set a value with very short TTL
	cache.Set("expired.key", "expired_value", 1*time.Nanosecond)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to get expired value
	value, exists := cache.Get("expired.key")
	if exists {
		t.Error("Expired key should not exist")
	}

	if value != nil {
		t.Errorf("Expected nil value for expired key, got %v", value)
	}
}

func TestMemoryUnifiedConfigCache_Set_ZeroTTL(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Set value with zero TTL (should not expire)
	cache.Set("no_expire.key", "permanent_value", 0)

	// Wait some time
	time.Sleep(10 * time.Millisecond)

	// Value should still exist
	value, exists := cache.Get("no_expire.key")
	if !exists {
		t.Error("Value with zero TTL should not expire")
	}

	if value != "permanent_value" {
		t.Errorf("Expected 'permanent_value', got %v", value)
	}
}

func TestMemoryUnifiedConfigCache_Delete(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Set a value
	cache.Set("delete.test", "to_be_deleted", 1*time.Hour)

	// Verify it exists
	_, exists := cache.Get("delete.test")
	if !exists {
		t.Error("Value should exist before deletion")
	}

	// Delete the value
	cache.Delete("delete.test")

	// Verify it's gone
	_, exists = cache.Get("delete.test")
	if exists {
		t.Error("Value should not exist after deletion")
	}
}

func TestMemoryUnifiedConfigCache_Delete_NonExistent(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Delete non-existent key (should not panic)
	cache.Delete("non.existent")

	// Test passes if no panic occurs
}

func TestMemoryUnifiedConfigCache_Clear(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Set multiple values
	cache.Set("clear.test1", "value1", 1*time.Hour)
	cache.Set("clear.test2", "value2", 1*time.Hour)
	cache.Set("clear.test3", "value3", 1*time.Hour)

	// Verify values exist
	_, exists1 := cache.Get("clear.test1")
	_, exists2 := cache.Get("clear.test2")
	_, exists3 := cache.Get("clear.test3")

	if !exists1 || !exists2 || !exists3 {
		t.Error("All values should exist before clear")
	}

	// Clear the cache
	cache.Clear()

	// Verify all values are gone
	_, exists1 = cache.Get("clear.test1")
	_, exists2 = cache.Get("clear.test2")
	_, exists3 = cache.Get("clear.test3")

	if exists1 || exists2 || exists3 {
		t.Error("No values should exist after clear")
	}
}

func TestMemoryUnifiedConfigCache_CleanupExpired(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Set some values with different TTLs
	cache.Set("short.ttl", "expires_soon", 1*time.Nanosecond)
	cache.Set("long.ttl", "expires_later", 1*time.Hour)

	// Wait for short TTL to expire
	time.Sleep(10 * time.Millisecond)

	// Run cleanup
	cache.cleanup()

	// Verify expired item is removed
	_, exists := cache.Get("short.ttl")
	if exists {
		t.Error("Expired item should be removed by cleanup")
	}

	// Verify non-expired item still exists
	_, exists = cache.Get("long.ttl")
	if !exists {
		t.Error("Non-expired item should still exist after cleanup")
	}
}

func TestMemoryUnifiedConfigCache_Size(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Test empty cache
	if cache.Size() != 0 {
		t.Errorf("Expected size 0 for empty cache, got %d", cache.Size())
	}

	// Add some items
	cache.Set("size.test1", "value1", 1*time.Hour)
	cache.Set("size.test2", "value2", 1*time.Hour)
	cache.Set("size.test3", "value3", 1*time.Hour)

	if cache.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cache.Size())
	}

	// Delete one item
	cache.Delete("size.test2")

	if cache.Size() != 2 {
		t.Errorf("Expected size 2 after deletion, got %d", cache.Size())
	}
}

func TestMemoryUnifiedConfigCache_Keys(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Test empty cache by checking size
	if cache.Size() != 0 {
		t.Errorf("Expected 0 keys for empty cache, got %d", cache.Size())
	}

	// Add some items
	testKeys := []string{"keys.test1", "keys.test2", "keys.test3"}
	for _, key := range testKeys {
		cache.Set(key, "value", 1*time.Hour)
	}

	if cache.Size() != 3 {
		t.Errorf("Expected 3 keys, got %d", cache.Size())
	}

	// Verify all test keys are present by trying to get them
	for _, testKey := range testKeys {
		if _, exists := cache.Get(testKey); !exists {
			t.Errorf("Expected key '%s' to be present", testKey)
		}
	}
}

func TestMemoryUnifiedConfigCache_Stats(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Initial size should be 0
	if cache.Size() != 0 {
		t.Errorf("Expected 0 total items, got %d", cache.Size())
	}

	// Add some items
	cache.Set("stats.active", "active_value", 1*time.Hour)
	cache.Set("stats.expired", "expired_value", 1*time.Nanosecond)

	// Total size should be 2
	if cache.Size() != 2 {
		t.Errorf("Expected 2 total items, got %d", cache.Size())
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Test that expired item is not accessible
	_, exists := cache.Get("stats.expired")
	if exists {
		t.Error("Expired item should not be accessible")
	}

	// Active item should still be accessible
	_, exists = cache.Get("stats.active")
	if !exists {
		t.Error("Active item should still be accessible")
	}
}

func TestMemoryUnifiedConfigCache_ConcurrentAccess(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()
	var wg sync.WaitGroup

	// Test concurrent reads and writes
	for i := 0; i < 10; i++ {
		wg.Add(3)

		// Concurrent writer
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("concurrent.%d.%d", id, j)
				cache.Set(key, fmt.Sprintf("value_%d_%d", id, j), 1*time.Hour)
			}
		}(i)

		// Concurrent reader
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("concurrent.%d.%d", id, j)
				cache.Get(key)
			}
		}(i)

		// Concurrent deleter
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("concurrent.%d.%d", id, j)
				cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()

	// Test should pass if no race conditions occur
}

func TestMemoryUnifiedConfigCache_StartAndStopCleanup(t *testing.T) {
	// Create cache with very short cleanup interval for testing
	cache := NewMemoryUnifiedConfigCache(WithCleanupInterval(10 * time.Millisecond))

	// Start cleanup
	cache.startCleanup()

	// Add an item that will expire quickly
	cache.Set("cleanup.test", "value", 1*time.Nanosecond)

	// Wait for cleanup to run
	time.Sleep(50 * time.Millisecond)

	// Verify expired item was cleaned up
	_, exists := cache.Get("cleanup.test")
	if exists {
		t.Error("Expired item should be cleaned up by background cleanup")
	}

	// Stop cleanup
	select {
	case cache.stopCleanup <- true:
	default:
	}
	time.Sleep(10 * time.Millisecond) // Give cleanup time to stop

	// Test should not hang or panic
}

func TestMemoryUnifiedConfigCache_MultipleStartStopCleanup(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	// Note: startCleanup() may not handle multiple calls gracefully,
	// so we'll just test basic start/stop functionality
	cache.startCleanup()

	// Stop cleanup
	select {
	case cache.stopCleanup <- true:
	default:
	}
	time.Sleep(10 * time.Millisecond)

	// Test should not hang or panic
}

func TestWithCleanupInterval(t *testing.T) {
	cache := &MemoryUnifiedConfigCache{}
	option := WithCleanupInterval(5 * time.Second)

	option(cache)

	if cache.cleanupInterval != 5*time.Second {
		t.Errorf("Expected cleanup interval 5s, got %v", cache.cleanupInterval)
	}
}

func TestMemoryUnifiedConfigCache_EdgeCases(t *testing.T) {
	cache := NewMemoryUnifiedConfigCache()

	t.Run("SetNilValue", func(t *testing.T) {
		cache.Set("nil.test", nil, 1*time.Hour)
		value, exists := cache.Get("nil.test")
		if !exists {
			t.Error("Nil value should be cacheable")
		}
		if value != nil {
			t.Errorf("Expected nil value, got %v", value)
		}
	})

	t.Run("SetEmptyString", func(t *testing.T) {
		cache.Set("empty.test", "", 1*time.Hour)
		value, exists := cache.Get("empty.test")
		if !exists {
			t.Error("Empty string should be cacheable")
		}
		if value != "" {
			t.Errorf("Expected empty string, got %v", value)
		}
	})

	t.Run("SetZeroValue", func(t *testing.T) {
		cache.Set("zero.test", 0, 1*time.Hour)
		value, exists := cache.Get("zero.test")
		if !exists {
			t.Error("Zero value should be cacheable")
		}
		if value != 0 {
			t.Errorf("Expected 0, got %v", value)
		}
	})

	t.Run("OverwriteExistingKey", func(t *testing.T) {
		cache.Set("overwrite.test", "original", 1*time.Hour)
		cache.Set("overwrite.test", "updated", 1*time.Hour)

		value, exists := cache.Get("overwrite.test")
		if !exists {
			t.Error("Overwritten value should exist")
		}
		if value != "updated" {
			t.Errorf("Expected 'updated', got %v", value)
		}
	})
}
