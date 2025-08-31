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
	"testing"
	"time"
)

// TestCacheKeyOptimizerBasicFunctionality tests basic cache key optimization
func TestCacheKeyOptimizerBasicFunctionality(t *testing.T) {
	optimizer := NewCacheKeyOptimizer(true)
	defer optimizer.Close()

	// Test role scope key generation
	req := &KeyGenerationRequest{
		Type:      RoleScopeKeyType,
		RoleCodes: []string{"admin", "user"},
	}

	key1 := optimizer.GenerateOptimizedKey(req)
	if key1 == "" {
		t.Fatal("Generated key should not be empty")
	}

	// Generate the same key again to test caching
	key2 := optimizer.GenerateOptimizedKey(req)
	if key1 != key2 {
		t.Fatal("Same request should generate same key")
	}

	// Test tenant role scope key generation
	tenantReq := &KeyGenerationRequest{
		Type:      TenantRoleScopeKeyType,
		TenantID:  12345,
		RoleCodes: []string{"admin", "user"},
	}

	tenantKey := optimizer.GenerateOptimizedKey(tenantReq)
	if tenantKey == "" {
		t.Fatal("Generated tenant key should not be empty")
	}

	if tenantKey == key1 {
		t.Fatal("Tenant key should be different from non-tenant key")
	}

	// Test metrics
	metrics := optimizer.GetMetrics()
	if metrics.totalKeys == 0 {
		t.Fatal("Total keys should be greater than 0")
	}

	if metrics.cachedKeys == 0 {
		t.Fatal("Should have cached keys")
	}

	// Test cache stats
	cacheStats := optimizer.GetCacheStats()
	if cacheStats["cache_hits"] == nil {
		t.Fatal("Cache stats should include hits")
	}

	t.Logf("Cache key optimization test completed successfully")
	t.Logf("Total keys: %d, Cached keys: %d", metrics.totalKeys, metrics.cachedKeys)
}

// TestCacheKeyOptimizerPerformance tests performance characteristics
func TestCacheKeyOptimizerPerformance(t *testing.T) {
	optimizer := NewCacheKeyOptimizer(true)
	defer optimizer.Close()

	start := time.Now()
	iterations := 1000

	// Generate many keys to test performance
	for i := 0; i < iterations; i++ {
		req := &KeyGenerationRequest{
			Type:      TenantRoleScopeKeyType,
			TenantID:  uint64(i % 10), // Limit tenant IDs to create some duplication
			RoleCodes: []string{"admin", "user", "moderator"},
		}
		key := optimizer.GenerateOptimizedKey(req)
		if key == "" {
			t.Fatalf("Generated key should not be empty at iteration %d", i)
		}
	}

	duration := time.Since(start)
	t.Logf("Generated %d keys in %v (%.2f keys/ms)",
		iterations, duration, float64(iterations)/float64(duration.Milliseconds()))

	// Check that we have reasonable cache hit rate
	metrics := optimizer.GetMetrics()
	if metrics.totalKeys != int64(iterations) {
		t.Fatalf("Expected %d total keys, got %d", iterations, metrics.totalKeys)
	}

	// Should have some cache hits due to limited tenant IDs
	if metrics.cachedKeys == 0 {
		t.Fatal("Should have some cached keys with repeated requests")
	}

	hitRate := float64(metrics.cachedKeys) / float64(metrics.totalKeys)
	t.Logf("Cache hit rate: %.2f%%", hitRate*100)
}

// TestCacheKeyOptimizerDisabled tests fallback behavior when disabled
func TestCacheKeyOptimizerDisabled(t *testing.T) {
	optimizer := NewCacheKeyOptimizer(false)
	defer optimizer.Close()

	req := &KeyGenerationRequest{
		Type:      RoleScopeKeyType,
		RoleCodes: []string{"admin", "user"},
	}

	key := optimizer.GenerateOptimizedKey(req)
	if key == "" {
		t.Fatal("Generated key should not be empty even when disabled")
	}

	// Metrics should show no optimization when disabled
	metrics := optimizer.GetMetrics()
	if metrics.cachedKeys != 0 || metrics.internedKeys != 0 {
		t.Fatal("Should have no cached or interned keys when disabled")
	}

	t.Logf("Disabled optimizer test completed: %s", key)
}
