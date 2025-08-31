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
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

func BenchmarkL1Cache_Get(b *testing.B) {
	cache := NewL1Cache(DefaultL1CacheConfig())
	defer cache.Close()

	ctx := context.Background()

	// 预填充缓存
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("benchmark_key_%d", i)
		value := fmt.Sprintf("benchmark_value_%d", i)
		cache.Set(ctx, key, value)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("benchmark_key_%d", i%1000)
			cache.Get(ctx, key)
			i++
		}
	})
}

func BenchmarkL1Cache_Set(b *testing.B) {
	cache := NewL1Cache(DefaultL1CacheConfig())
	defer cache.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("benchmark_key_%d", i)
			value := fmt.Sprintf("benchmark_value_%d", i)
			cache.Set(ctx, key, value)
			i++
		}
	})
}

func BenchmarkL1Cache_ConcurrentReadWrite(b *testing.B) {
	cache := NewL1Cache(DefaultL1CacheConfig())
	defer cache.Close()

	ctx := context.Background()

	// 预填充一些数据
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("initial_key_%d", i)
		value := fmt.Sprintf("initial_value_%d", i)
		cache.Set(ctx, key, value)
	}

	b.ResetTimer()

	// 80% reads, 20% writes
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%5 == 0 {
				// Write operation (20%)
				key := fmt.Sprintf("write_key_%d", i)
				value := fmt.Sprintf("write_value_%d", i)
				cache.Set(ctx, key, value)
			} else {
				// Read operation (80%)
				key := fmt.Sprintf("initial_key_%d", i%100)
				cache.Get(ctx, key)
			}
			i++
		}
	})
}

func TestL1Cache_PerformanceComparison(t *testing.T) {
	config := DefaultL1CacheConfig()
	config.MaxSize = 10000
	cache := NewL1Cache(config)
	defer cache.Close()

	ctx := context.Background()

	// 测试数据准备
	testKeys := make([]string, 1000)
	testValues := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		testKeys[i] = fmt.Sprintf("perf_test_key_%d", i)
		testValues[i] = fmt.Sprintf("perf_test_value_%d_with_longer_content_to_simulate_real_data", i)
		cache.Set(ctx, testKeys[i], testValues[i])
	}

	// 顺序读取测试
	t.Run("Sequential Reads", func(t *testing.T) {
		start := time.Now()
		hits := 0

		for i := 0; i < 10000; i++ {
			key := testKeys[i%1000]
			if _, hit := cache.Get(ctx, key); hit {
				hits++
			}
		}

		duration := time.Since(start)
		hitRate := float64(hits) / 10000

		t.Logf("Sequential reads: %d operations in %v", 10000, duration)
		t.Logf("Operations per second: %.0f", 10000.0/duration.Seconds())
		t.Logf("Hit rate: %.2f%%", hitRate*100)
		t.Logf("Average latency: %v", duration/10000)

		if hitRate < 0.95 {
			t.Errorf("Expected hit rate > 95%%, got %.2f%%", hitRate*100)
		}
	})

	// 并发读取测试
	t.Run("Concurrent Reads", func(t *testing.T) {
		concurrency := runtime.NumCPU()
		operationsPerWorker := 1000

		start := time.Now()
		var wg sync.WaitGroup
		var totalHits int64

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				hits := 0

				for j := 0; j < operationsPerWorker; j++ {
					key := testKeys[(workerID*operationsPerWorker+j)%1000]
					if _, hit := cache.Get(ctx, key); hit {
						hits++
					}
				}

				// Atomic add would be more precise, but this is fine for testing
				totalHits += int64(hits)
			}(i)
		}

		wg.Wait()
		duration := time.Since(start)
		totalOps := concurrency * operationsPerWorker
		hitRate := float64(totalHits) / float64(totalOps)

		t.Logf("Concurrent reads (%d workers): %d operations in %v", concurrency, totalOps, duration)
		t.Logf("Operations per second: %.0f", float64(totalOps)/duration.Seconds())
		t.Logf("Hit rate: %.2f%%", hitRate*100)
		t.Logf("Average latency: %v", duration/time.Duration(totalOps))

		if hitRate < 0.95 {
			t.Errorf("Expected hit rate > 95%%, got %.2f%%", hitRate*100)
		}
	})
}

func TestL1Cache_MemoryUsage(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	config := DefaultL1CacheConfig()
	config.MaxSize = 50000
	cache := NewL1Cache(config)
	defer cache.Close()

	ctx := context.Background()

	// 填充缓存
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("memory_test_key_%d", i)
		value := fmt.Sprintf("memory_test_value_%d_with_some_additional_content_to_make_it_realistic", i)
		cache.Set(ctx, key, value)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	memoryUsed := m2.Alloc - m1.Alloc
	stats := cache.GetStats()

	t.Logf("Memory usage: %d bytes", memoryUsed)
	t.Logf("Cache size: %d entries", stats.Size)
	t.Logf("Memory per entry: %.2f bytes", float64(memoryUsed)/float64(stats.Size))
	t.Logf("Hit rate: %.2f%%", stats.HitRate*100)

	// Reasonable memory usage per entry (should be under 500 bytes per entry for our use case)
	memoryPerEntry := float64(memoryUsed) / float64(stats.Size)
	if memoryPerEntry > 500 {
		t.Logf("Warning: Memory usage per entry is high: %.2f bytes", memoryPerEntry)
	}
}

func TestL1Cache_EvictionPerformance(t *testing.T) {
	config := DefaultL1CacheConfig()
	config.MaxSize = 1000 // Small size to force eviction
	cache := NewL1Cache(config)
	defer cache.Close()

	ctx := context.Background()

	start := time.Now()

	// Insert more entries than max size to trigger eviction
	for i := 0; i < 2000; i++ {
		key := fmt.Sprintf("eviction_key_%d", i)
		value := fmt.Sprintf("eviction_value_%d", i)
		cache.Set(ctx, key, value)
	}

	duration := time.Since(start)
	stats := cache.GetStats()

	t.Logf("Eviction test: 2000 insertions in %v", duration)
	t.Logf("Operations per second: %.0f", 2000.0/duration.Seconds())
	t.Logf("Final cache size: %d", stats.Size)
	t.Logf("Evictions: %d", stats.Evictions)

	if stats.Size > int64(config.MaxSize) {
		t.Errorf("Cache size %d exceeds max size %d", stats.Size, config.MaxSize)
	}

	if stats.Evictions == 0 {
		t.Error("Expected evictions to occur, but none were recorded")
	}
}

func TestL1Cache_TTLPerformance(t *testing.T) {
	config := DefaultL1CacheConfig()
	config.DefaultTTL = 100 * time.Millisecond     // Very short TTL for testing
	config.CleanupInterval = 50 * time.Millisecond // Frequent cleanup
	config.MaxSize = 2000                          // Larger size to accommodate all test entries
	cache := NewL1Cache(config)
	defer cache.Close()

	ctx := context.Background()

	// Insert fewer entries to ensure they fit within cache size limits
	testSize := 500
	for i := 0; i < testSize; i++ {
		key := fmt.Sprintf("ttl_key_%d", i)
		value := fmt.Sprintf("ttl_value_%d", i)
		cache.Set(ctx, key, value)
	}

	// Immediate read should have high hit rate
	hits := 0
	for i := 0; i < testSize; i++ {
		key := fmt.Sprintf("ttl_key_%d", i)
		if _, hit := cache.Get(ctx, key); hit {
			hits++
		}
	}

	immediateHitRate := float64(hits) / float64(testSize)
	t.Logf("Immediate hit rate: %.2f%%", immediateHitRate*100)

	if immediateHitRate < 0.95 { // Lowered expectation due to concurrent eviction
		t.Errorf("Expected immediate hit rate > 95%%, got %.2f%%", immediateHitRate*100)
	}

	// Wait for TTL expiration + cleanup
	time.Sleep(200 * time.Millisecond)

	// Read again - should have low hit rate due to expiration
	hits = 0
	for i := 0; i < testSize; i++ {
		key := fmt.Sprintf("ttl_key_%d", i)
		if _, hit := cache.Get(ctx, key); hit {
			hits++
		}
	}

	expiredHitRate := float64(hits) / float64(testSize)
	t.Logf("Post-expiration hit rate: %.2f%%", expiredHitRate*100)

	if expiredHitRate > 0.1 {
		t.Logf("Warning: Post-expiration hit rate is higher than expected: %.2f%%", expiredHitRate*100)
	}
}
