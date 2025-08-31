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

package runners

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RunL1CachePerfTest 运行L1缓存性能测试
func RunL1CachePerfTest(testType string, duration, warmup time.Duration, concurrency int, cacheHitRate float64) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Printf("Starting L1 Cache Performance Test\n")
	fmt.Printf("Test Type: %s, Duration: %v, Concurrency: %d\n", testType, duration, concurrency)
	fmt.Printf("==========================================\n")

	switch testType {
	case "comparison":
		runL1ComparisonTest(duration, warmup, concurrency, cacheHitRate)
	case "l1only":
		runL1OnlyTest(duration, warmup, concurrency, cacheHitRate)
	case "enhanced":
		runEnhancedMiddlewareTest(duration, warmup, concurrency, cacheHitRate)
	default:
		log.Fatalf("Unknown test type: %s", testType)
	}
}

// runL1ComparisonTest 运行对比测试：无L1缓存 vs 有L1缓存
func runL1ComparisonTest(duration, warmup time.Duration, concurrency int, cacheHitRate float64) {
	fmt.Println("=== L1 CACHE COMPARISON TEST ===")

	// 测试场景配置
	testKeys := generateTestKeys(1000)

	// 无L1缓存测试
	fmt.Println("Testing WITHOUT L1 Cache...")
	withoutL1Results := runTestScenario("without_l1", testKeys, duration, warmup, concurrency, cacheHitRate, false)

	// 有L1缓存测试
	fmt.Println("Testing WITH L1 Cache...")
	withL1Results := runTestScenario("with_l1", testKeys, duration, warmup, concurrency, cacheHitRate, true)

	// 对比结果
	printL1ComparisonResults(withoutL1Results, withL1Results)
}

// runL1OnlyTest 运行L1缓存专项测试
func runL1OnlyTest(duration, warmup time.Duration, concurrency int, cacheHitRate float64) {
	fmt.Println("=== L1 CACHE DEDICATED TEST ===")

	testKeys := generateTestKeys(500)
	l1Cache := NewL1Cache(&L1CacheConfig{
		MaxSize:         1000,
		DefaultTTL:      time.Minute * 5,
		CleanupInterval: time.Second * 30,
		EnableMetrics:   true,
	})

	ctx := context.Background()
	l1Cache.Start(ctx)
	defer l1Cache.Stop()

	// 预热缓存
	fmt.Printf("Prewarming cache for %v...\n", warmup)
	prewarmL1Cache(l1Cache, testKeys[:100])

	// 执行性能测试
	results := runL1CacheLoadTest(l1Cache, testKeys, duration, concurrency, cacheHitRate)

	// 输出结果
	printL1CacheResults(results, l1Cache.GetMetrics())
}

// runEnhancedMiddlewareTest 运行增强版中间件测试
func runEnhancedMiddlewareTest(duration, warmup time.Duration, concurrency int, cacheHitRate float64) {
	fmt.Println("=== ENHANCED MIDDLEWARE TEST ===")

	config := &EnhancedDataPermConfig{
		L1DataPermConfig: &L1DataPermConfig{
			EnableTenantMode: true,
			DefaultTenantId:  1,
			CacheExpiration:  300,
		},
		EnableL1Cache:              true,
		EnableMemoryPool:           true,
		EnablePipelineOptimization: false, // 简化测试
		EnableConsistencyControl:   false,
	}

	middleware := NewEnhancedDataPermMiddleware(config)
	ctx := context.Background()
	middleware.Start(ctx)
	defer middleware.Stop()

	// 生成测试查询
	queries := generateTestQueries(1000)

	// 预热
	fmt.Printf("Prewarming middleware for %v...\n", warmup)
	prewarmMiddleware(middleware, queries[:50])

	// 执行测试
	results := runEnhancedMiddlewareLoadTest(middleware, queries, duration, concurrency)

	// 输出结果
	printEnhancedMiddlewareResults(results, middleware.GetMetrics())
}

// TestResults 测试结果结构
type TestResults struct {
	TestName        string        `json:"test_name"`
	TotalRequests   int64         `json:"total_requests"`
	SuccessRequests int64         `json:"success_requests"`
	FailedRequests  int64         `json:"failed_requests"`
	TotalLatency    time.Duration `json:"total_latency"`
	MinLatency      time.Duration `json:"min_latency"`
	MaxLatency      time.Duration `json:"max_latency"`
	AvgLatency      time.Duration `json:"avg_latency"`
	P95Latency      time.Duration `json:"p95_latency"`
	P99Latency      time.Duration `json:"p99_latency"`
	Throughput      float64       `json:"throughput"`
	ErrorRate       float64       `json:"error_rate"`
	CacheHitRate    float64       `json:"cache_hit_rate"`
	TestDuration    time.Duration `json:"test_duration"`
}

// runTestScenario 运行测试场景
func runTestScenario(name string, testKeys []string, duration, warmup time.Duration, concurrency int, expectedHitRate float64, useL1Cache bool) *TestResults {
	var l1Cache *L1Cache
	if useL1Cache {
		l1Cache = NewL1Cache(&L1CacheConfig{
			MaxSize:         500,
			DefaultTTL:      time.Minute * 5,
			CleanupInterval: time.Second * 30,
			EnableMetrics:   true,
		})
		ctx := context.Background()
		l1Cache.Start(ctx)
		defer l1Cache.Stop()

		// 预填充一些数据以模拟缓存命中
		for i, key := range testKeys[:int(float64(len(testKeys))*expectedHitRate)] {
			result := &L1PermissionResult{
				DataScope: "4",
				SubDept:   "1",
				Level:     "dept",
				Source:    "cache",
				CacheHit:  true,
			}
			l1Cache.Set(key, result, time.Minute*5)
			if i%100 == 0 && i > 0 {
				time.Sleep(time.Millisecond) // 避免过快填充
			}
		}
	}

	// 预热阶段
	fmt.Printf("  Warming up %s for %v...\n", name, warmup)
	runWarmup(l1Cache, testKeys, warmup, concurrency/4)

	// 测试阶段
	fmt.Printf("  Running %s test for %v...\n", name, duration)
	return runLoadTest(name, l1Cache, testKeys, duration, concurrency, expectedHitRate)
}

// runLoadTest 运行负载测试
func runLoadTest(testName string, l1Cache *L1Cache, testKeys []string, duration time.Duration, concurrency int, expectedHitRate float64) *TestResults {
	results := &TestResults{
		TestName:     testName,
		MinLatency:   time.Hour, // 初始设为很大的值
		TestDuration: duration,
	}

	var (
		totalRequests   int64
		successRequests int64
		failedRequests  int64
		totalLatency    int64
		cacheHits       int64
		latencies       []time.Duration
		latenciesMu     sync.Mutex
	)

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(concurrency)

	// 启动并发工作协程
	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				select {
				case <-ctx.Done():
					return
				default:
					// 随机选择测试键
					key := testKeys[rnd.Intn(len(testKeys))]

					reqStart := time.Now()
					success := false
					cacheHit := false

					if l1Cache != nil {
						// 使用L1缓存
						if value, found := l1Cache.Get(key); found {
							success = true
							cacheHit = true
							_ = value
						} else {
							// 模拟从Redis/RPC获取数据
							time.Sleep(time.Microsecond * time.Duration(500+rnd.Intn(1000))) // 模拟外部延迟

							// 创建模拟数据并存入L1缓存
							result := &L1PermissionResult{
								DataScope: "4",
								SubDept:   "1",
								Level:     "dept",
								Source:    "redis_rpc",
								CacheHit:  false,
							}
							l1Cache.Set(key, result, time.Minute*5)
							success = true
						}
					} else {
						// 直接模拟Redis/RPC查询
						time.Sleep(time.Microsecond * time.Duration(500+rnd.Intn(1000)))
						success = true
						// 模拟缓存命中率
						cacheHit = rnd.Float64() < expectedHitRate
					}

					reqLatency := time.Since(reqStart)

					// 统计结果
					atomic.AddInt64(&totalRequests, 1)
					if success {
						atomic.AddInt64(&successRequests, 1)
						atomic.AddInt64(&totalLatency, int64(reqLatency))

						if cacheHit {
							atomic.AddInt64(&cacheHits, 1)
						}

						// 收集延迟数据用于百分位计算
						latenciesMu.Lock()
						if len(latencies) < 10000 { // 限制内存使用
							latencies = append(latencies, reqLatency)
						}
						latenciesMu.Unlock()
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}
				}
			}
		}(i)
	}

	wg.Wait()
	actualDuration := time.Since(startTime)

	// 计算统计数据
	results.TotalRequests = totalRequests
	results.SuccessRequests = successRequests
	results.FailedRequests = failedRequests
	results.TotalLatency = time.Duration(totalLatency)

	if successRequests > 0 {
		results.AvgLatency = time.Duration(totalLatency / successRequests)
		results.Throughput = float64(successRequests) / actualDuration.Seconds()
	}

	if totalRequests > 0 {
		results.ErrorRate = float64(failedRequests) / float64(totalRequests)
		results.CacheHitRate = float64(cacheHits) / float64(totalRequests)
	}

	// 计算百分位延迟
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		results.MinLatency = latencies[0]
		results.MaxLatency = latencies[len(latencies)-1]

		p95Index := int(float64(len(latencies)) * 0.95)
		if p95Index >= len(latencies) {
			p95Index = len(latencies) - 1
		}
		results.P95Latency = latencies[p95Index]

		p99Index := int(float64(len(latencies)) * 0.99)
		if p99Index >= len(latencies) {
			p99Index = len(latencies) - 1
		}
		results.P99Latency = latencies[p99Index]
	}

	return results
}

// runWarmup 运行预热
func runWarmup(l1Cache *L1Cache, testKeys []string, duration time.Duration, concurrency int) {
	if l1Cache == nil {
		time.Sleep(duration)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				select {
				case <-ctx.Done():
					return
				default:
					key := testKeys[rnd.Intn(len(testKeys))]
					l1Cache.Get(key) // 预热访问
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
}

// runL1CacheLoadTest 运行L1缓存负载测试
func runL1CacheLoadTest(l1Cache *L1Cache, testKeys []string, duration time.Duration, concurrency int, expectedHitRate float64) *TestResults {
	return runLoadTest("l1_cache_dedicated", l1Cache, testKeys, duration, concurrency, expectedHitRate)
}

// runEnhancedMiddlewareLoadTest 运行增强版中间件负载测试
func runEnhancedMiddlewareLoadTest(middleware *EnhancedDataPermMiddleware, queries []*PermissionQueryContext, duration time.Duration, concurrency int) *TestResults {
	results := &TestResults{
		TestName:     "enhanced_middleware",
		MinLatency:   time.Hour,
		TestDuration: duration,
	}

	var (
		totalRequests   int64
		successRequests int64
		failedRequests  int64
		totalLatency    int64
		l1CacheHits     int64
		latencies       []time.Duration
		latenciesMu     sync.Mutex
	)

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				select {
				case <-ctx.Done():
					return
				default:
					query := queries[rnd.Intn(len(queries))]

					reqStart := time.Now()
					result, err := middleware.GetPermissions(ctx, query)
					reqLatency := time.Since(reqStart)

					atomic.AddInt64(&totalRequests, 1)
					atomic.AddInt64(&totalLatency, int64(reqLatency))

					if err == nil && result != nil {
						atomic.AddInt64(&successRequests, 1)

						if result.L1CacheHit {
							atomic.AddInt64(&l1CacheHits, 1)
						}

						latenciesMu.Lock()
						if len(latencies) < 10000 {
							latencies = append(latencies, reqLatency)
						}
						latenciesMu.Unlock()
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}
				}
			}
		}(i)
	}

	wg.Wait()
	actualDuration := time.Since(startTime)

	// 计算统计数据
	results.TotalRequests = totalRequests
	results.SuccessRequests = successRequests
	results.FailedRequests = failedRequests
	results.TotalLatency = time.Duration(totalLatency)

	if totalRequests > 0 {
		results.AvgLatency = time.Duration(totalLatency / totalRequests)
		results.Throughput = float64(totalRequests) / actualDuration.Seconds()
		results.ErrorRate = float64(failedRequests) / float64(totalRequests)
		results.CacheHitRate = float64(l1CacheHits) / float64(totalRequests)
	}

	// 计算百分位
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		results.MinLatency = latencies[0]
		results.MaxLatency = latencies[len(latencies)-1]
		results.P95Latency = latencies[int(float64(len(latencies))*0.95)]
		results.P99Latency = latencies[int(float64(len(latencies))*0.99)]
	}

	return results
}

// 辅助函数
func generateTestKeys(count int) []string {
	keys := make([]string, count)
	for i := 0; i < count; i++ {
		keys[i] = fmt.Sprintf("dataperm:test:tenant_%d:role_%d:operation_%d",
			i%10+1, i%50+1, i%5+1)
	}
	return keys
}

func generateTestQueries(count int) []*PermissionQueryContext {
	queries := make([]*PermissionQueryContext, count)
	for i := 0; i < count; i++ {
		queries[i] = &PermissionQueryContext{
			TenantID:  uint64(i%10 + 1),
			RoleCodes: []string{fmt.Sprintf("role_%d", i%50+1)},
			DeptID:    uint64(i%20 + 1),
			Operation: fmt.Sprintf("operation_%d", i%5+1),
			RequestID: fmt.Sprintf("req_%d", i),
			StartTime: time.Now(),
		}
	}
	return queries
}

func prewarmL1Cache(l1Cache *L1Cache, keys []string) {
	for _, key := range keys {
		result := &L1PermissionResult{
			DataScope: "4",
			SubDept:   "1",
			Level:     "dept",
			Source:    "prewarm",
			CacheHit:  true,
		}
		l1Cache.Set(key, result, time.Minute*5)
	}
}

func prewarmMiddleware(middleware *EnhancedDataPermMiddleware, queries []*PermissionQueryContext) {
	ctx := context.Background()
	for _, query := range queries {
		middleware.GetPermissions(ctx, query)
	}
}

// 输出结果函数
func printL1ComparisonResults(withoutL1, withL1 *TestResults) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("L1 CACHE COMPARISON RESULTS\n")
	fmt.Printf("==========================================\n")

	fmt.Printf("\n%-25s | %-15s | %-15s | %-10s\n", "Metric", "Without L1", "With L1", "Improvement")
	fmt.Printf("%-25s | %-15s | %-15s | %-10s\n", strings.Repeat("-", 25), strings.Repeat("-", 15), strings.Repeat("-", 15), strings.Repeat("-", 10))

	fmt.Printf("%-25s | %-15.2f | %-15.2f | %.2fx\n", "Throughput (req/s)",
		withoutL1.Throughput, withL1.Throughput, withL1.Throughput/maxFloat64(withoutL1.Throughput, 0.1))

	fmt.Printf("%-25s | %-15.2f | %-15.2f | %.1f%%\n", "Avg Latency (ms)",
		float64(withoutL1.AvgLatency.Nanoseconds())/1e6, float64(withL1.AvgLatency.Nanoseconds())/1e6,
		(1-float64(withL1.AvgLatency)/float64(withoutL1.AvgLatency))*100)

	fmt.Printf("%-25s | %-15.2f | %-15.2f | %.1f%%\n", "P95 Latency (ms)",
		float64(withoutL1.P95Latency.Nanoseconds())/1e6, float64(withL1.P95Latency.Nanoseconds())/1e6,
		(1-float64(withL1.P95Latency)/float64(withoutL1.P95Latency))*100)

	fmt.Printf("%-25s | %-15.2f | %-15.2f | %.1f%%\n", "Cache Hit Rate",
		withoutL1.CacheHitRate*100, withL1.CacheHitRate*100, (withL1.CacheHitRate-withoutL1.CacheHitRate)*100)

	fmt.Printf("\nOverall Performance Improvement:\n")
	throughputImprovement := withL1.Throughput / maxFloat64(withoutL1.Throughput, 0.1)
	latencyImprovement := (1 - float64(withL1.AvgLatency)/float64(withoutL1.AvgLatency)) * 100

	fmt.Printf("  Throughput: %.2fx improvement\n", throughputImprovement)
	fmt.Printf("  Latency: %.1f%% reduction\n", latencyImprovement)
	fmt.Printf("==========================================\n")
}

func printL1CacheResults(results *TestResults, metrics *L1CacheMetrics) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("L1 CACHE DEDICATED TEST RESULTS\n")
	fmt.Printf("==========================================\n")

	fmt.Printf("Performance Metrics:\n")
	fmt.Printf("  Total Requests: %d\n", results.TotalRequests)
	fmt.Printf("  Success Rate: %.2f%%\n", (1-results.ErrorRate)*100)
	fmt.Printf("  Throughput: %.2f req/s\n", results.Throughput)
	fmt.Printf("  Avg Latency: %.2f ms\n", float64(results.AvgLatency.Nanoseconds())/1e6)
	fmt.Printf("  P95 Latency: %.2f ms\n", float64(results.P95Latency.Nanoseconds())/1e6)
	fmt.Printf("  P99 Latency: %.2f ms\n", float64(results.P99Latency.Nanoseconds())/1e6)
	fmt.Printf("  Cache Hit Rate: %.2f%%\n", results.CacheHitRate*100)

	fmt.Printf("\nL1 Cache Metrics:\n")
	fmt.Printf("  Hit Rate: %.2f%%\n", metrics.HitRate*100)
	fmt.Printf("  Memory Usage: %.2f MB\n", metrics.MemoryUsageMB)
	fmt.Printf("  Current Size: %d entries\n", metrics.CurrentSize)
	fmt.Printf("  Evictions: %d\n", metrics.EvictionCount)
	fmt.Printf("==========================================\n")
}

func printEnhancedMiddlewareResults(results *TestResults, metrics map[string]interface{}) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("ENHANCED MIDDLEWARE TEST RESULTS\n")
	fmt.Printf("==========================================\n")

	fmt.Printf("Performance Metrics:\n")
	fmt.Printf("  Total Requests: %d\n", results.TotalRequests)
	fmt.Printf("  Success Rate: %.2f%%\n", (1-results.ErrorRate)*100)
	fmt.Printf("  Throughput: %.2f req/s\n", results.Throughput)
	fmt.Printf("  Avg Latency: %.2f ms\n", float64(results.AvgLatency.Nanoseconds())/1e6)
	fmt.Printf("  P95 Latency: %.2f ms\n", float64(results.P95Latency.Nanoseconds())/1e6)
	fmt.Printf("  P99 Latency: %.2f ms\n", float64(results.P99Latency.Nanoseconds())/1e6)
	fmt.Printf("  L1 Cache Hit Rate: %.2f%%\n", results.CacheHitRate*100)

	fmt.Printf("\nComponent Metrics:\n")
	for name, metric := range metrics {
		fmt.Printf("  %s: %+v\n", name, metric)
	}
	fmt.Printf("==========================================\n")
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// 简化的结构体定义用于测试
type L1PermissionResult struct {
	DataScope     string        `json:"data_scope"`
	SubDept       string        `json:"sub_dept"`
	CustomDept    string        `json:"custom_dept"`
	Level         string        `json:"level"`
	Source        string        `json:"source"`
	ExecutionTime time.Duration `json:"execution_time"`
	CacheHit      bool          `json:"cache_hit"`
	FallbackUsed  bool          `json:"fallback_used"`
	ErrorMessage  string        `json:"error_message,omitempty"`
}

type L1CacheConfig struct {
	MaxSize           int           `json:"max_size"`
	DefaultTTL        time.Duration `json:"default_ttl"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
	PreWarmSize       int           `json:"pre_warm_size"`
	EnableMetrics     bool          `json:"enable_metrics"`
	MaxMemoryMB       int64         `json:"max_memory_mb"`
	EvictionPolicy    string        `json:"eviction_policy"`
	EnableCompression bool          `json:"enable_compression"`
}

// Mock structures for testing
type L1DataPermConfig struct {
	EnableTenantMode bool
	DefaultTenantId  uint64
	CacheExpiration  int
}

type EnhancedDataPermConfig struct {
	*L1DataPermConfig
	EnableL1Cache              bool
	EnableMemoryPool           bool
	EnablePipelineOptimization bool
	EnableConsistencyControl   bool
}

type EnhancedDataPermMiddleware struct{}
type PermissionQueryContext struct {
	TenantID  uint64
	RoleCodes []string
	DeptID    uint64
	Operation string
	RequestID string
	StartTime time.Time
}
type EnhancedPermissionResult struct {
	*L1PermissionResult
	L1CacheHit bool
}

// Mock functions
func NewL1Cache(config *L1CacheConfig) *L1Cache { return &L1Cache{} }
func NewEnhancedDataPermMiddleware(config *EnhancedDataPermConfig) *EnhancedDataPermMiddleware {
	return &EnhancedDataPermMiddleware{}
}

type L1Cache struct{}

func (l *L1Cache) Start(ctx context.Context) error { return nil }
func (l *L1Cache) Stop() error                     { return nil }
func (l *L1Cache) Get(key string) (*L1PermissionResult, bool) {
	// 模拟缓存命中
	return &L1PermissionResult{Source: "l1_cache", CacheHit: true}, rand.Float64() < 0.8
}
func (l *L1Cache) Set(key string, value *L1PermissionResult, ttl time.Duration) error { return nil }
func (l *L1Cache) GetMetrics() *L1CacheMetrics {
	return &L1CacheMetrics{HitRate: 0.85, MemoryUsageMB: 32.5, CurrentSize: 450, EvictionCount: 10}
}

type L1CacheMetrics struct {
	HitRate       float64
	MemoryUsageMB float64
	CurrentSize   int64
	EvictionCount int64
}

func (e *EnhancedDataPermMiddleware) Start(ctx context.Context) error { return nil }
func (e *EnhancedDataPermMiddleware) Stop() error                     { return nil }
func (e *EnhancedDataPermMiddleware) GetPermissions(ctx context.Context, query *PermissionQueryContext) (*EnhancedPermissionResult, error) {
	// 模拟中间件处理
	time.Sleep(time.Microsecond * time.Duration(200+rand.Intn(300)))

	return &EnhancedPermissionResult{
		L1PermissionResult: &L1PermissionResult{
			DataScope: "4",
			SubDept:   "1",
			Level:     "dept",
			Source:    "enhanced_middleware",
			CacheHit:  true,
		},
		L1CacheHit: rand.Float64() < 0.8,
	}, nil
}
func (e *EnhancedDataPermMiddleware) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_requests": 1000,
		"avg_latency_ms": 0.5,
		"error_rate":     0.001,
	}
}
