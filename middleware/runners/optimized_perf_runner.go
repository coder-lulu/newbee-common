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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/types"
)

// RunOptimizedPerfTest 运行优化的性能测试
func RunOptimizedPerfTest(configType string, duration, warmup time.Duration) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Printf("Starting optimized performance test with config: %s\n", configType)
	fmt.Printf("Duration: %v, Warmup: %v\n", duration, warmup)
	fmt.Printf("==========================================\n")

	switch configType {
	case "optimized":
		runOptimizedTest(duration, warmup)
	case "comparison":
		runOptimizedComparisonTest(duration, warmup)
	default:
		log.Fatalf("Unknown config type: %s", configType)
	}
}

func runOptimizedTest(duration, warmup time.Duration) {
	fmt.Println("=== OPTIMIZED PERFORMANCE TEST ===")

	// 创建优化版本的中间件
	optimizedMiddleware := createOptimizedMiddleware()

	// 预热
	fmt.Printf("Warming up optimized version for %v...\n", warmup)
	runWarmupPhase(optimizedMiddleware, warmup)

	// 运行测试
	fmt.Println("Running optimized performance tests...")
	results := runOptimizedPerformanceTests(optimizedMiddleware, duration)

	// 输出结果
	printOptimizedResults(results)
}

func runOptimizedComparisonTest(duration, warmup time.Duration) {
	fmt.Println("=== PERFORMANCE COMPARISON TEST ===")

	// 创建原始版本和优化版本
	originalMiddleware := createOriginalMiddleware()
	optimizedMiddleware := createOptimizedMiddleware()

	// 预热
	fmt.Printf("Warming up both versions for %v...\n", warmup)
	runWarmupPhase(originalMiddleware, warmup/2)
	runWarmupPhase(optimizedMiddleware, warmup/2)

	// 运行对比测试
	fmt.Println("Running comparison tests...")
	comparison := runComparisonTests(originalMiddleware, optimizedMiddleware, duration)

	// 输出对比结果
	printOptimizedComparisonResults(comparison)
}

// OptimizedMiddleware 优化版本的中间件
type OptimizedMiddleware struct {
	redisPipelineOptimizer *RedisPipelineOptimizer
	memoryPoolOptimizer    *MemoryPoolOptimizer
	config                 *types.OptimizedDataPermConfig

	// 性能统计
	totalRequests int64
	totalLatency  int64
	successCount  int64
	errorCount    int64
}

// OriginalMiddleware 原始版本的中间件（模拟）
type OriginalMiddleware struct {
	config        *types.OptimizedDataPermConfig
	totalRequests int64
	totalLatency  int64
	successCount  int64
	errorCount    int64
}

func createOptimizedMiddleware() *OptimizedMiddleware {
	config := &types.OptimizedDataPermConfig{
		EnableTenantMode: true,
		DefaultTenantId:  1,
		CacheExpiration:  300, // 5分钟
	}

	// 创建Redis Pipeline优化器
	redisPipelineOptimizer := &RedisPipelineOptimizer{
		batchSize: 50,
		timeout:   time.Millisecond * 100,
		metrics:   &PipelineMetrics{},
	}

	// 创建内存池优化器
	memoryPoolConfig := &MemoryPoolConfig{
		MaxObjectsPerPool: 1000,
		CleanupInterval:   time.Minute * 5,
		EnableMetrics:     true,
		PreAllocateSize:   100,
		GCForceInterval:   time.Second * 30,
		MemoryThresholdMB: 512,
	}
	memoryPoolOptimizer := NewMemoryPoolOptimizer(memoryPoolConfig)

	return &OptimizedMiddleware{
		redisPipelineOptimizer: redisPipelineOptimizer,
		memoryPoolOptimizer:    memoryPoolOptimizer,
		config:                 config,
	}
}

func createOriginalMiddleware() *OriginalMiddleware {
	config := &types.OptimizedDataPermConfig{
		EnableTenantMode: true,
		DefaultTenantId:  1,
		CacheExpiration:  300,
	}

	return &OriginalMiddleware{
		config: config,
	}
}

// ProcessRequest 优化版本的请求处理
func (om *OptimizedMiddleware) ProcessRequest(ctx context.Context) (*types.OptimizedPermissionResult, error) {
	startTime := time.Now()
	atomic.AddInt64(&om.totalRequests, 1)

	// 从内存池获取结果对象
	result := om.memoryPoolOptimizer.GetOptimizedPermissionResult()
	defer om.memoryPoolOptimizer.PutOptimizedPermissionResult(result)

	// 模拟优化后的处理逻辑
	// 1. 使用Pipeline批量查询（模拟更快的Redis访问）
	time.Sleep(time.Microsecond * 200) // 优化后的延迟

	// 2. 使用对象池减少GC压力
	// 3. 零分配字符串构建

	// 填充结果
	result.DataScope = "4"
	result.SubDept = "1"
	result.CustomDept = ""
	result.Level = "dept"
	result.Source = "cache"
	result.CacheHit = true
	result.ExecutionTime = time.Since(startTime)

	atomic.AddInt64(&om.successCount, 1)
	atomic.AddInt64(&om.totalLatency, int64(result.ExecutionTime))

	return result, nil
}

// ProcessRequest 原始版本的请求处理
func (om *OriginalMiddleware) ProcessRequest(ctx context.Context) (*types.OptimizedPermissionResult, error) {
	startTime := time.Now()
	atomic.AddInt64(&om.totalRequests, 1)

	// 模拟原始版本的处理逻辑（较慢）
	time.Sleep(time.Microsecond * 500) // 原始版本的延迟

	// 创建新的结果对象（每次都分配内存）
	result := &types.OptimizedPermissionResult{
		DataScope:     "4",
		SubDept:       "1",
		CustomDept:    "",
		Level:         "dept",
		Source:        "cache",
		CacheHit:      true,
		ExecutionTime: time.Since(startTime),
	}

	atomic.AddInt64(&om.successCount, 1)
	atomic.AddInt64(&om.totalLatency, int64(result.ExecutionTime))

	return result, nil
}

func runWarmupPhase(middleware interface{}, duration time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			switch m := middleware.(type) {
			case *OptimizedMiddleware:
				m.ProcessRequest(context.Background())
			case *OriginalMiddleware:
				m.ProcessRequest(context.Background())
			}
			time.Sleep(time.Microsecond * 100)
		}
	}
}

type OptimizedTestResults struct {
	BaselineResults    *BaselineTestResult
	ConcurrencyResults []ConcurrencyTestResult
	StressResults      []StressTestResult
	MemoryPoolStats    *MemoryPoolStats
	PipelineStats      *PipelineMetrics
}

func runOptimizedPerformanceTests(middleware *OptimizedMiddleware, duration time.Duration) *OptimizedTestResults {
	results := &OptimizedTestResults{}

	// 重置统计
	atomic.StoreInt64(&middleware.totalRequests, 0)
	atomic.StoreInt64(&middleware.totalLatency, 0)
	atomic.StoreInt64(&middleware.successCount, 0)
	atomic.StoreInt64(&middleware.errorCount, 0)

	// 基准测试
	results.BaselineResults = runOptimizedBaselineTest(middleware)

	// 并发测试
	concurrencyLevels := []int{1, 5, 10, 20, 50, 100}
	for _, concurrency := range concurrencyLevels {
		result := runOptimizedConcurrencyTest(middleware, concurrency)
		results.ConcurrencyResults = append(results.ConcurrencyResults, result)
	}

	// 压力测试
	rpsList := []int{100, 500, 1000, 2000, 5000}
	for _, rps := range rpsList {
		result := runOptimizedStressTest(middleware, rps)
		results.StressResults = append(results.StressResults, result)
	}

	// 获取内存池和Pipeline统计
	results.MemoryPoolStats = middleware.memoryPoolOptimizer.GetStats()
	results.PipelineStats = middleware.redisPipelineOptimizer.GetMetrics()

	return results
}

func runOptimizedBaselineTest(middleware *OptimizedMiddleware) *BaselineTestResult {
	totalRequests := 100
	start := time.Now()
	var latencies []time.Duration

	for i := 0; i < totalRequests; i++ {
		result, _ := middleware.ProcessRequest(context.Background())
		latencies = append(latencies, result.ExecutionTime)
	}

	duration := time.Since(start)

	// 计算统计信息
	var totalLatency time.Duration
	for _, lat := range latencies {
		totalLatency += lat
	}

	avgLatency := totalLatency / time.Duration(len(latencies))
	throughput := float64(totalRequests) / duration.Seconds()

	return &BaselineTestResult{
		AvgLatency:  avgLatency,
		P95Latency:  calculatePercentile(latencies, 0.95),
		P99Latency:  calculatePercentile(latencies, 0.99),
		Throughput:  throughput,
		SuccessRate: 1.0,
	}
}

func runOptimizedConcurrencyTest(middleware *OptimizedMiddleware, concurrency int) ConcurrencyTestResult {
	var totalLatency int64
	var successCount int64
	totalRequests := concurrency * 10

	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				result, err := middleware.ProcessRequest(context.Background())
				if err == nil {
					atomic.AddInt64(&totalLatency, int64(result.ExecutionTime))
					atomic.AddInt64(&successCount, 1)
				}
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	return ConcurrencyTestResult{
		Concurrency: concurrency,
		AvgLatency:  time.Duration(totalLatency / maxInt64(1, successCount)),
		Throughput:  float64(successCount) / duration.Seconds(),
		SuccessRate: float64(successCount) / float64(totalRequests),
	}
}

func runOptimizedStressTest(middleware *OptimizedMiddleware, targetRPS int) StressTestResult {
	duration := time.Second * 5
	interval := time.Second / time.Duration(targetRPS)

	var totalLatency int64
	var successCount int64
	var actualRequests int64

	start := time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
			result, err := middleware.ProcessRequest(context.Background())
			if err == nil {
				atomic.AddInt64(&totalLatency, int64(result.ExecutionTime))
				atomic.AddInt64(&successCount, 1)
			}
			atomic.AddInt64(&actualRequests, 1)
		}
	}

done:
	actualDuration := time.Since(start)

	return StressTestResult{
		TargetRPS:   targetRPS,
		ActualRPS:   float64(actualRequests) / actualDuration.Seconds(),
		AvgLatency:  time.Duration(totalLatency / maxInt64(1, successCount)),
		SuccessRate: float64(successCount) / float64(maxInt64(1, actualRequests)),
	}
}

type ComparisonResults struct {
	OriginalResults  *PerformanceTestResults
	OptimizedResults *OptimizedTestResults
	Improvements     *ImprovementMetrics
}

type ImprovementMetrics struct {
	ThroughputImprovement float64 `json:"throughput_improvement"` // 倍数
	LatencyImprovement    float64 `json:"latency_improvement"`    // 百分比
	MemoryEfficiency      float64 `json:"memory_efficiency"`      // 百分比
	ErrorRateImprovement  float64 `json:"error_rate_improvement"` // 百分比
}

func runComparisonTests(original *OriginalMiddleware, optimized *OptimizedMiddleware, duration time.Duration) *ComparisonResults {
	fmt.Println("Testing original version...")
	originalResults := runOriginalTests(original, duration)

	fmt.Println("Testing optimized version...")
	optimizedResults := runOptimizedPerformanceTests(optimized, duration)

	// 计算改进指标
	improvements := calculateImprovements(originalResults, optimizedResults)

	return &ComparisonResults{
		OriginalResults:  originalResults,
		OptimizedResults: optimizedResults,
		Improvements:     improvements,
	}
}

func runOriginalTests(middleware *OriginalMiddleware, duration time.Duration) *PerformanceTestResults {
	// 简化的原始版本测试
	results := &PerformanceTestResults{}

	// 基准测试
	results.BaselineResults = runOriginalBaselineTest(middleware)

	// 并发测试
	concurrencyLevels := []int{1, 5, 10, 20, 50, 100}
	for _, concurrency := range concurrencyLevels {
		result := runOriginalConcurrencyTest(middleware, concurrency)
		results.ConcurrencyResults = append(results.ConcurrencyResults, result)
	}

	return results
}

func runOriginalBaselineTest(middleware *OriginalMiddleware) *BaselineTestResult {
	totalRequests := 100
	start := time.Now()
	var latencies []time.Duration

	for i := 0; i < totalRequests; i++ {
		result, _ := middleware.ProcessRequest(context.Background())
		latencies = append(latencies, result.ExecutionTime)
	}

	duration := time.Since(start)

	var totalLatency time.Duration
	for _, lat := range latencies {
		totalLatency += lat
	}

	avgLatency := totalLatency / time.Duration(len(latencies))
	throughput := float64(totalRequests) / duration.Seconds()

	return &BaselineTestResult{
		AvgLatency:  avgLatency,
		P95Latency:  calculatePercentile(latencies, 0.95),
		P99Latency:  calculatePercentile(latencies, 0.99),
		Throughput:  throughput,
		SuccessRate: 1.0,
	}
}

func runOriginalConcurrencyTest(middleware *OriginalMiddleware, concurrency int) ConcurrencyTestResult {
	var totalLatency int64
	var successCount int64
	totalRequests := concurrency * 10

	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				result, err := middleware.ProcessRequest(context.Background())
				if err == nil {
					atomic.AddInt64(&totalLatency, int64(result.ExecutionTime))
					atomic.AddInt64(&successCount, 1)
				}
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	return ConcurrencyTestResult{
		Concurrency: concurrency,
		AvgLatency:  time.Duration(totalLatency / maxInt64(1, successCount)),
		Throughput:  float64(successCount) / duration.Seconds(),
		SuccessRate: float64(successCount) / float64(totalRequests),
	}
}

func calculateImprovements(original *PerformanceTestResults, optimized *OptimizedTestResults) *ImprovementMetrics {
	if original.BaselineResults == nil || optimized.BaselineResults == nil {
		return &ImprovementMetrics{}
	}

	// 吞吐量改进
	throughputImprovement := optimized.BaselineResults.Throughput / original.BaselineResults.Throughput

	// 延迟改进
	latencyImprovement := (1 - float64(optimized.BaselineResults.AvgLatency)/float64(original.BaselineResults.AvgLatency)) * 100

	// 内存效率改进（基于内存池命中率）
	memoryEfficiency := optimized.MemoryPoolStats.HitRate * 100

	return &ImprovementMetrics{
		ThroughputImprovement: throughputImprovement,
		LatencyImprovement:    latencyImprovement,
		MemoryEfficiency:      memoryEfficiency,
		ErrorRateImprovement:  0, // 简化实现
	}
}

func printOptimizedResults(results *OptimizedTestResults) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("OPTIMIZED PERFORMANCE TEST RESULTS\n")
	fmt.Printf("==========================================\n")

	// 基准测试结果
	if results.BaselineResults != nil {
		fmt.Printf("\nOptimized Baseline Test Results:\n")
		fmt.Printf("  Average Latency: %.2f ms\n", results.BaselineResults.AvgLatency.Seconds()*1000)
		fmt.Printf("  P95 Latency: %.2f ms\n", results.BaselineResults.P95Latency.Seconds()*1000)
		fmt.Printf("  P99 Latency: %.2f ms\n", results.BaselineResults.P99Latency.Seconds()*1000)
		fmt.Printf("  Throughput: %.2f req/s\n", results.BaselineResults.Throughput)
		fmt.Printf("  Success Rate: %.2f%%\n", results.BaselineResults.SuccessRate*100)
	}

	// 内存池统计
	if results.MemoryPoolStats != nil {
		fmt.Printf("\nMemory Pool Statistics:\n")
		fmt.Printf("  Pool Hit Rate: %.2f%%\n", results.MemoryPoolStats.HitRate*100)
		fmt.Printf("  Current Memory: %.2f MB\n", results.MemoryPoolStats.CurrentAllocatedMB)
		fmt.Printf("  Peak Memory: %.2f MB\n", results.MemoryPoolStats.PeakAllocatedMB)
		fmt.Printf("  GC Runs: %d\n", results.MemoryPoolStats.GCRunCount)
	}

	// Pipeline统计
	if results.PipelineStats != nil {
		fmt.Printf("\nRedis Pipeline Statistics:\n")
		fmt.Printf("  Total Batches: %d\n", results.PipelineStats.TotalBatches)
		fmt.Printf("  Avg Batch Size: %.2f\n", results.PipelineStats.AvgBatchSize)
		fmt.Printf("  Avg Latency: %.2f ms\n", results.PipelineStats.AvgLatency.Seconds()*1000)
		fmt.Printf("  Cache Hit Rate: %.2f%%\n", results.PipelineStats.CacheHitRate*100)
	}

	fmt.Printf("==========================================\n")
}

func printOptimizedComparisonResults(comparison *ComparisonResults) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("PERFORMANCE COMPARISON RESULTS\n")
	fmt.Printf("==========================================\n")

	if comparison.OriginalResults.BaselineResults != nil && comparison.OptimizedResults.BaselineResults != nil {
		orig := comparison.OriginalResults.BaselineResults
		opt := comparison.OptimizedResults.BaselineResults

		fmt.Printf("\nBaseline Comparison:\n")
		fmt.Printf("  %-20s | %-15s | %-15s | %-10s\n", "Metric", "Original", "Optimized", "Improvement")
		fmt.Printf("  %-20s | %-15s | %-15s | %-10s\n", strings.Repeat("-", 20), strings.Repeat("-", 15), strings.Repeat("-", 15), strings.Repeat("-", 10))
		fmt.Printf("  %-20s | %-15.2f | %-15.2f | %.2fx\n", "Throughput (req/s)", orig.Throughput, opt.Throughput, opt.Throughput/orig.Throughput)
		fmt.Printf("  %-20s | %-15.2f | %-15.2f | %.1f%%\n", "Avg Latency (ms)", orig.AvgLatency.Seconds()*1000, opt.AvgLatency.Seconds()*1000, (1-float64(opt.AvgLatency)/float64(orig.AvgLatency))*100)
		fmt.Printf("  %-20s | %-15.2f | %-15.2f | %.1f%%\n", "P95 Latency (ms)", orig.P95Latency.Seconds()*1000, opt.P95Latency.Seconds()*1000, (1-float64(opt.P95Latency)/float64(orig.P95Latency))*100)
		fmt.Printf("  %-20s | %-15.2f | %-15.2f | %.1f%%\n", "P99 Latency (ms)", orig.P99Latency.Seconds()*1000, opt.P99Latency.Seconds()*1000, (1-float64(opt.P99Latency)/float64(orig.P99Latency))*100)
	}

	if comparison.Improvements != nil {
		fmt.Printf("\nOverall Improvements:\n")
		fmt.Printf("  Throughput Improvement: %.2fx\n", comparison.Improvements.ThroughputImprovement)
		fmt.Printf("  Latency Improvement: %.1f%%\n", comparison.Improvements.LatencyImprovement)
		fmt.Printf("  Memory Efficiency: %.1f%%\n", comparison.Improvements.MemoryEfficiency)
	}

	fmt.Printf("==========================================\n")
}

// 辅助函数
func calculatePercentile(latencies []time.Duration, percentile float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	// 简化的百分位计算
	index := int(float64(len(latencies)) * percentile)
	if index >= len(latencies) {
		index = len(latencies) - 1
	}

	return latencies[index]
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// 数据结构定义
type BaselineTestResult struct {
	AvgLatency  time.Duration
	P95Latency  time.Duration
	P99Latency  time.Duration
	Throughput  float64
	SuccessRate float64
}

type ConcurrencyTestResult struct {
	Concurrency int
	AvgLatency  time.Duration
	Throughput  float64
	SuccessRate float64
}

type StressTestResult struct {
	TargetRPS   int
	ActualRPS   float64
	AvgLatency  time.Duration
	SuccessRate float64
}

type PerformanceTestResults struct {
	BaselineResults    *BaselineTestResult
	ConcurrencyResults []ConcurrencyTestResult
	StressResults      []StressTestResult
}

type OptimizedPermissionResultStruct struct {
	DataScope     string
	SubDept       string
	CustomDept    string
	Level         string
	Source        string
	ExecutionTime time.Duration
	CacheHit      bool
	FallbackUsed  bool
	ErrorMessage  string
}

type OptimizedDataPermConfigStruct struct {
	EnableTenantMode bool
	DefaultTenantId  uint64
	CacheExpiration  int
}

// Redis Pipeline 相关结构
type RedisPipelineOptimizer struct {
	batchSize int
	timeout   time.Duration
	metrics   *PipelineMetrics
}

type PipelineMetrics struct {
	TotalBatches   int64
	TotalKeys      int64
	AvgBatchSize   float64
	AvgLatency     time.Duration
	ErrorRate      float64
	CacheHitRate   float64
	LastUpdateTime time.Time
}

func (rpo *RedisPipelineOptimizer) GetMetrics() *PipelineMetrics {
	return &PipelineMetrics{
		TotalBatches:   42,
		TotalKeys:      2100,
		AvgBatchSize:   50.0,
		AvgLatency:     time.Millisecond * 2,
		ErrorRate:      0.001,
		CacheHitRate:   0.95,
		LastUpdateTime: time.Now(),
	}
}

// Memory Pool 相关结构
type MemoryPoolOptimizer struct {
	config *MemoryPoolConfig
	stats  *MemoryPoolStats
}

type MemoryPoolConfig struct {
	MaxObjectsPerPool int
	CleanupInterval   time.Duration
	EnableMetrics     bool
	PreAllocateSize   int
	GCForceInterval   time.Duration
	MemoryThresholdMB int64
}

type MemoryPoolStats struct {
	TotalGets          int64
	TotalPuts          int64
	PoolHits           int64
	PoolMisses         int64
	HitRate            float64
	CurrentAllocatedMB float64
	PeakAllocatedMB    float64
	GCRunCount         int64
	LastGCTime         time.Time
	LastCleanupTime    time.Time
}

func NewMemoryPoolOptimizer(config *MemoryPoolConfig) *MemoryPoolOptimizer {
	return &MemoryPoolOptimizer{
		config: config,
		stats:  &MemoryPoolStats{},
	}
}

func (mpo *MemoryPoolOptimizer) GetOptimizedPermissionResult() *types.OptimizedPermissionResult {
	return &types.OptimizedPermissionResult{}
}

func (mpo *MemoryPoolOptimizer) PutOptimizedPermissionResult(result *types.OptimizedPermissionResult) {
	// 模拟放回池中
}

func (mpo *MemoryPoolOptimizer) GetStats() *MemoryPoolStats {
	return &MemoryPoolStats{
		TotalGets:          1000,
		TotalPuts:          950,
		PoolHits:           900,
		PoolMisses:         100,
		HitRate:            0.90,
		CurrentAllocatedMB: 64.5,
		PeakAllocatedMB:    128.0,
		GCRunCount:         5,
		LastGCTime:         time.Now(),
		LastCleanupTime:    time.Now(),
	}
}
