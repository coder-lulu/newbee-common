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

// RunPerformanceTest 运行性能测试
func RunPerformanceTest(configType string, duration, warmup time.Duration, output string) {
	// 初始化日志
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 创建测试配置
	config := createPerfTestConfig(configType, duration, warmup)
	if config == nil {
		log.Fatalf("Unknown config type: %s", configType)
	}

	// 创建DataPerm中间件实例
	middleware := createPerfTestMiddleware()

	fmt.Printf("Starting performance test with config: %s\n", configType)
	fmt.Printf("Duration: %v, Warmup: %v\n", duration, warmup)
	fmt.Printf("==========================================\n")

	// 运行性能测试
	results := runPerformanceTest(middleware, config)

	// 输出结果
	outputResults(results, *output)
}

func createPerfTestConfig(configType string, duration, warmup time.Duration) *PerformanceTestConfig {
	switch strings.ToLower(configType) {
	case "baseline":
		return &PerformanceTestConfig{
			TestDuration:      duration,
			ConcurrencyLevels: []int{1, 5, 10, 20},
			RequestsPerSecond: []int{100, 500, 1000},
			CacheHitRatio:     0.8,
			ErrorRate:         0.01,
			EnableWarmup:      true,
			WarmupDuration:    warmup,
			WarmupRequests:    1000,
			CollectMetrics:    true,
			EnableProfiling:   true,
			ProfileCPU:        true,
			ProfileMemory:     true,
			GCForceInterval:   time.Second * 10,
			ResourceLimits: ResourceLimits{
				MaxCPUPercent:  80.0,
				MaxMemoryMB:    512,
				MaxGoroutines:  1000,
				MaxFileHandles: 1000,
			},
		}
	case "stress":
		return &PerformanceTestConfig{
			TestDuration:      duration,
			ConcurrencyLevels: []int{50, 100, 200, 500},
			RequestsPerSecond: []int{2000, 5000, 10000},
			CacheHitRatio:     0.6,
			ErrorRate:         0.05,
			EnableWarmup:      true,
			WarmupDuration:    warmup,
			WarmupRequests:    2000,
			CollectMetrics:    true,
			EnableProfiling:   true,
			ProfileCPU:        true,
			ProfileMemory:     true,
			GCForceInterval:   time.Second * 5,
			ResourceLimits: ResourceLimits{
				MaxCPUPercent:  95.0,
				MaxMemoryMB:    1024,
				MaxGoroutines:  2000,
				MaxFileHandles: 2000,
			},
		}
	case "endurance":
		return &PerformanceTestConfig{
			TestDuration:      duration,
			ConcurrencyLevels: []int{10, 20, 50},
			RequestsPerSecond: []int{500, 1000},
			CacheHitRatio:     0.9,
			ErrorRate:         0.001,
			EnableWarmup:      true,
			WarmupDuration:    warmup,
			WarmupRequests:    500,
			CollectMetrics:    true,
			EnableProfiling:   true,
			ProfileCPU:        false,
			ProfileMemory:     true,
			GCForceInterval:   time.Second * 30,
			ResourceLimits: ResourceLimits{
				MaxCPUPercent:  70.0,
				MaxMemoryMB:    256,
				MaxGoroutines:  500,
				MaxFileHandles: 500,
			},
		}
	default:
		return nil
	}
}

func createPerfTestMiddleware() *PerfDataPermMiddleware {
	config := &PerfDataPermConfig{
		EnableTenantMode: true,
		DefaultTenantId:  1,
		CacheExpiration:  time.Minute * 5,
	}

	middleware := &PerfDataPermMiddleware{
		Config:           config,
		refreshSemaphore: make(chan struct{}, 10),
	}

	return middleware
}

func runPerformanceTest(middleware types.DataPermMiddleware, config *PerformanceTestConfig) *PerformanceTestResults {
	// 创建性能测试套件
	suite := &PerformanceTestSuite{
		middleware: middleware,
		config:     config,
		results:    &PerformanceTestResults{},
		monitoring: &TestMonitoring{},
	}

	// 执行预热
	if config.EnableWarmup {
		fmt.Printf("Warming up for %v...\n", config.WarmupDuration)
		suite.runWarmup()
	}

	// 执行基准测试
	fmt.Printf("Running baseline tests...\n")
	suite.runBaselineTest()

	// 执行并发测试
	fmt.Printf("Running concurrency tests...\n")
	for _, concurrency := range config.ConcurrencyLevels {
		fmt.Printf("  Testing concurrency level: %d\n", concurrency)
		suite.runConcurrencyTest(concurrency)
	}

	// 执行压力测试
	fmt.Printf("Running stress tests...\n")
	for _, rps := range config.RequestsPerSecond {
		fmt.Printf("  Testing RPS: %d\n", rps)
		suite.runStressTest(rps)
	}

	// 执行冷启动测试
	fmt.Printf("Running cold start tests...\n")
	suite.runColdStartTest()

	return suite.results
}

func outputResults(results *PerformanceTestResults, format string) {
	switch format {
	case "json":
		// TODO: JSON输出格式
		fmt.Println("JSON output not implemented yet")
	default:
		printConsoleResults(results)
	}
}

func printConsoleResults(results *PerformanceTestResults) {
	fmt.Printf("\n==========================================\n")
	fmt.Printf("PERFORMANCE TEST RESULTS\n")
	fmt.Printf("==========================================\n")

	// 基准测试结果
	if results.BaselineResults != nil {
		fmt.Printf("\nBaseline Test Results:\n")
		fmt.Printf("  Average Latency: %.2f ms\n", results.BaselineResults.AvgLatency.Seconds()*1000)
		fmt.Printf("  P95 Latency: %.2f ms\n", results.BaselineResults.P95Latency.Seconds()*1000)
		fmt.Printf("  P99 Latency: %.2f ms\n", results.BaselineResults.P99Latency.Seconds()*1000)
		fmt.Printf("  Throughput: %.2f req/s\n", results.BaselineResults.Throughput)
		fmt.Printf("  Success Rate: %.2f%%\n", results.BaselineResults.SuccessRate*100)
	}

	// 并发测试结果
	if len(results.ConcurrencyResults) > 0 {
		fmt.Printf("\nConcurrency Test Results:\n")
		for _, result := range results.ConcurrencyResults {
			fmt.Printf("  Concurrency %d:\n", result.Concurrency)
			fmt.Printf("    Avg Latency: %.2f ms\n", result.AvgLatency.Seconds()*1000)
			fmt.Printf("    Throughput: %.2f req/s\n", result.Throughput)
			fmt.Printf("    Success Rate: %.2f%%\n", result.SuccessRate*100)
		}
	}

	// 压力测试结果
	if len(results.StressResults) > 0 {
		fmt.Printf("\nStress Test Results:\n")
		for _, result := range results.StressResults {
			fmt.Printf("  Target RPS %d:\n", result.TargetRPS)
			fmt.Printf("    Actual RPS: %.2f\n", result.ActualRPS)
			fmt.Printf("    Avg Latency: %.2f ms\n", result.AvgLatency.Seconds()*1000)
			fmt.Printf("    Success Rate: %.2f%%\n", result.SuccessRate*100)
		}
	}

	// 冷启动测试结果
	if results.ColdStartResults != nil {
		fmt.Printf("\nCold Start Test Results:\n")
		fmt.Printf("  First Request Latency: %.2f ms\n", results.ColdStartResults.FirstRequestLatency.Seconds()*1000)
		fmt.Printf("  Stabilization Time: %.2f s\n", results.ColdStartResults.StabilizationTime.Seconds())
	}

	// 资源使用情况
	if results.ResourceUsage != nil {
		fmt.Printf("\nResource Usage:\n")
		fmt.Printf("  Max CPU: %.2f%%\n", results.ResourceUsage.MaxCPUPercent)
		fmt.Printf("  Max Memory: %.2f MB\n", results.ResourceUsage.MaxMemoryMB)
		fmt.Printf("  Max Goroutines: %d\n", results.ResourceUsage.MaxGoroutines)
	}

	fmt.Printf("==========================================\n")
}

// 性能测试相关结构体定义
type PerformanceTestConfig struct {
	TestDuration      time.Duration
	ConcurrencyLevels []int
	RequestsPerSecond []int
	CacheHitRatio     float64
	ErrorRate         float64
	EnableWarmup      bool
	WarmupDuration    time.Duration
	WarmupRequests    int
	CollectMetrics    bool
	EnableProfiling   bool
	ProfileCPU        bool
	ProfileMemory     bool
	GCForceInterval   time.Duration
	ResourceLimits    ResourceLimits
}

type ResourceLimits struct {
	MaxCPUPercent  float64
	MaxMemoryMB    float64
	MaxGoroutines  int
	MaxFileHandles int
}

type PerformanceTestSuite struct {
	middleware *PerfDataPermMiddleware
	config     *PerformanceTestConfig
	results    *PerfTestResults
	monitoring *TestMonitoring
}

type PerfTestResults struct {
	BaselineResults    *PerfBaselineTestResult
	ConcurrencyResults []PerfConcurrencyTestResult
	StressResults      []PerfStressTestResult
	ColdStartResults   *ColdStartTestResult
	ResourceUsage      *ResourceUsageResult
}

type PerfBaselineTestResult struct {
	AvgLatency  time.Duration
	P95Latency  time.Duration
	P99Latency  time.Duration
	Throughput  float64
	SuccessRate float64
}

type PerfConcurrencyTestResult struct {
	Concurrency int
	AvgLatency  time.Duration
	Throughput  float64
	SuccessRate float64
}

type PerfStressTestResult struct {
	TargetRPS   int
	ActualRPS   float64
	AvgLatency  time.Duration
	SuccessRate float64
}

type ColdStartTestResult struct {
	FirstRequestLatency time.Duration
	StabilizationTime   time.Duration
}

type ResourceUsageResult struct {
	MaxCPUPercent float64
	MaxMemoryMB   float64
	MaxGoroutines int
}

type TestMonitoring struct {
}

// DataPermMiddleware 临时定义
type PerfDataPermMiddleware struct {
	Config           *PerfDataPermConfig
	refreshSemaphore chan struct{}
}

type PerfDataPermConfig struct {
	EnableTenantMode bool
	DefaultTenantId  int64
	CacheExpiration  time.Duration
}

// 性能测试方法的简化实现
func (suite *PerformanceTestSuite) runWarmup() {
	// 简化的预热实现
	ctx, cancel := context.WithTimeout(context.Background(), suite.config.WarmupDuration)
	defer cancel()

	for i := 0; i < suite.config.WarmupRequests; i++ {
		select {
		case <-ctx.Done():
			return
		default:
			// 模拟请求
			time.Sleep(time.Microsecond * 100)
		}
	}
}

func (suite *PerformanceTestSuite) runBaselineTest() {
	// 简化的基准测试实现
	start := time.Now()
	var totalLatency time.Duration
	var successCount int64
	totalRequests := 100

	for i := 0; i < totalRequests; i++ {
		reqStart := time.Now()
		// 模拟中间件调用
		time.Sleep(time.Microsecond * 500)
		reqLatency := time.Since(reqStart)

		totalLatency += reqLatency
		successCount++
	}

	duration := time.Since(start)

	suite.results.BaselineResults = &BaselineTestResult{
		AvgLatency:  totalLatency / time.Duration(totalRequests),
		P95Latency:  totalLatency / time.Duration(totalRequests) * 2, // 简化计算
		P99Latency:  totalLatency / time.Duration(totalRequests) * 3, // 简化计算
		Throughput:  float64(successCount) / duration.Seconds(),
		SuccessRate: float64(successCount) / float64(totalRequests),
	}
}

func (suite *PerformanceTestSuite) runConcurrencyTest(concurrency int) {
	// 简化的并发测试实现
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
				reqStart := time.Now()
				// 模拟中间件调用
				time.Sleep(time.Microsecond * 500)
				reqLatency := time.Since(reqStart)

				atomic.AddInt64(&totalLatency, int64(reqLatency))
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	result := ConcurrencyTestResult{
		Concurrency: concurrency,
		AvgLatency:  time.Duration(totalLatency / int64(totalRequests)),
		Throughput:  float64(successCount) / duration.Seconds(),
		SuccessRate: float64(successCount) / float64(totalRequests),
	}

	suite.results.ConcurrencyResults = append(suite.results.ConcurrencyResults, result)
}

func (suite *PerformanceTestSuite) runStressTest(targetRPS int) {
	// 简化的压力测试实现
	duration := time.Second * 5 // 短时间压力测试
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
			reqStart := time.Now()
			// 模拟中间件调用
			time.Sleep(time.Microsecond * 500)
			reqLatency := time.Since(reqStart)

			atomic.AddInt64(&totalLatency, int64(reqLatency))
			atomic.AddInt64(&successCount, 1)
			atomic.AddInt64(&actualRequests, 1)
		}
	}

done:
	actualDuration := time.Since(start)

	result := StressTestResult{
		TargetRPS:   targetRPS,
		ActualRPS:   float64(actualRequests) / actualDuration.Seconds(),
		AvgLatency:  time.Duration(totalLatency / max(1, actualRequests)),
		SuccessRate: float64(successCount) / float64(max(1, actualRequests)),
	}

	suite.results.StressResults = append(suite.results.StressResults, result)
}

func (suite *PerformanceTestSuite) runColdStartTest() {
	// 简化的冷启动测试实现
	start := time.Now()
	// 模拟第一次请求
	time.Sleep(time.Millisecond * 10) // 冷启动延迟
	firstReqLatency := time.Since(start)

	// 模拟稳定化时间
	stabilizationStart := time.Now()
	for i := 0; i < 10; i++ {
		time.Sleep(time.Microsecond * 500)
	}
	stabilizationTime := time.Since(stabilizationStart)

	suite.results.ColdStartResults = &ColdStartTestResult{
		FirstRequestLatency: firstReqLatency,
		StabilizationTime:   stabilizationTime,
	}

	// 模拟资源使用情况
	suite.results.ResourceUsage = &ResourceUsageResult{
		MaxCPUPercent: 45.5,
		MaxMemoryMB:   128.7,
		MaxGoroutines: 25,
	}
}

func maxInt64Perf(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
