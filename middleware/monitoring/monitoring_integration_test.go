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

package monitoring

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/coder-lulu/newbee-common/i18n"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
)

// TestDataPermMiddleware_MonitoringIntegration 测试数据权限中间件的完整监控集成
func TestDataPermMiddleware_MonitoringIntegration(t *testing.T) {
	// 创建配置
	config := &DataPermConfig{
		EnableTenantMode:      false,
		DefaultTenantId:       entenum.TenantDefaultId,
		CircuitBreakerEnabled: true,
		L1CacheEnabled:        true,
		TimeoutConfig: &TimeoutConfig{
			RequestTimeout: 100 * time.Millisecond,
		},
	}

	// 创建mock RPC客户端
	mockRPC := &MockRPCClient{}
	trans := &i18n.Translator{}

	// 创建中间件实例 - 传nil作为redis客户端用于测试
	middleware := NewDataPermMiddleware(nil, mockRPC, trans, config)
	defer middleware.Close()

	// 验证监控组件已初始化
	if middleware.metricsCollector == nil {
		t.Fatal("Expected metrics collector to be initialized")
	}

	if middleware.performanceAnalyzer == nil {
		t.Fatal("Expected performance analyzer to be initialized")
	}

	// Note: 在实际环境中，需要完整的HTTP请求处理和上下文设置
	// 这里我们专注于监控组件本身的测试

	// 测试指标收集
	t.Run("MetricsCollection", func(t *testing.T) {
		// 记录一些测试指标
		middleware.metricsCollector.RecordRequest("dataperm", "GET", 50*time.Millisecond, true)
		middleware.metricsCollector.RecordRequest("dataperm", "POST", 120*time.Millisecond, false)
		middleware.metricsCollector.RecordCacheOperation("dataperm", "l1_get", true, 1*time.Millisecond)
		middleware.metricsCollector.RecordCacheOperation("dataperm", "redis_get", false, 10*time.Millisecond)
		middleware.metricsCollector.RecordMemoryUsage("dataperm", 50*1024*1024) // 50MB

		// 获取并验证指标
		metrics := middleware.metricsCollector.(*InMemoryMetricsCollector).GetMetrics("dataperm")

		if metrics.RequestCount != 2 {
			t.Errorf("Expected 2 requests, got %d", metrics.RequestCount)
		}

		if metrics.ErrorCount != 1 {
			t.Errorf("Expected 1 error, got %d", metrics.ErrorCount)
		}

		if metrics.CacheOperations != 2 {
			t.Errorf("Expected 2 cache operations, got %d", metrics.CacheOperations)
		}

		if metrics.MemoryUsage != 50*1024*1024 {
			t.Errorf("Expected memory usage 50MB, got %d", metrics.MemoryUsage)
		}

		// 验证缓存命中率计算
		if metrics.CacheHitRate < 0.4 || metrics.CacheHitRate > 0.6 {
			t.Errorf("Expected cache hit rate around 0.5, got %.2f", metrics.CacheHitRate)
		}
	})

	// 测试性能分析
	t.Run("PerformanceAnalysis", func(t *testing.T) {
		// 获取性能报告
		report := middleware.performanceAnalyzer.GeneratePerformanceReport()

		if report.GoroutineCount <= 0 {
			t.Error("Expected positive goroutine count")
		}

		if report.HeapInUse < 0 {
			t.Error("Expected non-negative heap usage")
		}

		if report.GeneratedAt.IsZero() {
			t.Error("Expected valid generation timestamp")
		}

		// 验证推荐系统
		if len(report.Recommendations) >= 0 { // 可能有也可能没有推荐
			for _, rec := range report.Recommendations {
				if rec.Category == "" || rec.Priority == "" {
					t.Error("Expected recommendations to have category and priority")
				}
			}
		}
	})

	// 测试熔断器状态监控
	t.Run("CircuitBreakerMonitoring", func(t *testing.T) {
		stats := middleware.GetCircuitBreakerStats()

		// 应该有Redis和RPC熔断器
		if _, exists := stats["redis"]; !exists {
			t.Error("Expected redis circuit breaker stats")
		}

		if _, exists := stats["rpc"]; !exists {
			t.Error("Expected rpc circuit breaker stats")
		}

		// 验证熔断器状态
		for name, stat := range stats {
			statMap, ok := stat.(map[string]interface{})
			if !ok {
				t.Errorf("Expected stat map for %s circuit breaker", name)
				continue
			}

			if _, exists := statMap["state"]; !exists {
				t.Errorf("Expected state in %s circuit breaker stats", name)
			}

			if _, exists := statMap["counts"]; !exists {
				t.Errorf("Expected counts in %s circuit breaker stats", name)
			}
		}
	})

	// 测试指标导出
	t.Run("MetricsExport", func(t *testing.T) {
		exported := middleware.metricsCollector.Export()

		// 验证导出数据结构
		expectedKeys := []string{"middleware_metrics", "system_metrics", "total_requests", "total_errors", "export_time"}
		for _, key := range expectedKeys {
			if _, exists := exported[key]; !exists {
				t.Errorf("Expected key '%s' in exported metrics", key)
			}
		}

		// 验证中间件特定指标
		if middlewareMetrics, ok := exported["middleware_metrics"].(map[string]*MiddlewareMetrics); ok {
			if datapermMetrics, exists := middlewareMetrics["dataperm"]; exists {
				if datapermMetrics.RequestCount == 0 {
					t.Error("Expected non-zero request count in exported dataperm metrics")
				}
			} else {
				t.Error("Expected dataperm metrics in exported data")
			}
		} else {
			t.Error("Expected middleware_metrics to be map[string]*MiddlewareMetrics")
		}
	})
}

// TestMonitoringSystem_AlertIntegration 测试监控系统与告警系统的集成
func TestMonitoringSystem_AlertIntegration(t *testing.T) {
	// 创建监控系统组件
	metricsCollector := NewInMemoryMetricsCollector(DefaultMetricsConfig())
	alertManager := NewAlertManager(DefaultAlertConfig())

	// 添加日志通知器
	logNotifier := NewLogNotifier("integration-test", []string{"test-channel"}, nil)
	alertManager.AddNotifier(logNotifier)

	// 创建基于指标的告警规则
	errorRateRule := AlertRule{
		ID:          "integration-error-rate",
		Name:        "Integration Error Rate Alert",
		Description: "Monitors error rate from metrics collector",
		Condition: func(metrics map[string]interface{}) bool {
			// 从指标收集器检查阈值
			alerts := metricsCollector.CheckThresholds()
			for _, alert := range alerts {
				if alert.Type == "error_rate" && alert.Current > 0.2 {
					return true
				}
			}
			return false
		},
		Severity:             SeverityWarning,
		Enabled:              true,
		MinDuration:          10 * time.Millisecond,
		NotificationChannels: []string{"test-channel"},
	}

	latencyRule := AlertRule{
		ID:          "integration-latency",
		Name:        "Integration Latency Alert",
		Description: "Monitors response time from metrics",
		Condition: func(metrics map[string]interface{}) bool {
			if avgLatency, ok := metrics["avg_latency"].(time.Duration); ok {
				return avgLatency > 200*time.Millisecond
			}
			return false
		},
		Severity:             SeverityCritical,
		Enabled:              true,
		MinDuration:          5 * time.Millisecond,
		NotificationChannels: []string{"test-channel"},
	}

	alertManager.AddRule(errorRateRule)
	alertManager.AddRule(latencyRule)

	// 模拟高错误率场景
	t.Run("HighErrorRateScenario", func(t *testing.T) {
		// 记录大量错误请求
		for i := 0; i < 8; i++ {
			metricsCollector.RecordRequest("test-service", "GET", 100*time.Millisecond, false)
		}
		for i := 0; i < 2; i++ {
			metricsCollector.RecordRequest("test-service", "GET", 80*time.Millisecond, true)
		}
		// 错误率 = 8/10 = 80%

		// 检查阈值
		thresholdAlerts := metricsCollector.CheckThresholds()

		hasErrorRateAlert := false
		for _, alert := range thresholdAlerts {
			if alert.Type == "error_rate" {
				hasErrorRateAlert = true
				if alert.Current < 0.7 { // 应该接近80%
					t.Errorf("Expected high error rate, got %.2f", alert.Current)
				}
				break
			}
		}

		if !hasErrorRateAlert {
			t.Error("Expected error rate threshold alert")
		}

		// 模拟告警管理器评估
		originalGetCurrentMetrics := alertManager.getCurrentMetrics
		alertManager.getCurrentMetrics = func() map[string]interface{} {
			return map[string]interface{}{
				"error_rate": 0.8,
			}
		}
		defer func() {
			alertManager.getCurrentMetrics = originalGetCurrentMetrics
		}()

		// 评估规则
		alertManager.evaluateRules()

		// 检查活跃告警
		activeAlerts := alertManager.GetActiveAlerts()
		if len(activeAlerts) == 0 {
			t.Error("Expected active alert for high error rate")
		}
	})

	// 测试高延迟场景
	t.Run("HighLatencyScenario", func(t *testing.T) {
		// 模拟高延迟指标
		originalGetCurrentMetrics := alertManager.getCurrentMetrics
		alertManager.getCurrentMetrics = func() map[string]interface{} {
			return map[string]interface{}{
				"avg_latency": 300 * time.Millisecond, // 超过200ms阈值
			}
		}
		defer func() {
			alertManager.getCurrentMetrics = originalGetCurrentMetrics
		}()

		// 评估规则
		alertManager.evaluateRules()

		// 检查活跃告警
		activeAlerts := alertManager.GetActiveAlerts()

		hasLatencyAlert := false
		for _, alert := range activeAlerts {
			if alert.Rule.ID == "integration-latency" {
				hasLatencyAlert = true
				if alert.Rule.Severity != SeverityCritical {
					t.Errorf("Expected critical severity for latency alert, got %s", alert.Rule.Severity.String())
				}
				break
			}
		}

		if !hasLatencyAlert {
			t.Error("Expected latency alert for high response time")
		}
	})
}

// TestPerformanceAnalyzer_RealWorld 测试性能分析器的实际场景
func TestPerformanceAnalyzer_RealWorld(t *testing.T) {
	metricsCollector := NewInMemoryMetricsCollector(nil)

	config := DefaultAnalyzerConfig()
	config.CPUInterval = 10 * time.Millisecond
	config.MemoryInterval = 10 * time.Millisecond
	config.MemoryThreshold = 10 * 1024 * 1024 // 10MB threshold for testing

	analyzer := NewPerformanceAnalyzer(config, metricsCollector)

	// 启动分析器
	analyzer.Start()
	defer analyzer.Stop()

	// 等待一些监控周期
	time.Sleep(50 * time.Millisecond)

	// 模拟内存分配压力
	t.Run("MemoryPressureSimulation", func(t *testing.T) {
		// 分配一些内存来触发内存监控
		var memSlices [][]byte
		for i := 0; i < 100; i++ {
			memSlices = append(memSlices, make([]byte, 1024*1024)) // 1MB每次
		}

		// 等待监控周期捕获内存使用
		time.Sleep(30 * time.Millisecond)

		// 获取内存压力信息
		memPressure := analyzer.GetMemoryPressure()
		if memPressure.HeapInUse <= 0 {
			t.Error("Expected positive heap usage")
		}

		// 生成性能报告
		report := analyzer.GeneratePerformanceReport()
		if report.HeapInUse <= 0 {
			t.Error("Expected positive heap usage in report")
		}

		// 应该有一些推荐
		if len(report.Recommendations) > 0 {
			hasMemoryRec := false
			for _, rec := range report.Recommendations {
				if rec.Category == "memory" {
					hasMemoryRec = true
					break
				}
			}

			if !hasMemoryRec && memPressure.Level >= PressureHigh {
				t.Error("Expected memory recommendation for high memory usage")
			}
		}

		// 清理内存
		memSlices = nil
		runtime.GC()
	})

	// 测试Goroutine监控
	t.Run("GoroutineMonitoring", func(t *testing.T) {
		initialGoroutines := runtime.NumGoroutine()

		// 创建一些goroutines
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				time.Sleep(100 * time.Millisecond)
				done <- true
			}()
		}

		// 等待监控捕获
		time.Sleep(30 * time.Millisecond)

		currentGoroutines := runtime.NumGoroutine()
		if currentGoroutines <= initialGoroutines {
			t.Errorf("Expected more goroutines, initial: %d, current: %d",
				initialGoroutines, currentGoroutines)
		}

		// 等待goroutines完成
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// BenchmarkMetricsCollection 基准测试指标收集性能
func BenchmarkMetricsCollection(b *testing.B) {
	collector := NewInMemoryMetricsCollector(nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// 模拟并发指标记录
			collector.RecordRequest("benchmark", "GET", 100*time.Millisecond, true)
		}
	})
}

// BenchmarkCacheOperation 基准测试缓存操作记录性能
func BenchmarkCacheOperation(b *testing.B) {
	collector := NewInMemoryMetricsCollector(nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			collector.RecordCacheOperation("benchmark", "get", true, 1*time.Millisecond)
		}
	})
}

// BenchmarkAlertEvaluation 基准测试告警评估性能
func BenchmarkAlertEvaluation(b *testing.B) {
	manager := NewAlertManager(nil)

	// 添加多个规则
	for i := 0; i < 10; i++ {
		rule := AlertRule{
			ID:          fmt.Sprintf("bench-rule-%d", i),
			Name:        fmt.Sprintf("Benchmark Rule %d", i),
			Description: "Benchmark alert rule",
			Condition: func(metrics map[string]interface{}) bool {
				if value, ok := metrics["test_metric"].(float64); ok {
					return value > 50.0
				}
				return false
			},
			Severity: SeverityInfo,
			Enabled:  true,
		}
		manager.AddRule(rule)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.evaluateRules()
	}
}
