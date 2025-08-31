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

package framework

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestTraceManager_StartSpan(t *testing.T) {
	config := DefaultTracingConfig()
	config.SamplingRate = 1.0 // Sample all traces for testing

	traceManager := NewTraceManager(config)

	ctx := context.Background()
	span, newCtx := traceManager.StartSpan(ctx, "test_operation")

	if span == nil {
		t.Fatal("Expected non-nil span")
	}

	if span.OperationName != "test_operation" {
		t.Errorf("Expected operation name 'test_operation', got %s", span.OperationName)
	}

	if span.TraceID == "" {
		t.Error("Expected non-empty trace ID")
	}

	if span.SpanID == "" {
		t.Error("Expected non-empty span ID")
	}

	// Check context
	extractedSpan := SpanFromContext(newCtx)
	if extractedSpan != span {
		t.Error("Span not properly stored in context")
	}

	// Finish span
	traceManager.FinishSpan(span)

	if !span.finished {
		t.Error("Span should be marked as finished")
	}

	if span.Duration <= 0 {
		t.Error("Span should have positive duration")
	}
}

func TestTraceManager_ChildSpan(t *testing.T) {
	traceManager := NewTraceManager(DefaultTracingConfig())

	// Create parent span
	ctx := context.Background()
	parentSpan, parentCtx := traceManager.StartSpan(ctx, "parent_operation")

	// Create child span
	childSpan, childCtx := traceManager.StartSpan(parentCtx, "child_operation")

	if childSpan.TraceID != parentSpan.TraceID {
		t.Error("Child span should have same trace ID as parent")
	}

	if childSpan.ParentSpanID != parentSpan.SpanID {
		t.Error("Child span should have parent span ID set")
	}

	// Check both spans in context
	if SpanFromContext(parentCtx) != parentSpan {
		t.Error("Parent span not in parent context")
	}

	if SpanFromContext(childCtx) != childSpan {
		t.Error("Child span not in child context")
	}

	traceManager.FinishSpan(childSpan)
	traceManager.FinishSpan(parentSpan)
}

func TestSpan_Operations(t *testing.T) {
	traceManager := NewTraceManager(DefaultTracingConfig())

	span, _ := traceManager.StartSpan(context.Background(), "test_operation")

	// Test SetTag
	span.SetTag("user.id", "12345")
	span.SetTag("http.status_code", 200)

	if span.Tags["user.id"] != "12345" {
		t.Error("Tag not set correctly")
	}

	// Test AddEvent
	span.AddEvent("cache_hit", map[string]interface{}{
		"cache.key": "user:12345",
		"cache.ttl": 300,
	})

	if len(span.Events) != 1 {
		t.Error("Event not added")
	}

	// Test LogFields
	span.LogFields(map[string]interface{}{
		"message": "Processing user request",
		"level":   "info",
	})

	if len(span.Logs) != 1 {
		t.Error("Log not added")
	}

	// Test RecordError
	testErr := fmt.Errorf("test error")
	span.RecordError(testErr)

	if span.Status.Code != SpanStatusError {
		t.Error("Span status should be error")
	}

	if span.Status.Message != "test error" {
		t.Error("Error message not set correctly")
	}

	traceManager.FinishSpan(span)
}

func TestProbabilitySampler(t *testing.T) {
	// Test 100% sampling
	sampler := NewProbabilitySampler(1.0)
	for i := 0; i < 100; i++ {
		if !sampler.ShouldSample(context.Background(), fmt.Sprintf("trace_%d", i), "operation") {
			t.Error("100% sampler should always sample")
		}
	}

	// Test 0% sampling
	sampler = NewProbabilitySampler(0.0)
	for i := 0; i < 100; i++ {
		if sampler.ShouldSample(context.Background(), fmt.Sprintf("trace_%d", i), "operation") {
			t.Error("0% sampler should never sample")
		}
	}

	// Test 50% sampling (approximate)
	sampler = NewProbabilitySampler(0.5)
	sampledCount := 0
	for i := 0; i < 1000; i++ {
		if sampler.ShouldSample(context.Background(), fmt.Sprintf("trace_%d", i), "operation") {
			sampledCount++
		}
	}

	// Should be approximately 50% (allow 10% variance)
	if sampledCount < 400 || sampledCount > 600 {
		t.Errorf("50%% sampling should result in ~500 samples, got %d", sampledCount)
	}
}

func TestStructuredLogger_Basic(t *testing.T) {
	config := DefaultLoggingConfig()
	logger := NewStructuredLogger(config)

	if logger == nil {
		t.Fatal("Expected non-nil logger")
	}

	// Test basic logging methods
	logger.Debug("Debug message", String("key", "value"))
	logger.Info("Info message", Int("count", 42))
	logger.Warn("Warning message", Bool("flag", true))
	logger.Error("Error message", Duration("timeout", 5*time.Second))
}

func TestStructuredLogger_WithFields(t *testing.T) {
	config := DefaultLoggingConfig()
	logger := NewStructuredLogger(config)

	// Test With method
	childLogger := logger.With(
		String("service", "test"),
		String("version", "1.0.0"),
	)

	if childLogger == logger {
		t.Error("With should return a new logger instance")
	}

	// Test WithContext
	ctx := context.Background()
	contextLogger := logger.WithContext(ctx)

	if contextLogger == logger {
		t.Error("WithContext should return a new logger instance")
	}
}

func TestStructuredLogger_WithRequest(t *testing.T) {
	config := DefaultLoggingConfig()
	logger := NewStructuredLogger(config)

	req := &Request{
		ID:         "req_123",
		Method:     "GET",
		Path:       "/api/users",
		UserAgent:  "Test Agent",
		RemoteAddr: "192.168.1.1",
		Context: map[string]interface{}{
			"user_id":   "user_456",
			"tenant_id": "tenant_789",
		},
	}

	reqLogger := logger.WithRequest(req)

	if reqLogger == Logger(logger) {
		t.Error("WithRequest should return a new logger instance")
	}

	reqLogger.Info("Request processed")
}

func TestAdvancedMetricsCollector_Counter(t *testing.T) {
	config := DefaultMetricsConfig()
	collector := NewAdvancedMetricsCollector(config)

	counter := collector.NewCounter("test_counter", "Test counter", map[string]string{
		"service": "test",
	})

	if counter == nil {
		t.Fatal("Expected non-nil counter")
	}

	// Test increment
	counter.Inc()
	if counter.Value() != uint64(1) {
		t.Errorf("Expected counter value 1, got %v", counter.Value())
	}

	// Test add
	counter.Add(5)
	if counter.Value() != uint64(6) {
		t.Errorf("Expected counter value 6, got %v", counter.Value())
	}

	// Test negative value (should be ignored)
	counter.Add(-1)
	if counter.Value() != uint64(6) {
		t.Error("Counter should not accept negative values")
	}
}

func TestAdvancedMetricsCollector_Gauge(t *testing.T) {
	config := DefaultMetricsConfig()
	collector := NewAdvancedMetricsCollector(config)

	gauge := collector.NewGauge("test_gauge", "Test gauge", map[string]string{
		"service": "test",
	})

	if gauge == nil {
		t.Fatal("Expected non-nil gauge")
	}

	// Test set
	gauge.Set(42.5)
	if gauge.Value() != 42.5 {
		t.Errorf("Expected gauge value 42.5, got %v", gauge.Value())
	}

	// Test increment
	gauge.Inc()
	if gauge.Value() != 43.5 {
		t.Errorf("Expected gauge value 43.5, got %v", gauge.Value())
	}

	// Test decrement
	gauge.Dec()
	if gauge.Value() != 42.5 {
		t.Errorf("Expected gauge value 42.5, got %v", gauge.Value())
	}

	// Test add
	gauge.Add(-10.5)
	if gauge.Value() != 32.0 {
		t.Errorf("Expected gauge value 32.0, got %v", gauge.Value())
	}
}

func TestAdvancedMetricsCollector_Histogram(t *testing.T) {
	config := DefaultMetricsConfig()
	collector := NewAdvancedMetricsCollector(config)

	buckets := []float64{0.1, 0.5, 1.0, 2.0, 5.0}
	histogram := collector.NewHistogram("test_histogram", "Test histogram",
		map[string]string{"service": "test"}, buckets)

	if histogram == nil {
		t.Fatal("Expected non-nil histogram")
	}

	// Test observations
	histogram.Observe(0.05) // Should go in 0.1 bucket
	histogram.Observe(0.75) // Should go in 1.0 bucket
	histogram.Observe(3.0)  // Should go in 5.0 bucket
	histogram.Observe(10.0) // Should go in +Inf bucket

	value := histogram.Value().(map[string]interface{})

	if value["count"] != uint64(4) {
		t.Errorf("Expected count 4, got %v", value["count"])
	}

	expectedSum := 0.05 + 0.75 + 3.0 + 10.0
	if value["sum"] != expectedSum {
		t.Errorf("Expected sum %f, got %v", expectedSum, value["sum"])
	}

	bucketCounts := value["buckets"].(map[string]uint64)
	if bucketCounts["0.100000"] != 1 {
		t.Error("Bucket 0.1 should have 1 observation")
	}
	if bucketCounts["1.000000"] != 2 {
		t.Error("Bucket 1.0 should have 2 observations")
	}
}

func TestAdvancedMetricsCollector_Timer(t *testing.T) {
	config := DefaultMetricsConfig()
	collector := NewAdvancedMetricsCollector(config)

	timer := collector.NewTimer("test_timer", "Test timer", map[string]string{
		"operation": "test",
	})

	if timer == nil {
		t.Fatal("Expected non-nil timer")
	}

	// Test manual timing
	timer.Start()
	time.Sleep(10 * time.Millisecond)
	duration := timer.Stop()

	if duration < 10*time.Millisecond {
		t.Error("Timer should measure at least 10ms")
	}

	// Test function timing
	duration = timer.Time(func() {
		time.Sleep(5 * time.Millisecond)
	})

	if duration < 5*time.Millisecond {
		t.Error("Timer should measure at least 5ms")
	}
}

func TestAdvancedMetricsCollector_Integration(t *testing.T) {
	config := DefaultMetricsConfig()
	collector := NewAdvancedMetricsCollector(config)

	// Test request recording
	collector.RecordRequest("test_middleware", "GET", 100*time.Millisecond, true)
	collector.RecordRequest("test_middleware", "POST", 200*time.Millisecond, false)

	// Test error recording
	collector.RecordError("test_middleware", "validation_error", "400")

	// Test cache operation recording
	collector.RecordCacheOperation("test_middleware", "get", true, 5*time.Millisecond)
	collector.RecordCacheOperation("test_middleware", "set", false, 10*time.Millisecond)

	// Test custom metrics
	collector.RecordCustomMetric("custom_gauge", 42.0, map[string]string{"type": "test"})
	collector.RecordHistogram("custom_histogram", 1.5, map[string]string{"operation": "custom"})
	collector.RecordCounter("custom_counter", 5.0, map[string]string{"source": "test"})

	// Test memory and goroutine recording
	collector.RecordMemoryUsage("test_middleware", 1024*1024)
	collector.RecordGoroutineCount("test_middleware", 10)

	// Verify metrics were recorded
	metrics := collector.GetMetrics()

	if len(metrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Test metrics by middleware
	middlewareMetrics := collector.GetMetricsByMiddleware("test_middleware")
	if len(middlewareMetrics) == 0 {
		t.Error("Expected middleware-specific metrics")
	}
}

func TestMonitoringManager_Integration(t *testing.T) {
	config := DefaultMonitoringConfig()
	config.HealthCheck.Port = 9091 // Use different port for testing
	config.Profiling.Port = 6061   // Use different port for testing

	manager := NewMonitoringManager(config)

	if manager == nil {
		t.Fatal("Expected non-nil monitoring manager")
	}

	// Test component access
	if manager.GetTraceManager() == nil {
		t.Error("Expected trace manager to be initialized")
	}

	if manager.GetLogger() == nil {
		t.Error("Expected logger to be initialized")
	}

	if manager.GetMetricsCollector() == nil {
		t.Error("Expected metrics collector to be initialized")
	}
}

func TestMonitoringMiddleware_Integration(t *testing.T) {
	config := DefaultMonitoringConfig()
	manager := NewMonitoringManager(config)
	middleware := NewMonitoringMiddleware(manager)

	// Create test request
	req := &Request{
		ID:         "test_req_123",
		Method:     "GET",
		Path:       "/api/test",
		UserAgent:  "Test Agent",
		RemoteAddr: "127.0.0.1",
		Body:       []byte(`{"test": true}`),
		Context: map[string]interface{}{
			"user_id": "user_123",
		},
	}

	// Test successful request
	resp, err := middleware.Handle(context.Background(), req, func(ctx context.Context, req *Request) (*Response, error) {
		return &Response{
			StatusCode: 200,
			Body:       []byte(`{"success": true}`),
			Headers:    make(map[string][]string),
		}, nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if resp == nil || resp.StatusCode != 200 {
		t.Error("Expected successful response")
	}

	// Test error request
	testError := fmt.Errorf("test error")
	resp, err = middleware.Handle(context.Background(), req, func(ctx context.Context, req *Request) (*Response, error) {
		return nil, testError
	})

	if err != testError {
		t.Errorf("Expected test error, got %v", err)
	}

	// Verify metrics were recorded
	metrics := manager.GetMetricsCollector().GetMetrics()
	if len(metrics) == 0 {
		t.Error("Expected metrics to be recorded by middleware")
	}
}

func TestHealthChecks(t *testing.T) {
	// Test framework health check
	framework := createMonitoringTestFramework(t)
	defer framework.Stop()

	healthCheck := NewFrameworkHealthCheck(framework)

	if healthCheck.Name() != "framework" {
		t.Error("Expected framework health check name")
	}

	err := healthCheck.Check(context.Background())
	if err != nil {
		t.Errorf("Framework health check should pass, got error: %v", err)
	}

	// Test database health check
	dbCheck := NewDatabaseHealthCheck("database", func(ctx context.Context) error {
		return nil // Simulate healthy database
	})

	if dbCheck.Name() != "database" {
		t.Error("Expected database health check name")
	}

	err = dbCheck.Check(context.Background())
	if err != nil {
		t.Errorf("Database health check should pass, got error: %v", err)
	}

	// Test failing health check
	failingCheck := NewDatabaseHealthCheck("failing_db", func(ctx context.Context) error {
		return fmt.Errorf("connection failed")
	})

	err = failingCheck.Check(context.Background())
	if err == nil {
		t.Error("Failing health check should return error")
	}
}

// Helper function to create test framework for monitoring tests
func createMonitoringTestFramework(t *testing.T) FrameworkCore {
	config := &FrameworkConfig{
		Name:        "test-monitoring-framework",
		Version:     "1.0.0",
		Environment: "test",
		LogLevel:    "info",
	}

	framework := NewCoreEngine()
	err := framework.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	err = framework.Start()
	if err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}

	return framework
}

// Benchmark tests
func BenchmarkTraceManager_StartFinishSpan(b *testing.B) {
	traceManager := NewTraceManager(DefaultTracingConfig())
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span, _ := traceManager.StartSpan(ctx, "benchmark_operation")
		traceManager.FinishSpan(span)
	}
}

func BenchmarkAdvancedMetricsCollector_CounterInc(b *testing.B) {
	collector := NewAdvancedMetricsCollector(DefaultMetricsConfig())
	counter := collector.NewCounter("benchmark_counter", "Benchmark counter", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		counter.Inc()
	}
}

func BenchmarkAdvancedMetricsCollector_HistogramObserve(b *testing.B) {
	collector := NewAdvancedMetricsCollector(DefaultMetricsConfig())
	histogram := collector.NewHistogram("benchmark_histogram", "Benchmark histogram", nil, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		histogram.Observe(float64(i%1000) / 1000.0)
	}
}

func BenchmarkStructuredLogger_Info(b *testing.B) {
	config := DefaultLoggingConfig()
	logger := NewStructuredLogger(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("Benchmark log message",
			String("iteration", fmt.Sprintf("%d", i)),
			Int("value", i),
		)
	}
}
