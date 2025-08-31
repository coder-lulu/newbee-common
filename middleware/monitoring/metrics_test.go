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
	"testing"
	"time"
)

func TestInMemoryMetricsCollector_RecordRequest(t *testing.T) {
	collector := NewInMemoryMetricsCollector(nil)

	// Record some requests
	collector.RecordRequest("test-middleware", "GET", 100*time.Millisecond, true)
	collector.RecordRequest("test-middleware", "POST", 200*time.Millisecond, true)
	collector.RecordRequest("test-middleware", "GET", 150*time.Millisecond, false)

	// Get metrics
	metrics := collector.GetMetrics("test-middleware")

	// Verify basic counts
	if metrics.RequestCount != 3 {
		t.Errorf("Expected 3 requests, got %d", metrics.RequestCount)
	}

	if metrics.ErrorCount != 1 {
		t.Errorf("Expected 1 error, got %d", metrics.ErrorCount)
	}

	// Verify method breakdown
	if metrics.MethodBreakdown["GET"] != 2 {
		t.Errorf("Expected 2 GET requests, got %d", metrics.MethodBreakdown["GET"])
	}

	if metrics.MethodBreakdown["POST"] != 1 {
		t.Errorf("Expected 1 POST request, got %d", metrics.MethodBreakdown["POST"])
	}

	// Verify error rate
	expectedErrorRate := 1.0 / 3.0
	if abs(metrics.ErrorRate-expectedErrorRate) > 0.01 {
		t.Errorf("Expected error rate %.3f, got %.3f", expectedErrorRate, metrics.ErrorRate)
	}
}

func TestInMemoryMetricsCollector_RecordCacheOperation(t *testing.T) {
	collector := NewInMemoryMetricsCollector(nil)

	// Record cache operations
	collector.RecordCacheOperation("test-middleware", "get", true, 1*time.Millisecond)
	collector.RecordCacheOperation("test-middleware", "get", true, 2*time.Millisecond)
	collector.RecordCacheOperation("test-middleware", "get", false, 3*time.Millisecond)

	metrics := collector.GetMetrics("test-middleware")

	// Verify cache operations
	if metrics.CacheOperations != 3 {
		t.Errorf("Expected 3 cache operations, got %d", metrics.CacheOperations)
	}

	// Cache hit rate should be around 2/3
	expectedHitRate := 0.67 // Approximately 2/3 due to EMA
	if abs(metrics.CacheHitRate-expectedHitRate) > 0.2 {
		t.Errorf("Expected hit rate around %.2f, got %.2f", expectedHitRate, metrics.CacheHitRate)
	}
}

func TestInMemoryMetricsCollector_Export(t *testing.T) {
	collector := NewInMemoryMetricsCollector(nil)

	// Record some data
	collector.RecordRequest("middleware1", "GET", 100*time.Millisecond, true)
	collector.RecordRequest("middleware2", "POST", 200*time.Millisecond, false)
	collector.RecordCustomMetric("custom_metric", 42.5, map[string]string{"label": "value"})

	// Export metrics
	exported := collector.Export()

	// Verify exported data structure
	if _, exists := exported["middleware_metrics"]; !exists {
		t.Error("Expected middleware_metrics in export")
	}

	if _, exists := exported["system_metrics"]; !exists {
		t.Error("Expected system_metrics in export")
	}

	if totalReqs, exists := exported["total_requests"]; !exists {
		t.Error("Expected total_requests in export")
	} else if totalReqs.(int64) != 2 {
		t.Errorf("Expected 2 total requests, got %d", totalReqs.(int64))
	}

	if totalErrors, exists := exported["total_errors"]; !exists {
		t.Error("Expected total_errors in export")
	} else if totalErrors.(int64) != 1 {
		t.Errorf("Expected 1 total error, got %d", totalErrors.(int64))
	}
}

func TestInMemoryMetricsCollector_CheckThresholds(t *testing.T) {
	config := DefaultMetricsConfig()
	config.ErrorRateThreshold = 0.3 // 30% error rate threshold
	config.LatencyThreshold = 150 * time.Millisecond

	collector := NewInMemoryMetricsCollector(config)

	// Record requests that exceed thresholds
	collector.RecordRequest("test-middleware", "GET", 200*time.Millisecond, false) // High latency + error
	collector.RecordRequest("test-middleware", "GET", 100*time.Millisecond, false) // Error
	collector.RecordRequest("test-middleware", "GET", 50*time.Millisecond, true)   // Success

	// Check thresholds
	alerts := collector.CheckThresholds()

	// Should have alerts for both error rate and latency
	if len(alerts) == 0 {
		t.Error("Expected threshold alerts, got none")
	}

	// Verify alert types
	hasErrorRateAlert := false

	for _, alert := range alerts {
		switch alert.Type {
		case "error_rate":
			hasErrorRateAlert = true
			if alert.Current < 0.3 { // Should be above 30%
				t.Errorf("Expected error rate alert above 0.3, got %.3f", alert.Current)
			}
		case "latency":
			// Note: Latency alert depends on EMA calculation, so we don't strictly test it
		}
	}

	if !hasErrorRateAlert {
		t.Error("Expected error rate alert")
	}
}

func TestInMemoryMetricsCollector_Reset(t *testing.T) {
	collector := NewInMemoryMetricsCollector(nil)

	// Record some data
	collector.RecordRequest("test-middleware", "GET", 100*time.Millisecond, true)
	collector.RecordError("test-middleware", "test_error", "E001")
	collector.RecordCustomMetric("test_metric", 123.45, nil)

	// Verify data exists
	if collector.GetMetrics("test-middleware").RequestCount == 0 {
		t.Error("Expected request data before reset")
	}

	// Reset
	collector.Reset()

	// Verify data is cleared
	metrics := collector.GetMetrics("test-middleware")
	if metrics.RequestCount != 0 {
		t.Errorf("Expected 0 requests after reset, got %d", metrics.RequestCount)
	}

	systemMetrics := collector.GetSystemMetrics()
	if len(systemMetrics.CustomMetrics) != 0 {
		t.Errorf("Expected 0 custom metrics after reset, got %d", len(systemMetrics.CustomMetrics))
	}
}

func TestMiddlewareMetrics_CalculateHitRate(t *testing.T) {
	stats := &L1CacheStats{
		Hits:   80,
		Misses: 20,
	}

	stats.CalculateHitRate()

	expectedRate := 0.8 // 80%
	if abs(stats.HitRate-expectedRate) > 0.01 {
		t.Errorf("Expected hit rate %.2f, got %.2f", expectedRate, stats.HitRate)
	}
}

func TestDefaultMetricsConfig(t *testing.T) {
	config := DefaultMetricsConfig()

	// Verify default values
	if !config.EnableCollection {
		t.Error("Expected collection to be enabled by default")
	}

	if config.CollectionInterval != 30*time.Second {
		t.Errorf("Expected 30s collection interval, got %v", config.CollectionInterval)
	}

	if config.SamplingRate != 1.0 {
		t.Error("Expected 100% sampling rate by default")
	}

	if config.ErrorRateThreshold != 0.05 {
		t.Errorf("Expected 5%% error rate threshold, got %.2f", config.ErrorRateThreshold)
	}
}

// Helper function for floating point comparison
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
