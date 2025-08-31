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
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
	"github.com/coder-lulu/newbee-common/middleware/types"
)

// MetricsCollector defines the interface for collecting metrics
type MetricsCollector interface {
	// Request metrics
	RecordRequest(middleware, method string, duration time.Duration, success bool)
	RecordError(middleware, errorType, errorCode string)

	// Performance metrics
	RecordMemoryUsage(middleware string, bytes int64)
	RecordCacheOperation(middleware, operation string, hit bool, duration time.Duration)
	RecordCircuitBreakerState(middleware, name string, state types.CircuitBreakerState)

	// System metrics
	RecordGoroutineCount(count int)
	RecordGCStats(pauseNs int64, numGC uint32)

	// Custom metrics
	RecordCustomMetric(name string, value float64, labels map[string]string)

	// Export metrics for monitoring systems
	Export() map[string]interface{}
	Reset()
}

// MiddlewareMetrics holds performance metrics for middlewares
type MiddlewareMetrics struct {
	// Request metrics
	RequestCount    int64         `json:"request_count"`
	RequestDuration time.Duration `json:"avg_request_duration"`
	ErrorCount      int64         `json:"error_count"`
	ErrorRate       float64       `json:"error_rate"`

	// Performance metrics
	MemoryUsage     int64   `json:"memory_usage_bytes"`
	CacheHitRate    float64 `json:"cache_hit_rate"`
	CacheOperations int64   `json:"cache_operations"`

	// Circuit breaker stats
	CircuitBreakerOpen int64 `json:"circuit_breaker_open_count"`

	// Detailed breakdowns
	ErrorBreakdown    map[string]int64 `json:"error_breakdown"`
	MethodBreakdown   map[string]int64 `json:"method_breakdown"`
	DurationHistogram []float64        `json:"duration_histogram"`

	// Timestamps
	LastUpdated time.Time `json:"last_updated"`
	StartTime   time.Time `json:"start_time"`
}

// NewMiddlewareMetrics creates a new metrics instance
func NewMiddlewareMetrics() *MiddlewareMetrics {
	now := time.Now()
	return &MiddlewareMetrics{
		ErrorBreakdown:    make(map[string]int64),
		MethodBreakdown:   make(map[string]int64),
		DurationHistogram: make([]float64, 0, 1000), // Pre-allocate for performance
		LastUpdated:       now,
		StartTime:         now,
	}
}

// InMemoryMetricsCollector implements MetricsCollector using in-memory storage
type InMemoryMetricsCollector struct {
	mu          sync.RWMutex
	metrics     map[string]*MiddlewareMetrics
	systemStats *SystemMetrics

	// Performance optimization: atomic counters for hot paths
	totalRequests int64
	totalErrors   int64

	// Configuration
	config *MetricsConfig
}

// SystemMetrics holds system-wide performance metrics
type SystemMetrics struct {
	GoroutineCount int64     `json:"goroutine_count"`
	GCPauseNs      int64     `json:"gc_pause_ns"`
	GCCount        uint32    `json:"gc_count"`
	LastGCTime     time.Time `json:"last_gc_time"`

	// Memory stats
	HeapInUse    int64 `json:"heap_in_use_bytes"`
	HeapReleased int64 `json:"heap_released_bytes"`
	StackInUse   int64 `json:"stack_in_use_bytes"`

	// Custom metrics
	CustomMetrics map[string]MetricValue `json:"custom_metrics"`
}

// MetricValue represents a custom metric with labels
type MetricValue struct {
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
}

// MetricsConfig defines configuration for metrics collection
type MetricsConfig struct {
	// Collection settings
	EnableCollection   bool          `json:"enable_collection"`
	CollectionInterval time.Duration `json:"collection_interval"`
	RetentionDuration  time.Duration `json:"retention_duration"`

	// Performance settings
	MaxHistogramSize int     `json:"max_histogram_size"`
	SamplingRate     float64 `json:"sampling_rate"`
	EnableGCMetrics  bool    `json:"enable_gc_metrics"`

	// Alert thresholds
	ErrorRateThreshold float64       `json:"error_rate_threshold"`
	LatencyThreshold   time.Duration `json:"latency_threshold"`
	MemoryThreshold    int64         `json:"memory_threshold_bytes"`

	// Export settings
	PrometheusEnabled bool   `json:"prometheus_enabled"`
	PrometheusPrefix  string `json:"prometheus_prefix"`
	MetricsEndpoint   string `json:"metrics_endpoint"`
}

// DefaultMetricsConfig returns default metrics configuration
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		EnableCollection:   true,
		CollectionInterval: 30 * time.Second,
		RetentionDuration:  24 * time.Hour,
		MaxHistogramSize:   1000,
		SamplingRate:       1.0, // 100% sampling by default
		EnableGCMetrics:    true,
		ErrorRateThreshold: 0.05, // 5% error rate threshold
		LatencyThreshold:   500 * time.Millisecond,
		MemoryThreshold:    100 * 1024 * 1024, // 100MB
		PrometheusEnabled:  false,
		PrometheusPrefix:   "newbee_middleware_",
		MetricsEndpoint:    "/metrics",
	}
}

// NewInMemoryMetricsCollector creates a new in-memory metrics collector
func NewInMemoryMetricsCollector(config *MetricsConfig) *InMemoryMetricsCollector {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	collector := &InMemoryMetricsCollector{
		metrics: make(map[string]*MiddlewareMetrics),
		systemStats: &SystemMetrics{
			CustomMetrics: make(map[string]MetricValue),
		},
		config: config,
	}

	logx.Infow("Metrics collector initialized",
		logx.Field("collectionInterval", config.CollectionInterval),
		logx.Field("enableGCMetrics", config.EnableGCMetrics),
		logx.Field("samplingRate", config.SamplingRate))

	return collector
}

// RecordRequest records a request metric
func (c *InMemoryMetricsCollector) RecordRequest(middleware, method string, duration time.Duration, success bool) {
	if !c.config.EnableCollection {
		return
	}

	// Fast path: update atomic counters
	atomic.AddInt64(&c.totalRequests, 1)
	if !success {
		atomic.AddInt64(&c.totalErrors, 1)
	}

	// Sampling for detailed metrics
	if c.shouldSample() {
		c.mu.Lock()
		defer c.mu.Unlock()

		metrics := c.getOrCreateMetrics(middleware)
		metrics.RequestCount++
		metrics.MethodBreakdown[method]++

		// Update duration using exponential moving average
		if metrics.RequestDuration == 0 {
			metrics.RequestDuration = duration
		} else {
			// EMA with alpha = 0.1
			alpha := 0.1
			metrics.RequestDuration = time.Duration(
				alpha*float64(duration) + (1-alpha)*float64(metrics.RequestDuration),
			)
		}

		// Add to histogram if within size limit
		if len(metrics.DurationHistogram) < c.config.MaxHistogramSize {
			metrics.DurationHistogram = append(metrics.DurationHistogram, duration.Seconds())
		}

		if !success {
			metrics.ErrorCount++
		}

		// Calculate error rate
		if metrics.RequestCount > 0 {
			metrics.ErrorRate = float64(metrics.ErrorCount) / float64(metrics.RequestCount)
		}

		metrics.LastUpdated = time.Now()
	}
}

// RecordError records an error metric
func (c *InMemoryMetricsCollector) RecordError(middleware, errorType, errorCode string) {
	if !c.config.EnableCollection {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	metrics := c.getOrCreateMetrics(middleware)
	errorKey := errorType + ":" + errorCode
	metrics.ErrorBreakdown[errorKey]++
	metrics.LastUpdated = time.Now()
}

// RecordMemoryUsage records memory usage metric
func (c *InMemoryMetricsCollector) RecordMemoryUsage(middleware string, bytes int64) {
	if !c.config.EnableCollection {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	metrics := c.getOrCreateMetrics(middleware)
	metrics.MemoryUsage = bytes
	metrics.LastUpdated = time.Now()
}

// RecordCacheOperation records cache operation metrics
func (c *InMemoryMetricsCollector) RecordCacheOperation(middleware, operation string, hit bool, duration time.Duration) {
	if !c.config.EnableCollection {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	metrics := c.getOrCreateMetrics(middleware)
	metrics.CacheOperations++

	// Update hit rate using exponential moving average
	hitValue := 0.0
	if hit {
		hitValue = 1.0
	}

	if metrics.CacheOperations == 1 {
		metrics.CacheHitRate = hitValue
	} else {
		alpha := 0.1
		metrics.CacheHitRate = alpha*hitValue + (1-alpha)*metrics.CacheHitRate
	}

	metrics.LastUpdated = time.Now()
}

// RecordCircuitBreakerState records circuit breaker state changes
func (c *InMemoryMetricsCollector) RecordCircuitBreakerState(middleware, name string, state types.CircuitBreakerState) {
	if !c.config.EnableCollection {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	metrics := c.getOrCreateMetrics(middleware)
	if state == 1 { // StateOpen equivalent
		metrics.CircuitBreakerOpen++
	}
	metrics.LastUpdated = time.Now()
}

// RecordGoroutineCount records the current goroutine count
func (c *InMemoryMetricsCollector) RecordGoroutineCount(count int) {
	if !c.config.EnableCollection {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.systemStats.GoroutineCount = int64(count)
}

// RecordGCStats records garbage collection statistics
func (c *InMemoryMetricsCollector) RecordGCStats(pauseNs int64, numGC uint32) {
	if !c.config.EnableCollection || !c.config.EnableGCMetrics {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.systemStats.GCPauseNs = pauseNs
	c.systemStats.GCCount = numGC
	c.systemStats.LastGCTime = time.Now()
}

// RecordCustomMetric records a custom metric with labels
func (c *InMemoryMetricsCollector) RecordCustomMetric(name string, value float64, labels map[string]string) {
	if !c.config.EnableCollection {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.systemStats.CustomMetrics[name] = MetricValue{
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
}

// Export exports all metrics for monitoring systems
func (c *InMemoryMetricsCollector) Export() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]interface{})
	result["middleware_metrics"] = c.metrics
	result["system_metrics"] = c.systemStats
	result["total_requests"] = atomic.LoadInt64(&c.totalRequests)
	result["total_errors"] = atomic.LoadInt64(&c.totalErrors)

	// Calculate overall error rate
	totalReqs := atomic.LoadInt64(&c.totalRequests)
	if totalReqs > 0 {
		result["overall_error_rate"] = float64(atomic.LoadInt64(&c.totalErrors)) / float64(totalReqs)
	}

	result["export_time"] = time.Now()
	return result
}

// Reset clears all metrics
func (c *InMemoryMetricsCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset metrics maps
	c.metrics = make(map[string]*MiddlewareMetrics)
	c.systemStats = &SystemMetrics{
		CustomMetrics: make(map[string]MetricValue),
	}

	// Reset atomic counters
	atomic.StoreInt64(&c.totalRequests, 0)
	atomic.StoreInt64(&c.totalErrors, 0)

	logx.Info("Metrics collector reset")
}

// getOrCreateMetrics gets or creates metrics for a middleware
func (c *InMemoryMetricsCollector) getOrCreateMetrics(middleware string) *MiddlewareMetrics {
	if metrics, exists := c.metrics[middleware]; exists {
		return metrics
	}

	metrics := NewMiddlewareMetrics()
	c.metrics[middleware] = metrics
	return metrics
}

// shouldSample determines if this request should be sampled
func (c *InMemoryMetricsCollector) shouldSample() bool {
	if c.config.SamplingRate >= 1.0 {
		return true
	}

	// Simple sampling based on request count
	reqCount := atomic.LoadInt64(&c.totalRequests)
	return float64(reqCount%100)/100.0 < c.config.SamplingRate
}

// GetMetrics returns metrics for a specific middleware
func (c *InMemoryMetricsCollector) GetMetrics(middleware string) *MiddlewareMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if metrics, exists := c.metrics[middleware]; exists {
		// Return a copy to prevent race conditions
		metricsCopy := *metrics
		metricsCopy.ErrorBreakdown = make(map[string]int64)
		metricsCopy.MethodBreakdown = make(map[string]int64)

		for k, v := range metrics.ErrorBreakdown {
			metricsCopy.ErrorBreakdown[k] = v
		}
		for k, v := range metrics.MethodBreakdown {
			metricsCopy.MethodBreakdown[k] = v
		}

		return &metricsCopy
	}

	return NewMiddlewareMetrics()
}

// GetSystemMetrics returns system-wide metrics
func (c *InMemoryMetricsCollector) GetSystemMetrics() *SystemMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy
	statsCopy := *c.systemStats
	statsCopy.CustomMetrics = make(map[string]MetricValue)
	for k, v := range c.systemStats.CustomMetrics {
		statsCopy.CustomMetrics[k] = v
	}

	return &statsCopy
}

// CheckThresholds checks if any metrics exceed configured thresholds
func (c *InMemoryMetricsCollector) CheckThresholds() []AlertCondition {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var alerts []AlertCondition

	// Check overall error rate
	totalReqs := atomic.LoadInt64(&c.totalRequests)
	if totalReqs > 0 {
		errorRate := float64(atomic.LoadInt64(&c.totalErrors)) / float64(totalReqs)
		if errorRate > c.config.ErrorRateThreshold {
			alerts = append(alerts, AlertCondition{
				Type:       "error_rate",
				Middleware: "overall",
				Threshold:  c.config.ErrorRateThreshold,
				Current:    errorRate,
				Message:    "Overall error rate exceeds threshold",
				Severity:   "high",
				Timestamp:  time.Now(),
			})
		}
	}

	// Check individual middleware metrics
	for middleware, metrics := range c.metrics {
		// Error rate threshold
		if metrics.ErrorRate > c.config.ErrorRateThreshold {
			alerts = append(alerts, AlertCondition{
				Type:       "error_rate",
				Middleware: middleware,
				Threshold:  c.config.ErrorRateThreshold,
				Current:    metrics.ErrorRate,
				Message:    "Middleware error rate exceeds threshold",
				Severity:   "high",
				Timestamp:  time.Now(),
			})
		}

		// Latency threshold
		if metrics.RequestDuration > c.config.LatencyThreshold {
			alerts = append(alerts, AlertCondition{
				Type:       "latency",
				Middleware: middleware,
				Threshold:  float64(c.config.LatencyThreshold.Milliseconds()),
				Current:    float64(metrics.RequestDuration.Milliseconds()),
				Message:    "Middleware latency exceeds threshold",
				Severity:   "medium",
				Timestamp:  time.Now(),
			})
		}

		// Memory threshold
		if metrics.MemoryUsage > c.config.MemoryThreshold {
			alerts = append(alerts, AlertCondition{
				Type:       "memory",
				Middleware: middleware,
				Threshold:  float64(c.config.MemoryThreshold),
				Current:    float64(metrics.MemoryUsage),
				Message:    "Middleware memory usage exceeds threshold",
				Severity:   "medium",
				Timestamp:  time.Now(),
			})
		}
	}

	return alerts
}

// AlertCondition represents an alert condition that has been triggered
type AlertCondition struct {
	Type       string    `json:"type"`
	Middleware string    `json:"middleware"`
	Threshold  float64   `json:"threshold"`
	Current    float64   `json:"current"`
	Message    string    `json:"message"`
	Severity   string    `json:"severity"` // low, medium, high, critical
	Timestamp  time.Time `json:"timestamp"`
}

// Global metrics collector instance
var (
	defaultMetricsCollector MetricsCollector
	metricsOnce             sync.Once
)

// GetDefaultMetricsCollector returns the default metrics collector instance
func GetDefaultMetricsCollector() MetricsCollector {
	metricsOnce.Do(func() {
		defaultMetricsCollector = NewInMemoryMetricsCollector(DefaultMetricsConfig())
	})
	return defaultMetricsCollector
}

// SetDefaultMetricsCollector sets the default metrics collector
func SetDefaultMetricsCollector(collector MetricsCollector) {
	defaultMetricsCollector = collector
}
