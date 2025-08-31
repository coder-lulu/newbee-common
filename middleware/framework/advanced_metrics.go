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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AdvancedMetricsCollector provides comprehensive metrics collection
type AdvancedMetricsCollector struct {
	config     *MetricsConfig
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	summaries  map[string]*Summary
	timers     map[string]*Timer
	mutex      sync.RWMutex
	enabled    bool
	exporters  []MetricsExporter
	registry   *MetricsRegistry
}

// MetricsConfig defines metrics configuration
type MetricsConfig struct {
	Enabled            bool                `json:"enabled" yaml:"enabled"`
	Namespace          string              `json:"namespace" yaml:"namespace"`
	Subsystem          string              `json:"subsystem" yaml:"subsystem"`
	DefaultLabels      map[string]string   `json:"default_labels" yaml:"default_labels"`
	CollectionInterval time.Duration       `json:"collection_interval" yaml:"collection_interval"`
	RetentionPeriod    time.Duration       `json:"retention_period" yaml:"retention_period"`
	HistogramBuckets   []float64           `json:"histogram_buckets" yaml:"histogram_buckets"`
	SummaryObjectives  map[float64]float64 `json:"summary_objectives" yaml:"summary_objectives"`
	EnableGC           bool                `json:"enable_gc" yaml:"enable_gc"`
	EnableRuntime      bool                `json:"enable_runtime" yaml:"enable_runtime"`
	EnableProcess      bool                `json:"enable_process" yaml:"enable_process"`
	Cardinality        *CardinalityConfig  `json:"cardinality" yaml:"cardinality"`
}

// CardinalityConfig defines cardinality limits
type CardinalityConfig struct {
	MaxSeries          int `json:"max_series" yaml:"max_series"`
	MaxLabelValues     int `json:"max_label_values" yaml:"max_label_values"`
	MaxLabelNameLength int `json:"max_label_name_length" yaml:"max_label_name_length"`
}

// Counter represents a monotonically increasing counter
type Counter struct {
	name   string
	help   string
	labels map[string]string
	value  uint64
	mutex  sync.RWMutex
}

// Gauge represents a gauge metric
type Gauge struct {
	name   string
	help   string
	labels map[string]string
	value  float64
	mutex  sync.RWMutex
}

// Histogram represents a histogram metric
type Histogram struct {
	name    string
	help    string
	labels  map[string]string
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
	mutex   sync.RWMutex
}

// Summary represents a summary metric with quantiles
type Summary struct {
	name       string
	help       string
	labels     map[string]string
	objectives map[float64]float64
	samples    []float64
	sum        float64
	count      uint64
	maxAge     time.Duration
	mutex      sync.RWMutex
}

// Timer represents a timer metric
type Timer struct {
	name      string
	help      string
	labels    map[string]string
	histogram *Histogram
	startTime time.Time
	mutex     sync.RWMutex
}

// MetricsRegistry manages metric registration and deduplication
type MetricsRegistry struct {
	metrics map[string]Metric
	mutex   sync.RWMutex
}

// Metric interface for all metric types
type Metric interface {
	Name() string
	Help() string
	Labels() map[string]string
	Type() MetricType
	Value() interface{}
}

// MetricType represents the type of metric
type MetricType int

const (
	CounterType MetricType = iota
	GaugeType
	HistogramType
	SummaryType
	TimerType
)

func (mt MetricType) String() string {
	switch mt {
	case CounterType:
		return "counter"
	case GaugeType:
		return "gauge"
	case HistogramType:
		return "histogram"
	case SummaryType:
		return "summary"
	case TimerType:
		return "timer"
	default:
		return "unknown"
	}
}

// MetricsExporter exports metrics to external systems
type MetricsExporter interface {
	Export(ctx context.Context, metrics []Metric) error
	Shutdown(ctx context.Context) error
}

// NewAdvancedMetricsCollector creates a new advanced metrics collector
func NewAdvancedMetricsCollector(config *MetricsConfig) *AdvancedMetricsCollector {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	amc := &AdvancedMetricsCollector{
		config:     config,
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		summaries:  make(map[string]*Summary),
		timers:     make(map[string]*Timer),
		enabled:    config.Enabled,
		exporters:  make([]MetricsExporter, 0),
		registry:   NewMetricsRegistry(),
	}

	// Start background collection if enabled
	if amc.enabled {
		go amc.collectRuntimeMetrics()
	}

	return amc
}

// DefaultMetricsConfig returns default metrics configuration
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled:            true,
		Namespace:          "middleware",
		Subsystem:          "framework",
		DefaultLabels:      make(map[string]string),
		CollectionInterval: 15 * time.Second,
		RetentionPeriod:    24 * time.Hour,
		HistogramBuckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		SummaryObjectives: map[float64]float64{
			0.5:  0.05,
			0.9:  0.01,
			0.95: 0.005,
			0.99: 0.001,
		},
		EnableGC:      true,
		EnableRuntime: true,
		EnableProcess: true,
		Cardinality: &CardinalityConfig{
			MaxSeries:          100000,
			MaxLabelValues:     10000,
			MaxLabelNameLength: 255,
		},
	}
}

// NewMetricsRegistry creates a new metrics registry
func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		metrics: make(map[string]Metric),
	}
}

// Counter implementation

// NewCounter creates a new counter
func (amc *AdvancedMetricsCollector) NewCounter(name, help string, labels map[string]string) *Counter {
	if !amc.enabled {
		return &Counter{}
	}

	fullName := amc.buildMetricName(name)
	labelKey := amc.buildLabelKey(fullName, labels)

	amc.mutex.Lock()
	defer amc.mutex.Unlock()

	if counter, exists := amc.counters[labelKey]; exists {
		return counter
	}

	counter := &Counter{
		name:   fullName,
		help:   help,
		labels: amc.mergeLabels(labels),
	}

	amc.counters[labelKey] = counter
	amc.registry.Register(counter)

	return counter
}

// Inc increments the counter by 1
func (c *Counter) Inc() {
	c.Add(1)
}

// Add adds the given value to the counter
func (c *Counter) Add(value float64) {
	if value < 0 {
		return // Counters cannot decrease
	}
	atomic.AddUint64(&c.value, uint64(value))
}

// Value returns the current counter value
func (c *Counter) Value() interface{} {
	return atomic.LoadUint64(&c.value)
}

// Name returns the counter name
func (c *Counter) Name() string { return c.name }

// Help returns the counter help text
func (c *Counter) Help() string { return c.help }

// Labels returns the counter labels
func (c *Counter) Labels() map[string]string { return c.labels }

// Type returns the metric type
func (c *Counter) Type() MetricType { return CounterType }

// Gauge implementation

// NewGauge creates a new gauge
func (amc *AdvancedMetricsCollector) NewGauge(name, help string, labels map[string]string) *Gauge {
	if !amc.enabled {
		return &Gauge{}
	}

	fullName := amc.buildMetricName(name)
	labelKey := amc.buildLabelKey(fullName, labels)

	amc.mutex.Lock()
	defer amc.mutex.Unlock()

	if gauge, exists := amc.gauges[labelKey]; exists {
		return gauge
	}

	gauge := &Gauge{
		name:   fullName,
		help:   help,
		labels: amc.mergeLabels(labels),
	}

	amc.gauges[labelKey] = gauge
	amc.registry.Register(gauge)

	return gauge
}

// Set sets the gauge value
func (g *Gauge) Set(value float64) {
	g.mutex.Lock()
	g.value = value
	g.mutex.Unlock()
}

// Inc increments the gauge by 1
func (g *Gauge) Inc() {
	g.Add(1)
}

// Dec decrements the gauge by 1
func (g *Gauge) Dec() {
	g.Add(-1)
}

// Add adds the given value to the gauge
func (g *Gauge) Add(value float64) {
	g.mutex.Lock()
	g.value += value
	g.mutex.Unlock()
}

// Value returns the current gauge value
func (g *Gauge) Value() interface{} {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.value
}

// Name returns the gauge name
func (g *Gauge) Name() string { return g.name }

// Help returns the gauge help text
func (g *Gauge) Help() string { return g.help }

// Labels returns the gauge labels
func (g *Gauge) Labels() map[string]string { return g.labels }

// Type returns the metric type
func (g *Gauge) Type() MetricType { return GaugeType }

// Histogram implementation

// NewHistogram creates a new histogram
func (amc *AdvancedMetricsCollector) NewHistogram(name, help string, labels map[string]string, buckets []float64) *Histogram {
	if !amc.enabled {
		return &Histogram{}
	}

	if buckets == nil {
		buckets = amc.config.HistogramBuckets
	}

	fullName := amc.buildMetricName(name)
	labelKey := amc.buildLabelKey(fullName, labels)

	amc.mutex.Lock()
	defer amc.mutex.Unlock()

	if histogram, exists := amc.histograms[labelKey]; exists {
		return histogram
	}

	// Sort buckets
	sort.Float64s(buckets)

	histogram := &Histogram{
		name:    fullName,
		help:    help,
		labels:  amc.mergeLabels(labels),
		buckets: buckets,
		counts:  make([]uint64, len(buckets)+1), // +1 for +Inf bucket
	}

	amc.histograms[labelKey] = histogram
	amc.registry.Register(histogram)

	return histogram
}

// Observe records an observation
func (h *Histogram) Observe(value float64) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.sum += value
	h.count++

	// Find bucket and increment
	for i, bucket := range h.buckets {
		if value <= bucket {
			h.counts[i]++
		}
	}
	// Always increment +Inf bucket
	h.counts[len(h.buckets)]++
}

// Value returns histogram statistics
func (h *Histogram) Value() interface{} {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	return map[string]interface{}{
		"count":   h.count,
		"sum":     h.sum,
		"buckets": h.getBucketCounts(),
	}
}

// getBucketCounts returns bucket counts with their upper bounds
func (h *Histogram) getBucketCounts() map[string]uint64 {
	result := make(map[string]uint64)
	for i, bucket := range h.buckets {
		result[fmt.Sprintf("%.6f", bucket)] = h.counts[i]
	}
	result["+Inf"] = h.counts[len(h.buckets)]
	return result
}

// Name returns the histogram name
func (h *Histogram) Name() string { return h.name }

// Help returns the histogram help text
func (h *Histogram) Help() string { return h.help }

// Labels returns the histogram labels
func (h *Histogram) Labels() map[string]string { return h.labels }

// Type returns the metric type
func (h *Histogram) Type() MetricType { return HistogramType }

// Timer implementation

// NewTimer creates a new timer
func (amc *AdvancedMetricsCollector) NewTimer(name, help string, labels map[string]string) *Timer {
	if !amc.enabled {
		return &Timer{}
	}

	histogram := amc.NewHistogram(name+"_duration_seconds", help, labels, nil)

	fullName := amc.buildMetricName(name)
	labelKey := amc.buildLabelKey(fullName, labels)

	amc.mutex.Lock()
	defer amc.mutex.Unlock()

	if timer, exists := amc.timers[labelKey]; exists {
		return timer
	}

	timer := &Timer{
		name:      fullName,
		help:      help,
		labels:    amc.mergeLabels(labels),
		histogram: histogram,
	}

	amc.timers[labelKey] = timer

	return timer
}

// Start starts the timer
func (t *Timer) Start() {
	t.mutex.Lock()
	t.startTime = time.Now()
	t.mutex.Unlock()
}

// Stop stops the timer and records the duration
func (t *Timer) Stop() time.Duration {
	t.mutex.Lock()
	duration := time.Since(t.startTime)
	t.mutex.Unlock()

	if t.histogram != nil {
		t.histogram.Observe(duration.Seconds())
	}

	return duration
}

// Time times a function execution
func (t *Timer) Time(fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)

	if t.histogram != nil {
		t.histogram.Observe(duration.Seconds())
	}

	return duration
}

// Value returns timer statistics
func (t *Timer) Value() interface{} {
	if t.histogram != nil {
		return t.histogram.Value()
	}
	return nil
}

// Name returns the timer name
func (t *Timer) Name() string { return t.name }

// Help returns the timer help text
func (t *Timer) Help() string { return t.help }

// Labels returns the timer labels
func (t *Timer) Labels() map[string]string { return t.labels }

// Type returns the metric type
func (t *Timer) Type() MetricType { return TimerType }

// AdvancedMetricsCollector methods

// RecordRequest records request metrics
func (amc *AdvancedMetricsCollector) RecordRequest(middleware, method string, duration time.Duration, success bool) {
	labels := map[string]string{
		"middleware": middleware,
		"method":     method,
		"status":     "success",
	}
	if !success {
		labels["status"] = "error"
	}

	// Request counter
	counter := amc.NewCounter("requests_total", "Total number of requests", labels)
	counter.Inc()

	// Request duration histogram
	histogram := amc.NewHistogram("request_duration_seconds", "Request duration in seconds", labels, nil)
	histogram.Observe(duration.Seconds())
}

// RecordError records error metrics
func (amc *AdvancedMetricsCollector) RecordError(middleware, errorType, errorCode string) {
	labels := map[string]string{
		"middleware": middleware,
		"type":       errorType,
		"code":       errorCode,
	}

	counter := amc.NewCounter("errors_total", "Total number of errors", labels)
	counter.Inc()
}

// RecordCacheOperation records cache operation metrics
func (amc *AdvancedMetricsCollector) RecordCacheOperation(middleware, operation string, hit bool, duration time.Duration) {
	status := "miss"
	if hit {
		status = "hit"
	}

	labels := map[string]string{
		"middleware": middleware,
		"operation":  operation,
		"status":     status,
	}

	// Cache operations counter
	counter := amc.NewCounter("cache_operations_total", "Total number of cache operations", labels)
	counter.Inc()

	// Cache operation duration
	histogram := amc.NewHistogram("cache_operation_duration_seconds", "Cache operation duration", labels, nil)
	histogram.Observe(duration.Seconds())
}

// RecordCustomMetric records a custom metric
func (amc *AdvancedMetricsCollector) RecordCustomMetric(name string, value float64, tags map[string]string) {
	gauge := amc.NewGauge(name, "Custom metric", tags)
	gauge.Set(value)
}

// RecordHistogram records a histogram metric
func (amc *AdvancedMetricsCollector) RecordHistogram(name string, value float64, tags map[string]string) {
	histogram := amc.NewHistogram(name, "Custom histogram", tags, nil)
	histogram.Observe(value)
}

// RecordCounter records a counter metric
func (amc *AdvancedMetricsCollector) RecordCounter(name string, value float64, tags map[string]string) {
	counter := amc.NewCounter(name, "Custom counter", tags)
	counter.Add(value)
}

// RecordMemoryUsage records memory usage metrics
func (amc *AdvancedMetricsCollector) RecordMemoryUsage(middleware string, bytes int64) {
	labels := map[string]string{"middleware": middleware}
	gauge := amc.NewGauge("memory_usage_bytes", "Memory usage in bytes", labels)
	gauge.Set(float64(bytes))
}

// RecordGoroutineCount records goroutine count metrics
func (amc *AdvancedMetricsCollector) RecordGoroutineCount(middleware string, count int) {
	labels := map[string]string{"middleware": middleware}
	gauge := amc.NewGauge("goroutines_count", "Number of goroutines", labels)
	gauge.Set(float64(count))
}

// GetMetrics returns all collected metrics
func (amc *AdvancedMetricsCollector) GetMetrics() map[string]interface{} {
	result := make(map[string]interface{})

	amc.mutex.RLock()
	defer amc.mutex.RUnlock()

	// Collect counters
	counters := make(map[string]interface{})
	for key, counter := range amc.counters {
		counters[key] = counter.Value()
	}
	result["counters"] = counters

	// Collect gauges
	gauges := make(map[string]interface{})
	for key, gauge := range amc.gauges {
		gauges[key] = gauge.Value()
	}
	result["gauges"] = gauges

	// Collect histograms
	histograms := make(map[string]interface{})
	for key, histogram := range amc.histograms {
		histograms[key] = histogram.Value()
	}
	result["histograms"] = histograms

	// Collect timers
	timers := make(map[string]interface{})
	for key, timer := range amc.timers {
		timers[key] = timer.Value()
	}
	result["timers"] = timers

	return result
}

// GetMetricsByMiddleware returns metrics for a specific middleware
func (amc *AdvancedMetricsCollector) GetMetricsByMiddleware(middleware string) map[string]interface{} {
	allMetrics := amc.GetMetrics()
	result := make(map[string]interface{})

	// Filter metrics by middleware label
	for metricType, metrics := range allMetrics {
		filteredMetrics := make(map[string]interface{})
		if metricsMap, ok := metrics.(map[string]interface{}); ok {
			for key, value := range metricsMap {
				if strings.Contains(key, fmt.Sprintf("middleware=%s", middleware)) {
					filteredMetrics[key] = value
				}
			}
		}
		if len(filteredMetrics) > 0 {
			result[metricType] = filteredMetrics
		}
	}

	return result
}

// ResetMetrics resets all metrics
func (amc *AdvancedMetricsCollector) ResetMetrics() error {
	amc.mutex.Lock()
	defer amc.mutex.Unlock()

	amc.counters = make(map[string]*Counter)
	amc.gauges = make(map[string]*Gauge)
	amc.histograms = make(map[string]*Histogram)
	amc.summaries = make(map[string]*Summary)
	amc.timers = make(map[string]*Timer)
	amc.registry = NewMetricsRegistry()

	return nil
}

// Helper methods

// buildMetricName builds a full metric name
func (amc *AdvancedMetricsCollector) buildMetricName(name string) string {
	if amc.config.Namespace != "" && amc.config.Subsystem != "" {
		return fmt.Sprintf("%s_%s_%s", amc.config.Namespace, amc.config.Subsystem, name)
	} else if amc.config.Namespace != "" {
		return fmt.Sprintf("%s_%s", amc.config.Namespace, name)
	}
	return name
}

// buildLabelKey builds a unique key for metrics with labels
func (amc *AdvancedMetricsCollector) buildLabelKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := []string{name}
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, labels[key]))
	}

	return strings.Join(parts, ",")
}

// mergeLabels merges default labels with provided labels
func (amc *AdvancedMetricsCollector) mergeLabels(labels map[string]string) map[string]string {
	result := make(map[string]string)

	// Add default labels
	for key, value := range amc.config.DefaultLabels {
		result[key] = value
	}

	// Add provided labels (overrides defaults)
	for key, value := range labels {
		result[key] = value
	}

	return result
}

// collectRuntimeMetrics collects runtime metrics in background
func (amc *AdvancedMetricsCollector) collectRuntimeMetrics() {
	ticker := time.NewTicker(amc.config.CollectionInterval)
	defer ticker.Stop()

	for range ticker.C {
		if amc.config.EnableRuntime {
			amc.collectGCMetrics()
			amc.collectMemoryMetrics()
			amc.collectGoroutineMetrics()
		}
	}
}

// collectGCMetrics collects garbage collection metrics
func (amc *AdvancedMetricsCollector) collectGCMetrics() {
	// This would integrate with runtime.ReadMemStats() for real GC metrics
	// For now, using placeholder values
	gcCounter := amc.NewCounter("gc_collections_total", "Total number of GC collections", nil)
	gcCounter.Inc()
}

// collectMemoryMetrics collects memory metrics
func (amc *AdvancedMetricsCollector) collectMemoryMetrics() {
	// This would integrate with runtime.ReadMemStats() for real memory metrics
	// For now, using placeholder values
	memGauge := amc.NewGauge("memory_heap_bytes", "Current heap memory usage", nil)
	memGauge.Set(1024 * 1024) // 1MB placeholder
}

// collectGoroutineMetrics collects goroutine metrics
func (amc *AdvancedMetricsCollector) collectGoroutineMetrics() {
	// This would integrate with runtime.NumGoroutine() for real goroutine count
	// For now, using placeholder values
	goroutineGauge := amc.NewGauge("goroutines_active", "Number of active goroutines", nil)
	goroutineGauge.Set(10) // Placeholder value
}

// Registry implementation

// Register registers a metric in the registry
func (mr *MetricsRegistry) Register(metric Metric) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	key := metric.Name()
	if existing, exists := mr.metrics[key]; exists {
		return fmt.Errorf("metric %s already registered with type %s", key, existing.Type())
	}

	mr.metrics[key] = metric
	return nil
}

// Unregister removes a metric from the registry
func (mr *MetricsRegistry) Unregister(name string) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	delete(mr.metrics, name)
}

// Get retrieves a metric from the registry
func (mr *MetricsRegistry) Get(name string) (Metric, bool) {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()
	metric, exists := mr.metrics[name]
	return metric, exists
}

// All returns all registered metrics
func (mr *MetricsRegistry) All() []Metric {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	metrics := make([]Metric, 0, len(mr.metrics))
	for _, metric := range mr.metrics {
		metrics = append(metrics, metric)
	}
	return metrics
}
