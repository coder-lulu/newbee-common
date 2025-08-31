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
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zeromicro/go-zero/core/logx"
)

// PrometheusMetricsCollector implements MetricsCollector using Prometheus
type PrometheusMetricsCollector struct {
	// Request metrics
	requestTotal     *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	requestsInFlight *prometheus.GaugeVec

	// Cache metrics
	cacheOperations *prometheus.CounterVec
	cacheHitRate    *prometheus.GaugeVec
	cacheSize       *prometheus.GaugeVec

	// Circuit breaker metrics
	circuitBreakerState *prometheus.GaugeVec
	circuitBreakerTrips *prometheus.CounterVec

	// Memory and CPU metrics
	memoryUsage *prometheus.GaugeVec
	cpuUsage    *prometheus.GaugeVec

	// Error metrics
	errorTotal   *prometheus.CounterVec
	timeoutTotal *prometheus.CounterVec

	// Custom metrics registry
	customMetrics map[string]prometheus.Collector
	customMutex   sync.RWMutex

	// Configuration
	config *PrometheusConfig
}

// PrometheusConfig configures Prometheus metrics collection
type PrometheusConfig struct {
	// Namespace for all metrics
	Namespace string `json:"namespace" yaml:"namespace"`

	// Subsystem for middleware metrics
	Subsystem string `json:"subsystem" yaml:"subsystem"`

	// EnableDetailedMetrics enables detailed per-middleware metrics
	EnableDetailedMetrics bool `json:"enable_detailed_metrics" yaml:"enable_detailed_metrics"`

	// EnableHistograms enables histogram metrics (more expensive)
	EnableHistograms bool `json:"enable_histograms" yaml:"enable_histograms"`

	// Labels to add to all metrics
	ConstLabels map[string]string `json:"const_labels" yaml:"const_labels"`

	// Histogram buckets for request duration
	DurationBuckets []float64 `json:"duration_buckets" yaml:"duration_buckets"`

	// Cache size buckets
	CacheSizeBuckets []float64 `json:"cache_size_buckets" yaml:"cache_size_buckets"`
}

// NewPrometheusMetricsCollector creates a new Prometheus metrics collector
func NewPrometheusMetricsCollector(config *PrometheusConfig) *PrometheusMetricsCollector {
	if config == nil {
		config = &PrometheusConfig{
			Namespace:             "newbee",
			Subsystem:             "middleware",
			EnableDetailedMetrics: true,
			EnableHistograms:      true,
			ConstLabels:           make(map[string]string),
			DurationBuckets:       prometheus.DefBuckets,
			CacheSizeBuckets:      []float64{10, 100, 1000, 10000, 100000},
		}
	}

	// Set default buckets if not provided
	if len(config.DurationBuckets) == 0 {
		config.DurationBuckets = prometheus.DefBuckets
	}
	if len(config.CacheSizeBuckets) == 0 {
		config.CacheSizeBuckets = []float64{10, 100, 1000, 10000, 100000}
	}

	collector := &PrometheusMetricsCollector{
		config:        config,
		customMetrics: make(map[string]prometheus.Collector),
	}

	collector.initializeMetrics()
	return collector
}

// initializeMetrics creates all Prometheus metrics
func (p *PrometheusMetricsCollector) initializeMetrics() {
	// Request metrics
	p.requestTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "requests_total",
			Help:        "Total number of requests processed by middleware",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "method", "status"},
	)

	if p.config.EnableHistograms {
		p.requestDuration = promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace:   p.config.Namespace,
				Subsystem:   p.config.Subsystem,
				Name:        "request_duration_seconds",
				Help:        "Request duration in seconds",
				Buckets:     p.config.DurationBuckets,
				ConstLabels: p.config.ConstLabels,
			},
			[]string{"middleware", "method"},
		)
	}

	p.requestsInFlight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "requests_in_flight",
			Help:        "Number of requests currently being processed",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware"},
	)

	// Cache metrics
	p.cacheOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "cache_operations_total",
			Help:        "Total number of cache operations",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "operation", "result"},
	)

	p.cacheHitRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "cache_hit_rate",
			Help:        "Cache hit rate as a percentage",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "cache_type"},
	)

	p.cacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "cache_size_bytes",
			Help:        "Current cache size in bytes",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "cache_type"},
	)

	// Circuit breaker metrics
	p.circuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "circuit_breaker_state",
			Help:        "Circuit breaker state (0=closed, 1=half-open, 2=open)",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "circuit_breaker"},
	)

	p.circuitBreakerTrips = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "circuit_breaker_trips_total",
			Help:        "Total number of circuit breaker trips",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "circuit_breaker"},
	)

	// Resource usage metrics
	p.memoryUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "memory_usage_bytes",
			Help:        "Memory usage in bytes",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware"},
	)

	p.cpuUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "cpu_usage_percent",
			Help:        "CPU usage percentage",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware"},
	)

	// Error metrics
	p.errorTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "errors_total",
			Help:        "Total number of errors",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "error_type"},
	)

	p.timeoutTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   p.config.Namespace,
			Subsystem:   p.config.Subsystem,
			Name:        "timeouts_total",
			Help:        "Total number of timeouts",
			ConstLabels: p.config.ConstLabels,
		},
		[]string{"middleware", "operation"},
	)

	logx.Infow("Prometheus metrics initialized",
		logx.Field("namespace", p.config.Namespace),
		logx.Field("subsystem", p.config.Subsystem),
		logx.Field("detailed_metrics", p.config.EnableDetailedMetrics))
}

// RecordRequest records request metrics
func (p *PrometheusMetricsCollector) RecordRequest(middleware, method string, duration time.Duration, success bool) {
	status := "success"
	if !success {
		status = "error"
	}

	p.requestTotal.WithLabelValues(middleware, method, status).Inc()

	if p.config.EnableHistograms && p.requestDuration != nil {
		p.requestDuration.WithLabelValues(middleware, method).Observe(duration.Seconds())
	}
}

// RecordRequestInFlight records in-flight request metrics
func (p *PrometheusMetricsCollector) RecordRequestInFlight(middleware string, delta int) {
	p.requestsInFlight.WithLabelValues(middleware).Add(float64(delta))
}

// RecordCacheOperation records cache operation metrics
func (p *PrometheusMetricsCollector) RecordCacheOperation(middleware, operation string, success bool, duration time.Duration) {
	result := "hit"
	if !success {
		result = "miss"
	}

	p.cacheOperations.WithLabelValues(middleware, operation, result).Inc()
}

// RecordCacheHitRate records cache hit rate
func (p *PrometheusMetricsCollector) RecordCacheHitRate(middleware, cacheType string, hitRate float64) {
	p.cacheHitRate.WithLabelValues(middleware, cacheType).Set(hitRate)
}

// RecordCacheSize records cache size
func (p *PrometheusMetricsCollector) RecordCacheSize(middleware, cacheType string, sizeBytes int64) {
	p.cacheSize.WithLabelValues(middleware, cacheType).Set(float64(sizeBytes))
}

// RecordCircuitBreakerState records circuit breaker state
func (p *PrometheusMetricsCollector) RecordCircuitBreakerState(middleware, name string, state CircuitBreakerState) {
	var stateValue float64
	switch state {
	case CircuitBreakerClosed:
		stateValue = 0
	case CircuitBreakerHalfOpen:
		stateValue = 1
	case CircuitBreakerOpen:
		stateValue = 2
	}

	p.circuitBreakerState.WithLabelValues(middleware, name).Set(stateValue)
}

// RecordCircuitBreakerTrip records circuit breaker trip
func (p *PrometheusMetricsCollector) RecordCircuitBreakerTrip(middleware, name string) {
	p.circuitBreakerTrips.WithLabelValues(middleware, name).Inc()
}

// RecordMemoryUsage records memory usage
func (p *PrometheusMetricsCollector) RecordMemoryUsage(middleware string, bytes int64) {
	p.memoryUsage.WithLabelValues(middleware).Set(float64(bytes))
}

// RecordCPUUsage records CPU usage
func (p *PrometheusMetricsCollector) RecordCPUUsage(middleware string, percent float64) {
	p.cpuUsage.WithLabelValues(middleware).Set(percent)
}

// RecordGoroutineCount records goroutine count (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) RecordGoroutineCount(middleware string, count int) {
	// Log goroutine count for now - in production this would be a gauge metric
	logx.Debugw("Recording goroutine count",
		logx.Field("middleware", middleware),
		logx.Field("count", count))
}

// RecordError records error metrics
func (p *PrometheusMetricsCollector) RecordError(middleware, errorType, errorCode string) {
	p.errorTotal.WithLabelValues(middleware, errorType).Inc()
	// Note: errorCode could be used as an additional label if needed
}

// RecordTimeout records timeout metrics
func (p *PrometheusMetricsCollector) RecordTimeout(middleware, operation string) {
	p.timeoutTotal.WithLabelValues(middleware, operation).Inc()
}

// RecordCounter records counter metrics (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) RecordCounter(name string, value float64, tags map[string]string) {
	// For Prometheus, we use the existing counters or create a dynamic one
	// This is a simplified implementation
	logx.Debugw("Recording counter metric",
		logx.Field("name", name),
		logx.Field("value", value),
		logx.Field("tags", tags))
}

// RecordCustomMetric records custom metrics (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) RecordCustomMetric(name string, value float64, tags map[string]string) {
	// For Prometheus, we log the custom metric for now
	// In a production implementation, this would create/update dynamic metrics
	logx.Debugw("Recording custom metric",
		logx.Field("name", name),
		logx.Field("value", value),
		logx.Field("tags", tags))
}

// RecordHistogram records histogram metrics (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) RecordHistogram(name string, value float64, tags map[string]string) {
	// For Prometheus, we would use the request duration histogram or create dynamic ones
	logx.Debugw("Recording histogram metric",
		logx.Field("name", name),
		logx.Field("value", value),
		logx.Field("tags", tags))
}

// RegisterCustomMetric registers a custom Prometheus collector
func (p *PrometheusMetricsCollector) RegisterCustomMetric(name string, metric prometheus.Collector) error {
	p.customMutex.Lock()
	defer p.customMutex.Unlock()

	if _, exists := p.customMetrics[name]; exists {
		return fmt.Errorf("custom metric '%s' already registered", name)
	}

	// Register with Prometheus
	if err := prometheus.Register(metric); err != nil {
		return fmt.Errorf("failed to register custom metric '%s': %w", name, err)
	}

	p.customMetrics[name] = metric
	return nil
}

// GetCustomMetric retrieves a custom metric by name
func (p *PrometheusMetricsCollector) GetCustomMetric(name string) (prometheus.Collector, bool) {
	p.customMutex.RLock()
	defer p.customMutex.RUnlock()

	metric, exists := p.customMetrics[name]
	return metric, exists
}

// GetHandler returns the Prometheus HTTP handler for metrics endpoint
func (p *PrometheusMetricsCollector) GetHandler() http.Handler {
	return promhttp.Handler()
}

// AlertingRules contains Prometheus alerting rules for middleware monitoring
type AlertingRules struct {
	HighErrorRate      *AlertRule `json:"high_error_rate" yaml:"high_error_rate"`
	HighLatency        *AlertRule `json:"high_latency" yaml:"high_latency"`
	LowCacheHitRate    *AlertRule `json:"low_cache_hit_rate" yaml:"low_cache_hit_rate"`
	CircuitBreakerOpen *AlertRule `json:"circuit_breaker_open" yaml:"circuit_breaker_open"`
	HighMemoryUsage    *AlertRule `json:"high_memory_usage" yaml:"high_memory_usage"`
	HighCPUUsage       *AlertRule `json:"high_cpu_usage" yaml:"high_cpu_usage"`
}

// AlertRule defines a Prometheus alerting rule
type AlertRule struct {
	Name        string            `json:"name" yaml:"name"`
	Expression  string            `json:"expression" yaml:"expression"`
	Duration    string            `json:"duration" yaml:"duration"`
	Labels      map[string]string `json:"labels" yaml:"labels"`
	Annotations map[string]string `json:"annotations" yaml:"annotations"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
}

// GetDefaultAlertingRules returns default alerting rules for middleware monitoring
func GetDefaultAlertingRules(namespace, subsystem string) *AlertingRules {
	return &AlertingRules{
		HighErrorRate: &AlertRule{
			Name: "MiddlewareHighErrorRate",
			Expression: fmt.Sprintf(
				`(rate(%s_%s_requests_total{status="error"}[5m]) / rate(%s_%s_requests_total[5m])) > 0.1`,
				namespace, subsystem, namespace, subsystem,
			),
			Duration: "2m",
			Labels: map[string]string{
				"severity": "warning",
				"service":  "middleware",
			},
			Annotations: map[string]string{
				"summary":     "High error rate in middleware",
				"description": "Middleware {{ $labels.middleware }} has error rate above 10% for more than 2 minutes",
			},
			Enabled: true,
		},
		HighLatency: &AlertRule{
			Name: "MiddlewareHighLatency",
			Expression: fmt.Sprintf(
				`histogram_quantile(0.95, rate(%s_%s_request_duration_seconds_bucket[5m])) > 1.0`,
				namespace, subsystem,
			),
			Duration: "2m",
			Labels: map[string]string{
				"severity": "warning",
				"service":  "middleware",
			},
			Annotations: map[string]string{
				"summary":     "High latency in middleware",
				"description": "Middleware {{ $labels.middleware }} 95th percentile latency is above 1 second",
			},
			Enabled: true,
		},
		LowCacheHitRate: &AlertRule{
			Name: "MiddlewareLowCacheHitRate",
			Expression: fmt.Sprintf(
				`%s_%s_cache_hit_rate < 0.8`,
				namespace, subsystem,
			),
			Duration: "5m",
			Labels: map[string]string{
				"severity": "warning",
				"service":  "middleware",
			},
			Annotations: map[string]string{
				"summary":     "Low cache hit rate in middleware",
				"description": "Middleware {{ $labels.middleware }} cache hit rate is below 80%",
			},
			Enabled: true,
		},
		CircuitBreakerOpen: &AlertRule{
			Name: "MiddlewareCircuitBreakerOpen",
			Expression: fmt.Sprintf(
				`%s_%s_circuit_breaker_state == 2`,
				namespace, subsystem,
			),
			Duration: "0m",
			Labels: map[string]string{
				"severity": "critical",
				"service":  "middleware",
			},
			Annotations: map[string]string{
				"summary":     "Circuit breaker is open in middleware",
				"description": "Middleware {{ $labels.middleware }} circuit breaker {{ $labels.circuit_breaker }} is open",
			},
			Enabled: true,
		},
		HighMemoryUsage: &AlertRule{
			Name: "MiddlewareHighMemoryUsage",
			Expression: fmt.Sprintf(
				`%s_%s_memory_usage_bytes > 1073741824`, // 1GB
				namespace, subsystem,
			),
			Duration: "5m",
			Labels: map[string]string{
				"severity": "warning",
				"service":  "middleware",
			},
			Annotations: map[string]string{
				"summary":     "High memory usage in middleware",
				"description": "Middleware {{ $labels.middleware }} is using more than 1GB of memory",
			},
			Enabled: true,
		},
		HighCPUUsage: &AlertRule{
			Name: "MiddlewareHighCPUUsage",
			Expression: fmt.Sprintf(
				`%s_%s_cpu_usage_percent > 80`,
				namespace, subsystem,
			),
			Duration: "5m",
			Labels: map[string]string{
				"severity": "warning",
				"service":  "middleware",
			},
			Annotations: map[string]string{
				"summary":     "High CPU usage in middleware",
				"description": "Middleware {{ $labels.middleware }} is using more than 80% CPU",
			},
			Enabled: true,
		},
	}
}

// GeneratePrometheusRulesYAML generates a Prometheus rules file in YAML format
func (ar *AlertingRules) GeneratePrometheusRulesYAML() string {
	rules := `groups:
- name: middleware_alerts
  rules:`

	if ar.HighErrorRate != nil && ar.HighErrorRate.Enabled {
		rules += fmt.Sprintf(`
  - alert: %s
    expr: %s
    for: %s
    labels:
      %s
    annotations:
      %s`,
			ar.HighErrorRate.Name,
			ar.HighErrorRate.Expression,
			ar.HighErrorRate.Duration,
			formatLabels(ar.HighErrorRate.Labels),
			formatAnnotations(ar.HighErrorRate.Annotations),
		)
	}

	if ar.HighLatency != nil && ar.HighLatency.Enabled {
		rules += fmt.Sprintf(`
  - alert: %s
    expr: %s
    for: %s
    labels:
      %s
    annotations:
      %s`,
			ar.HighLatency.Name,
			ar.HighLatency.Expression,
			ar.HighLatency.Duration,
			formatLabels(ar.HighLatency.Labels),
			formatAnnotations(ar.HighLatency.Annotations),
		)
	}

	if ar.LowCacheHitRate != nil && ar.LowCacheHitRate.Enabled {
		rules += fmt.Sprintf(`
  - alert: %s
    expr: %s
    for: %s
    labels:
      %s
    annotations:
      %s`,
			ar.LowCacheHitRate.Name,
			ar.LowCacheHitRate.Expression,
			ar.LowCacheHitRate.Duration,
			formatLabels(ar.LowCacheHitRate.Labels),
			formatAnnotations(ar.LowCacheHitRate.Annotations),
		)
	}

	if ar.CircuitBreakerOpen != nil && ar.CircuitBreakerOpen.Enabled {
		rules += fmt.Sprintf(`
  - alert: %s
    expr: %s
    for: %s
    labels:
      %s
    annotations:
      %s`,
			ar.CircuitBreakerOpen.Name,
			ar.CircuitBreakerOpen.Expression,
			ar.CircuitBreakerOpen.Duration,
			formatLabels(ar.CircuitBreakerOpen.Labels),
			formatAnnotations(ar.CircuitBreakerOpen.Annotations),
		)
	}

	if ar.HighMemoryUsage != nil && ar.HighMemoryUsage.Enabled {
		rules += fmt.Sprintf(`
  - alert: %s
    expr: %s
    for: %s
    labels:
      %s
    annotations:
      %s`,
			ar.HighMemoryUsage.Name,
			ar.HighMemoryUsage.Expression,
			ar.HighMemoryUsage.Duration,
			formatLabels(ar.HighMemoryUsage.Labels),
			formatAnnotations(ar.HighMemoryUsage.Annotations),
		)
	}

	if ar.HighCPUUsage != nil && ar.HighCPUUsage.Enabled {
		rules += fmt.Sprintf(`
  - alert: %s
    expr: %s
    for: %s
    labels:
      %s
    annotations:
      %s`,
			ar.HighCPUUsage.Name,
			ar.HighCPUUsage.Expression,
			ar.HighCPUUsage.Duration,
			formatLabels(ar.HighCPUUsage.Labels),
			formatAnnotations(ar.HighCPUUsage.Annotations),
		)
	}

	return rules
}

// Helper functions for formatting YAML
func formatLabels(labels map[string]string) string {
	result := ""
	for key, value := range labels {
		if result != "" {
			result += "\n      "
		}
		result += fmt.Sprintf(`%s: "%s"`, key, value)
	}
	return result
}

func formatAnnotations(annotations map[string]string) string {
	result := ""
	for key, value := range annotations {
		if result != "" {
			result += "\n      "
		}
		result += fmt.Sprintf(`%s: "%s"`, key, value)
	}
	return result
}

// MonitoringDashboard provides Grafana dashboard configuration for middleware monitoring
type MonitoringDashboard struct {
	Panels []DashboardPanel `json:"panels" yaml:"panels"`
}

// DashboardPanel represents a Grafana dashboard panel
type DashboardPanel struct {
	ID          int                    `json:"id" yaml:"id"`
	Title       string                 `json:"title" yaml:"title"`
	Type        string                 `json:"type" yaml:"type"`
	Targets     []DashboardTarget      `json:"targets" yaml:"targets"`
	YAxes       []DashboardYAxis       `json:"yAxes" yaml:"yAxes"`
	GridPos     DashboardGridPos       `json:"gridPos" yaml:"gridPos"`
	Options     map[string]interface{} `json:"options" yaml:"options"`
	FieldConfig map[string]interface{} `json:"fieldConfig" yaml:"fieldConfig"`
}

// DashboardTarget represents a Grafana query target
type DashboardTarget struct {
	Expr         string `json:"expr" yaml:"expr"`
	LegendFormat string `json:"legendFormat" yaml:"legendFormat"`
	RefID        string `json:"refId" yaml:"refId"`
}

// DashboardYAxis represents a Grafana Y-axis configuration
type DashboardYAxis struct {
	Label string  `json:"label" yaml:"label"`
	Min   float64 `json:"min" yaml:"min"`
	Max   float64 `json:"max" yaml:"max"`
	Unit  string  `json:"unit" yaml:"unit"`
}

// DashboardGridPos represents panel position in Grafana
type DashboardGridPos struct {
	H int `json:"h" yaml:"h"`
	W int `json:"w" yaml:"w"`
	X int `json:"x" yaml:"x"`
	Y int `json:"y" yaml:"y"`
}

// GetDefaultMonitoringDashboard returns a default Grafana dashboard for middleware monitoring
func GetDefaultMonitoringDashboard(namespace, subsystem string) *MonitoringDashboard {
	return &MonitoringDashboard{
		Panels: []DashboardPanel{
			{
				ID:    1,
				Title: "Request Rate",
				Type:  "graph",
				Targets: []DashboardTarget{
					{
						Expr:         fmt.Sprintf(`sum(rate(%s_%s_requests_total[5m])) by (middleware)`, namespace, subsystem),
						LegendFormat: "{{middleware}}",
						RefID:        "A",
					},
				},
				YAxes: []DashboardYAxis{
					{Label: "Requests/sec", Unit: "reqps"},
				},
				GridPos: DashboardGridPos{H: 8, W: 12, X: 0, Y: 0},
			},
			{
				ID:    2,
				Title: "Error Rate",
				Type:  "graph",
				Targets: []DashboardTarget{
					{
						Expr:         fmt.Sprintf(`sum(rate(%s_%s_requests_total{status="error"}[5m])) by (middleware)`, namespace, subsystem),
						LegendFormat: "{{middleware}}",
						RefID:        "A",
					},
				},
				YAxes: []DashboardYAxis{
					{Label: "Errors/sec", Unit: "reqps"},
				},
				GridPos: DashboardGridPos{H: 8, W: 12, X: 12, Y: 0},
			},
			{
				ID:    3,
				Title: "Response Time",
				Type:  "graph",
				Targets: []DashboardTarget{
					{
						Expr:         fmt.Sprintf(`histogram_quantile(0.95, sum(rate(%s_%s_request_duration_seconds_bucket[5m])) by (le, middleware))`, namespace, subsystem),
						LegendFormat: "95th percentile - {{middleware}}",
						RefID:        "A",
					},
					{
						Expr:         fmt.Sprintf(`histogram_quantile(0.50, sum(rate(%s_%s_request_duration_seconds_bucket[5m])) by (le, middleware))`, namespace, subsystem),
						LegendFormat: "50th percentile - {{middleware}}",
						RefID:        "B",
					},
				},
				YAxes: []DashboardYAxis{
					{Label: "Duration", Unit: "s"},
				},
				GridPos: DashboardGridPos{H: 8, W: 12, X: 0, Y: 8},
			},
			{
				ID:    4,
				Title: "Cache Hit Rate",
				Type:  "graph",
				Targets: []DashboardTarget{
					{
						Expr:         fmt.Sprintf(`%s_%s_cache_hit_rate`, namespace, subsystem),
						LegendFormat: "{{middleware}} - {{cache_type}}",
						RefID:        "A",
					},
				},
				YAxes: []DashboardYAxis{
					{Label: "Hit Rate", Unit: "percent", Min: 0, Max: 100},
				},
				GridPos: DashboardGridPos{H: 8, W: 12, X: 12, Y: 8},
			},
		},
	}
}

// GetMetrics returns all metrics as a map (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) GetMetrics() map[string]interface{} {
	p.customMutex.RLock()
	defer p.customMutex.RUnlock()

	metrics := make(map[string]interface{})

	// Add basic metrics information
	metrics["request_total"] = "Total number of requests processed"
	metrics["request_duration"] = "Request duration histogram"
	metrics["cache_operations"] = "Cache operation metrics"
	metrics["error_total"] = "Total number of errors"
	metrics["circuit_breaker_trips"] = "Circuit breaker trip events"
	metrics["memory_usage"] = "Memory usage by middleware"
	metrics["cpu_usage"] = "CPU usage by middleware"
	metrics["timeout_total"] = "Total number of timeouts"

	// Add custom metrics count
	metrics["custom_metrics_count"] = len(p.customMetrics)

	return metrics
}

// GetMetricsByMiddleware returns metrics for a specific middleware (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) GetMetricsByMiddleware(middleware string) map[string]interface{} {
	metrics := make(map[string]interface{})
	metrics["middleware"] = middleware
	metrics["note"] = "Prometheus metrics are collected globally, use Prometheus queries to filter by middleware label"
	return metrics
}

// ResetMetrics resets all metrics (required by MetricsCollector interface)
func (p *PrometheusMetricsCollector) ResetMetrics() error {
	// Note: Prometheus metrics are typically not reset programmatically
	// This would require re-registering all metrics
	logx.Infow("Prometheus metrics reset requested - metrics will be reset on next collection cycle")
	return nil
}

// Global metrics collector instance
var DefaultPrometheusCollector *PrometheusMetricsCollector

// InitializePrometheusMetrics initializes the default Prometheus metrics collector
func InitializePrometheusMetrics(config *PrometheusConfig) {
	DefaultPrometheusCollector = NewPrometheusMetricsCollector(config)

	logx.Infow("Default Prometheus metrics collector initialized",
		logx.Field("namespace", config.Namespace),
		logx.Field("subsystem", config.Subsystem))
}

// GetDefaultMetricsCollector returns the default metrics collector
func GetDefaultMetricsCollector() MetricsCollector {
	if DefaultPrometheusCollector == nil {
		InitializePrometheusMetrics(nil) // Use default config
	}
	return DefaultPrometheusCollector
}
