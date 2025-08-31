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
	"net/http"
	"runtime"
	"sync"
	"time"
)

// MonitoringManager integrates tracing, logging, and metrics
type MonitoringManager struct {
	config           *MonitoringConfig
	traceManager     *TraceManager
	logger           *StructuredLogger
	metricsCollector *AdvancedMetricsCollector
	enabled          bool
	mutex            sync.RWMutex
}

// MonitoringConfig defines comprehensive monitoring configuration
type MonitoringConfig struct {
	Enabled        bool               `json:"enabled" yaml:"enabled"`
	ServiceName    string             `json:"service_name" yaml:"service_name"`
	ServiceVersion string             `json:"service_version" yaml:"service_version"`
	Environment    string             `json:"environment" yaml:"environment"`
	Tracing        *TracingConfig     `json:"tracing" yaml:"tracing"`
	Logging        *LoggingConfig     `json:"logging" yaml:"logging"`
	Metrics        *MetricsConfig     `json:"metrics" yaml:"metrics"`
	HealthCheck    *HealthCheckConfig `json:"health_check" yaml:"health_check"`
	Profiling      *ProfilingConfig   `json:"profiling" yaml:"profiling"`
}

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	Enabled          bool          `json:"enabled" yaml:"enabled"`
	Port             int           `json:"port" yaml:"port"`
	Path             string        `json:"path" yaml:"path"`
	Timeout          time.Duration `json:"timeout" yaml:"timeout"`
	Interval         time.Duration `json:"interval" yaml:"interval"`
	FailureThreshold int           `json:"failure_threshold" yaml:"failure_threshold"`
	SuccessThreshold int           `json:"success_threshold" yaml:"success_threshold"`
	InitialDelay     time.Duration `json:"initial_delay" yaml:"initial_delay"`
	Checks           []HealthCheck `json:"checks" yaml:"checks"`
}

// ProfilingConfig defines profiling configuration
type ProfilingConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	Port            int           `json:"port" yaml:"port"`
	CPUProfile      bool          `json:"cpu_profile" yaml:"cpu_profile"`
	MemProfile      bool          `json:"mem_profile" yaml:"mem_profile"`
	BlockProfile    bool          `json:"block_profile" yaml:"block_profile"`
	MutexProfile    bool          `json:"mutex_profile" yaml:"mutex_profile"`
	ProfileDuration time.Duration `json:"profile_duration" yaml:"profile_duration"`
}

// HealthCheck interface for custom health checks
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) error
}

// MonitoringMiddleware provides comprehensive monitoring for requests
type MonitoringMiddleware struct {
	manager *MonitoringManager
}

// NewMonitoringManager creates a new monitoring manager
func NewMonitoringManager(config *MonitoringConfig) *MonitoringManager {
	if config == nil {
		config = DefaultMonitoringConfig()
	}

	mm := &MonitoringManager{
		config:  config,
		enabled: config.Enabled,
	}

	if mm.enabled {
		// Initialize tracing
		if config.Tracing.Enabled {
			mm.traceManager = NewTraceManager(config.Tracing)
		}

		// Initialize logging
		if config.Logging.Level != FatalLevel+1 { // Check if logging is enabled
			mm.logger = NewStructuredLogger(config.Logging)
		}

		// Initialize metrics
		if config.Metrics.Enabled {
			mm.metricsCollector = NewAdvancedMetricsCollector(config.Metrics)
		}

		// Start health check server if enabled
		if config.HealthCheck.Enabled {
			go mm.startHealthCheckServer()
		}

		// Start profiling server if enabled
		if config.Profiling.Enabled {
			go mm.startProfilingServer()
		}
	}

	return mm
}

// DefaultMonitoringConfig returns default monitoring configuration
func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		Enabled:        true,
		ServiceName:    "middleware-framework",
		ServiceVersion: "1.0.0",
		Environment:    "production",
		Tracing:        DefaultTracingConfig(),
		Logging:        DefaultLoggingConfig(),
		Metrics:        DefaultMetricsConfig(),
		HealthCheck: &HealthCheckConfig{
			Enabled:          true,
			Port:             9090,
			Path:             "/health",
			Timeout:          30 * time.Second,
			Interval:         10 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 1,
			InitialDelay:     5 * time.Second,
			Checks:           make([]HealthCheck, 0),
		},
		Profiling: &ProfilingConfig{
			Enabled:         false,
			Port:            6060,
			CPUProfile:      true,
			MemProfile:      true,
			BlockProfile:    false,
			MutexProfile:    false,
			ProfileDuration: 30 * time.Second,
		},
	}
}

// NewMonitoringMiddleware creates a new monitoring middleware
func NewMonitoringMiddleware(manager *MonitoringManager) *MonitoringMiddleware {
	return &MonitoringMiddleware{
		manager: manager,
	}
}

// Handle implements MiddlewareHandler for comprehensive monitoring
func (mm *MonitoringMiddleware) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	if !mm.manager.enabled {
		return next(ctx, req)
	}

	startTime := time.Now()

	// Start distributed tracing span
	var span *Span
	var newCtx context.Context = ctx
	if mm.manager.traceManager != nil {
		span, newCtx = mm.manager.traceManager.StartSpan(ctx,
			fmt.Sprintf("%s %s", req.Method, req.Path),
			WithSpanTag("http.method", req.Method),
			WithSpanTag("http.path", req.Path),
			WithSpanTag("http.user_agent", req.UserAgent),
			WithSpanTag("service.name", mm.manager.config.ServiceName),
		)
		if span != nil {
			defer mm.manager.traceManager.FinishSpan(span)
		}
	}

	// Create logger with context
	var logger Logger
	if mm.manager.logger != nil {
		logger = mm.manager.logger.WithContext(newCtx).(*StructuredLogger).WithRequest(req)
		logger.Info("Request started",
			String("method", req.Method),
			String("path", req.Path),
		)
	}

	// Record request start metrics
	if mm.manager.metricsCollector != nil {
		requestCounter := mm.manager.metricsCollector.NewCounter(
			"requests_total",
			"Total number of requests",
			map[string]string{
				"method": req.Method,
				"path":   req.Path,
			},
		)
		requestCounter.Inc()

		activeRequestsGauge := mm.manager.metricsCollector.NewGauge(
			"requests_active",
			"Number of active requests",
			map[string]string{
				"method": req.Method,
			},
		)
		activeRequestsGauge.Inc()
		defer activeRequestsGauge.Dec()
	}

	// Process request through next middleware
	resp, err := next(newCtx, req)

	// Calculate request duration
	duration := time.Since(startTime)

	// Determine success status
	success := err == nil && (resp == nil || resp.StatusCode < 400)

	// Update tracing information
	if span != nil {
		if resp != nil {
			span.SetTag("http.status_code", resp.StatusCode)
		}
		if err != nil {
			span.RecordError(err)
		} else {
			span.SetStatus(SpanStatusOK, "")
		}
		span.SetTag("request.duration_ms", float64(duration.Nanoseconds())/1e6)
	}

	// Log request completion
	if logger != nil {
		logLevel := InfoLevel
		if err != nil {
			logLevel = ErrorLevel
			logger = logger.(*StructuredLogger).WithError(err)
		} else if resp != nil && resp.StatusCode >= 400 {
			logLevel = WarnLevel
		}

		fields := []LogField{
			String("method", req.Method),
			String("path", req.Path),
			Duration("duration", duration),
		}

		if resp != nil {
			fields = append(fields, Int("status_code", resp.StatusCode))
		}

		message := "Request completed"
		if err != nil {
			message = "Request failed"
		}

		logger.Log(logLevel, message, fields...)
	}

	// Record metrics
	if mm.manager.metricsCollector != nil {
		// Request duration histogram
		labels := map[string]string{
			"method": req.Method,
			"path":   req.Path,
			"status": "success",
		}
		if !success {
			labels["status"] = "error"
		}
		if resp != nil {
			labels["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
		}

		durationHistogram := mm.manager.metricsCollector.NewHistogram(
			"request_duration_seconds",
			"Request duration in seconds",
			labels,
			nil,
		)
		durationHistogram.Observe(duration.Seconds())

		// Request size histogram if body is present
		if len(req.Body) > 0 {
			requestSizeHistogram := mm.manager.metricsCollector.NewHistogram(
				"request_size_bytes",
				"Request size in bytes",
				labels,
				[]float64{100, 1000, 10000, 100000, 1000000},
			)
			requestSizeHistogram.Observe(float64(len(req.Body)))
		}

		// Response size histogram if body is present
		if resp != nil && len(resp.Body) > 0 {
			responseSizeHistogram := mm.manager.metricsCollector.NewHistogram(
				"response_size_bytes",
				"Response size in bytes",
				labels,
				[]float64{100, 1000, 10000, 100000, 1000000},
			)
			responseSizeHistogram.Observe(float64(len(resp.Body)))
		}

		// Error counter if request failed
		if err != nil {
			errorCounter := mm.manager.metricsCollector.NewCounter(
				"errors_total",
				"Total number of errors",
				map[string]string{
					"method": req.Method,
					"path":   req.Path,
					"type":   fmt.Sprintf("%T", err),
				},
			)
			errorCounter.Inc()
		}
	}

	return resp, err
}

// GetTraceManager returns the trace manager
func (mm *MonitoringManager) GetTraceManager() *TraceManager {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()
	return mm.traceManager
}

// GetLogger returns the structured logger
func (mm *MonitoringManager) GetLogger() *StructuredLogger {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()
	return mm.logger
}

// GetMetricsCollector returns the metrics collector
func (mm *MonitoringManager) GetMetricsCollector() *AdvancedMetricsCollector {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()
	return mm.metricsCollector
}

// startHealthCheckServer starts the health check HTTP server
func (mm *MonitoringManager) startHealthCheckServer() {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc(mm.config.HealthCheck.Path, mm.handleHealthCheck)

	// Readiness check endpoint
	mux.HandleFunc("/ready", mm.handleReadinessCheck)

	// Liveness check endpoint
	mux.HandleFunc("/live", mm.handleLivenessCheck)

	// Metrics endpoint
	if mm.metricsCollector != nil {
		mux.HandleFunc("/metrics", mm.handleMetrics)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", mm.config.HealthCheck.Port),
		Handler:      mux,
		ReadTimeout:  mm.config.HealthCheck.Timeout,
		WriteTimeout: mm.config.HealthCheck.Timeout,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		if mm.logger != nil {
			mm.logger.Error("Health check server failed",
				String("error", err.Error()),
			)
		}
	}
}

// handleHealthCheck handles health check requests
func (mm *MonitoringManager) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), mm.config.HealthCheck.Timeout)
	defer cancel()

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service": map[string]string{
			"name":        mm.config.ServiceName,
			"version":     mm.config.ServiceVersion,
			"environment": mm.config.Environment,
		},
		"checks": make(map[string]interface{}),
	}

	allHealthy := true

	// Run custom health checks
	for _, check := range mm.config.HealthCheck.Checks {
		checkResult := map[string]interface{}{
			"status": "healthy",
		}

		if err := check.Check(ctx); err != nil {
			checkResult["status"] = "unhealthy"
			checkResult["error"] = err.Error()
			allHealthy = false
		}

		health["checks"].(map[string]interface{})[check.Name()] = checkResult
	}

	// Add system information
	health["system"] = map[string]interface{}{
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc":       getMemStats().Alloc,
			"total_alloc": getMemStats().TotalAlloc,
			"sys":         getMemStats().Sys,
		},
	}

	if !allHealthy {
		health["status"] = "unhealthy"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%+v", health)
}

// handleReadinessCheck handles readiness check requests
func (mm *MonitoringManager) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	ready := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%+v", ready)
}

// handleLivenessCheck handles liveness check requests
func (mm *MonitoringManager) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	alive := map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%+v", alive)
}

// handleMetrics handles metrics endpoint requests
func (mm *MonitoringManager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if mm.metricsCollector == nil {
		http.Error(w, "Metrics not available", http.StatusNotFound)
		return
	}

	metrics := mm.metricsCollector.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%+v", metrics)
}

// startProfilingServer starts the profiling HTTP server
func (mm *MonitoringManager) startProfilingServer() {
	// This would integrate with net/http/pprof for real profiling
	// For now, creating a placeholder server
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Profiling endpoint placeholder")
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", mm.config.Profiling.Port),
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		if mm.logger != nil {
			mm.logger.Error("Profiling server failed",
				String("error", err.Error()),
			)
		}
	}
}

// Utility functions

var startTime = time.Now()

// getMemStats returns memory statistics
func getMemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// Framework health checks

// FrameworkHealthCheck checks framework health
type FrameworkHealthCheck struct {
	framework FrameworkCore
}

// NewFrameworkHealthCheck creates a new framework health check
func NewFrameworkHealthCheck(framework FrameworkCore) *FrameworkHealthCheck {
	return &FrameworkHealthCheck{framework: framework}
}

// Name returns the health check name
func (fhc *FrameworkHealthCheck) Name() string {
	return "framework"
}

// Check performs the health check
func (fhc *FrameworkHealthCheck) Check(ctx context.Context) error {
	if !fhc.framework.IsRunning() {
		return fmt.Errorf("framework is not running")
	}
	return nil
}

// DatabaseHealthCheck checks database connectivity
type DatabaseHealthCheck struct {
	name      string
	checkFunc func(ctx context.Context) error
}

// NewDatabaseHealthCheck creates a new database health check
func NewDatabaseHealthCheck(name string, checkFunc func(ctx context.Context) error) *DatabaseHealthCheck {
	return &DatabaseHealthCheck{
		name:      name,
		checkFunc: checkFunc,
	}
}

// Name returns the health check name
func (dhc *DatabaseHealthCheck) Name() string {
	return dhc.name
}

// Check performs the health check
func (dhc *DatabaseHealthCheck) Check(ctx context.Context) error {
	return dhc.checkFunc(ctx)
}

// RedisHealthCheck checks Redis connectivity
type RedisHealthCheck struct {
	name      string
	checkFunc func(ctx context.Context) error
}

// NewRedisHealthCheck creates a new Redis health check
func NewRedisHealthCheck(name string, checkFunc func(ctx context.Context) error) *RedisHealthCheck {
	return &RedisHealthCheck{
		name:      name,
		checkFunc: checkFunc,
	}
}

// Name returns the health check name
func (rhc *RedisHealthCheck) Name() string {
	return rhc.name
}

// Check performs the health check
func (rhc *RedisHealthCheck) Check(ctx context.Context) error {
	return rhc.checkFunc(ctx)
}
