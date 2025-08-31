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

// Package framework provides standardized interfaces and configurations
// for all middleware components across the NewBee microservices architecture.
//
// This framework ensures consistency, performance, and maintainability
// across all middleware implementations.
package framework

import (
	"context"
	"net/http"
	"time"
)

// ========================================
// STANDARD MIDDLEWARE INTERFACE
// ========================================

// StandardMiddleware defines the interface for lifecycle-managed middleware components
// This is different from the pipeline Middleware interface in interfaces.go
type StandardMiddleware interface {
	// Handle processes the HTTP request with middleware logic
	Handle(next http.HandlerFunc) http.HandlerFunc

	// Name returns the middleware name for logging and metrics
	Name() string

	// Version returns the middleware version for compatibility tracking
	Version() string

	// Health returns the current health status of the middleware
	Health() HealthStatus

	// Close gracefully shuts down the middleware and releases resources
	Close() error
}

// ConfigurableMiddleware extends StandardMiddleware with dynamic configuration support
type ConfigurableMiddleware interface {
	StandardMiddleware

	// UpdateConfig dynamically updates the middleware configuration
	UpdateConfig(config interface{}) error

	// GetConfig returns the current configuration
	GetConfig() interface{}
}

// MonitorableMiddleware extends Middleware with metrics and monitoring capabilities
type MonitorableMiddleware interface {
	Middleware

	// GetMetrics returns current performance metrics
	GetMetrics() MiddlewareMetrics

	// ResetMetrics resets all metrics counters
	ResetMetrics()
}

// CacheableMiddleware extends Middleware with cache management capabilities
type CacheableMiddleware interface {
	Middleware

	// InvalidateCache clears all cached data
	InvalidateCache() error

	// GetCacheStats returns cache performance statistics
	GetCacheStats() CacheStats
}

// ========================================
// CONFIGURATION STANDARDS
// ========================================

// BaseConfig defines standard configuration fields for all middleware
type BaseConfig struct {
	// Enabled controls whether the middleware is active
	Enabled bool `json:"enabled" yaml:"enabled"`

	// LogLevel sets the logging level for this middleware
	LogLevel string `json:"log_level" yaml:"log_level"`

	// Timeout sets the maximum processing time
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// Priority determines middleware execution order (higher = earlier)
	Priority int `json:"priority" yaml:"priority"`

	// Tags for categorization and filtering
	Tags []string `json:"tags" yaml:"tags"`
}

// PerformanceConfig defines standard performance-related settings
type PerformanceConfig struct {
	// EnableMetrics controls performance metrics collection
	EnableMetrics bool `json:"enable_metrics" yaml:"enable_metrics"`

	// MetricsInterval sets how often metrics are collected
	MetricsInterval time.Duration `json:"metrics_interval" yaml:"metrics_interval"`

	// MaxConcurrency limits concurrent request processing
	MaxConcurrency int `json:"max_concurrency" yaml:"max_concurrency"`

	// EnableProfiling controls performance profiling
	EnableProfiling bool `json:"enable_profiling" yaml:"enable_profiling"`
}

// StandardSecurityConfig defines standard security-related settings for middleware
// Note: Renamed to avoid conflict with SecurityConfig in security_hardening.go
type StandardSecurityConfig struct {
	// EnableRateLimit controls rate limiting functionality
	EnableRateLimit bool `json:"enable_rate_limit" yaml:"enable_rate_limit"`

	// RateLimitConfig specifies rate limiting parameters
	RateLimitConfig *RateLimitConfig `json:"rate_limit_config" yaml:"rate_limit_config"`

	// EnableCircuitBreaker controls circuit breaker functionality
	EnableCircuitBreaker bool `json:"enable_circuit_breaker" yaml:"enable_circuit_breaker"`

	// Note: CircuitBreakerConfig is defined in parent middleware package to avoid import cycle

	// TrustedProxies defines trusted proxy IP ranges
	TrustedProxies []string `json:"trusted_proxies" yaml:"trusted_proxies"`
}

// ========================================
// METRICS AND MONITORING
// ========================================

// MiddlewareMetrics defines standard metrics collected by all middleware
type MiddlewareMetrics struct {
	// Request metrics
	TotalRequests      uint64        `json:"total_requests"`
	SuccessfulRequests uint64        `json:"successful_requests"`
	FailedRequests     uint64        `json:"failed_requests"`
	AverageLatency     time.Duration `json:"average_latency"`
	MaxLatency         time.Duration `json:"max_latency"`
	MinLatency         time.Duration `json:"min_latency"`

	// Throughput metrics
	RequestsPerSecond float64 `json:"requests_per_second"`

	// Resource usage
	MemoryUsage     int64   `json:"memory_usage_bytes"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`

	// Cache metrics (if applicable)
	CacheHitRate float64 `json:"cache_hit_rate"`
	CacheSize    int64   `json:"cache_size"`

	// Error metrics
	TimeoutCount uint64  `json:"timeout_count"`
	ErrorRate    float64 `json:"error_rate"`

	// Timestamp
	LastUpdated time.Time `json:"last_updated"`
}

// CacheStats is defined in interfaces.go to avoid duplication

// DetailedHealthStatus provides comprehensive health information for middleware
// Note: Renamed to avoid conflict with HealthStatus enum in interfaces.go
type DetailedHealthStatus struct {
	Status       string                     `json:"status"`       // "healthy", "degraded", "unhealthy"
	Message      string                     `json:"message"`      // Human-readable status description
	CheckTime    time.Time                  `json:"check_time"`   // When the health check was performed
	Uptime       time.Duration              `json:"uptime"`       // How long the middleware has been running
	Version      string                     `json:"version"`      // Middleware version
	Dependencies []StandardDependencyHealth `json:"dependencies"` // Status of dependencies
}

// StandardDependencyHealth represents the health of a middleware dependency
// Note: Renamed to avoid conflict with DependencyHealth in health_endpoints.go
type StandardDependencyHealth struct {
	Name      string        `json:"name"`
	Status    string        `json:"status"`
	Message   string        `json:"message"`
	CheckTime time.Time     `json:"check_time"`
	Latency   time.Duration `json:"latency"`
}

// ========================================
// ERROR HANDLING STANDARDS
// ========================================

// MiddlewareError defines standard error interface for middleware
type MiddlewareError interface {
	error

	// Code returns the error code for categorization
	Code() string

	// Type returns the error type (temporary, permanent, etc.)
	Type() ErrorType

	// Context returns additional error context
	Context() map[string]interface{}

	// Recoverable indicates if the error is recoverable
	Recoverable() bool
}

// ErrorType categorizes middleware errors
type ErrorType string

const (
	ErrorTypeTemporary   ErrorType = "temporary"
	ErrorTypePermanent   ErrorType = "permanent"
	ErrorTypeRetryable   ErrorType = "retryable"
	ErrorTypeCircuitOpen ErrorType = "circuit_open"
	ErrorTypeTimeout     ErrorType = "timeout"
	ErrorTypeValidation  ErrorType = "validation"
	ErrorTypeSecurity    ErrorType = "security"
)

// ========================================
// LOGGING STANDARDS
// ========================================

// LogContext defines standard context fields for middleware logging
type LogContext struct {
	// Request identification
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`

	// User context
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`

	// Request details
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	UserAgent string            `json:"user_agent"`
	RemoteIP  string            `json:"remote_ip"`
	Headers   map[string]string `json:"headers,omitempty"`

	// Timing
	StartTime time.Time     `json:"start_time"`
	Duration  time.Duration `json:"duration"`

	// Middleware specific
	MiddlewareName    string `json:"middleware_name"`
	MiddlewareVersion string `json:"middleware_version"`

	// Custom fields
	Custom map[string]interface{} `json:"custom,omitempty"`
}

// ========================================
// FACTORY PATTERN
// ========================================

// MiddlewareFactory defines the factory interface for creating middleware instances
type MiddlewareFactory interface {
	// Create creates a new middleware instance with the given configuration
	Create(config interface{}) (StandardMiddleware, error)

	// Name returns the factory name
	Name() string

	// SupportedVersions returns supported configuration versions
	SupportedVersions() []string
}

// Registry manages middleware factories and instances
type Registry interface {
	// RegisterFactory registers a middleware factory
	RegisterFactory(name string, factory MiddlewareFactory) error

	// CreateMiddleware creates middleware by name and config
	CreateMiddleware(name string, config interface{}) (StandardMiddleware, error)

	// ListMiddleware returns all registered middleware names
	ListMiddleware() []string

	// GetMiddleware returns a middleware instance by name
	GetMiddleware(name string) (StandardMiddleware, error)

	// HealthCheck returns health status of all registered middleware
	HealthCheck() map[string]HealthStatus

	// GetMetrics returns metrics for all registered middleware
	GetMetrics() map[string]MiddlewareMetrics
}

// ========================================
// CONTEXT KEYS
// ========================================

// Standard context keys used across all middleware
type ContextKey string

const (
	ContextKeyRequestID     ContextKey = "middleware:request_id"
	ContextKeyCorrelationID ContextKey = "middleware:correlation_id"
	ContextKeyUserID        ContextKey = "middleware:user_id"
	ContextKeyUsername      ContextKey = "middleware:username"
	ContextKeyTenantID      ContextKey = "middleware:tenant_id"
	ContextKeyRoleCodes     ContextKey = "middleware:role_codes"
	ContextKeyPermissions   ContextKey = "middleware:permissions"
	ContextKeyStartTime     ContextKey = "middleware:start_time"
	ContextKeyMiddleware    ContextKey = "middleware:chain"
)

// ========================================
// UTILITY FUNCTIONS
// ========================================

// GetContextValue safely retrieves a value from request context
func GetContextValue(ctx context.Context, key ContextKey) interface{} {
	return ctx.Value(key)
}

// SetContextValue safely sets a value in request context
func SetContextValue(ctx context.Context, key ContextKey, value interface{}) context.Context {
	return context.WithValue(ctx, key, value)
}

// GetLogContext extracts standard log context from request
func GetLogContext(r *http.Request, middlewareName, middlewareVersion string) LogContext {
	ctx := r.Context()
	startTime := time.Now()

	// Check if start time already exists
	if existing := GetContextValue(ctx, ContextKeyStartTime); existing != nil {
		if t, ok := existing.(time.Time); ok {
			startTime = t
		}
	}

	return LogContext{
		RequestID:         getStringFromContext(ctx, ContextKeyRequestID),
		CorrelationID:     getStringFromContext(ctx, ContextKeyCorrelationID),
		UserID:            getStringFromContext(ctx, ContextKeyUserID),
		Username:          getStringFromContext(ctx, ContextKeyUsername),
		TenantID:          getStringFromContext(ctx, ContextKeyTenantID),
		Method:            r.Method,
		Path:              r.URL.Path,
		UserAgent:         r.UserAgent(),
		RemoteIP:          getRemoteIP(r),
		StartTime:         startTime,
		Duration:          time.Since(startTime),
		MiddlewareName:    middlewareName,
		MiddlewareVersion: middlewareVersion,
		Custom:            make(map[string]interface{}),
	}
}

// Helper functions
func getStringFromContext(ctx context.Context, key ContextKey) string {
	if value := ctx.Value(key); value != nil {
		if s, ok := value.(string); ok {
			return s
		}
	}
	return ""
}

// GetRemoteIP extracts the real client IP from HTTP request
func GetRemoteIP(r *http.Request) string {
	return getRemoteIP(r)
}

func getRemoteIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
