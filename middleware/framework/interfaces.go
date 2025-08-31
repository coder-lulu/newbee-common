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
	"net/http"
	"time"
)

// FrameworkCore defines the core framework interface
type FrameworkCore interface {
	// Framework lifecycle
	Initialize(config *FrameworkConfig) error
	Start() error
	Stop() error
	IsRunning() bool

	// Plugin management
	RegisterPlugin(plugin Plugin) error
	UnregisterPlugin(name string) error
	GetPlugin(name string) (Plugin, bool)
	ListPlugins() []string

	// Request processing
	ProcessRequest(ctx context.Context, req *Request) (*Response, error)
	CreateHandler() http.HandlerFunc

	// Configuration
	GetConfig() *FrameworkConfig
	ReloadConfig() error
}

// Plugin defines the standard plugin interface
type Plugin interface {
	PluginInfo
	PluginLifecycle
	MiddlewareHandler
}

// PluginInfo provides plugin metadata
type PluginInfo interface {
	Name() string
	Version() string
	Description() string
	Dependencies() []string
	Priority() int
	Metadata() *PluginMetadata
}

// PluginLifecycle manages plugin lifecycle
type PluginLifecycle interface {
	Initialize(config PluginConfig) error
	Start() error
	Stop() error
	Health() HealthStatus
}

// MiddlewareHandler processes requests
type MiddlewareHandler interface {
	Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error)
}

// Extended plugin interfaces
type ConfigurablePlugin interface {
	Plugin
	ReloadConfig(config PluginConfig) error
	ValidateConfig(config PluginConfig) error
}

type TypedConfigurablePlugin interface {
	Plugin
	ReloadTypedConfig(config *TypedPluginConfig) error
	ValidateTypedConfig(config *TypedPluginConfig) error
	GetConfigSchema() map[string]*ConfigValue
}

type MetricsPlugin interface {
	Plugin
	GetMetrics() map[string]interface{}
	ResetMetrics() error
}

type HealthCheckPlugin interface {
	Plugin
	HealthCheck() HealthStatus
	GetHealthDetails() map[string]interface{}
}

// ConfigurationManager handles framework configuration
type ConfigurationManager interface {
	// Configuration loading
	Initialize(config *FrameworkConfig) error
	LoadConfig(source ConfigSource) error
	GetPluginConfig(pluginName string) PluginConfig
	GetFrameworkConfig() *FrameworkConfig

	// Dynamic configuration
	WatchConfig(callback ConfigChangeCallback) error
	ReloadConfig() error
	ValidateConfig(config *FrameworkConfig) error

	// Environment and secrets
	ResolveEnvironmentVariables(config *FrameworkConfig) error
	GetSecret(key string) (string, error)
}

// ConfigSource defines configuration source interface
type ConfigSource interface {
	Load() (*FrameworkConfig, error)
	Watch(callback ConfigChangeCallback) error
	Validate() error
}

// DependencyInjector manages service dependencies
type DependencyInjector interface {
	// Service registration
	Register(name string, service interface{}) error
	RegisterFactory(name string, factory Factory) error
	RegisterSingleton(name string, factory Factory) error

	// Service resolution
	Get(name string) (interface{}, error)
	GetTyped(name string, target interface{}) error
	Inject(target interface{}) error

	// Lifecycle
	Initialize() error
	Shutdown() error
}

// MiddlewarePipeline manages the middleware execution chain
type MiddlewarePipeline interface {
	// Pipeline management
	SetMiddlewares(middlewares []Middleware) error
	AddMiddleware(middleware Middleware) error
	RemoveMiddleware(name string) error

	// Request processing
	Process(ctx context.Context, req *Request) (*Response, error)
	ProcessWithTimeout(ctx context.Context, req *Request, timeout time.Duration) (*Response, error)

	// Pipeline info
	GetMiddlewares() []Middleware
	GetExecutionOrder() []string
}

// MetricsCollector collects and reports metrics
type MetricsCollector interface {
	// Basic metrics
	RecordRequest(middleware, method string, duration time.Duration, success bool)
	RecordError(middleware, errorType, errorCode string)
	RecordCacheOperation(middleware, operation string, hit bool, duration time.Duration)

	// Custom metrics
	RecordCustomMetric(name string, value float64, tags map[string]string)
	RecordHistogram(name string, value float64, tags map[string]string)
	RecordCounter(name string, value float64, tags map[string]string)

	// System metrics
	RecordMemoryUsage(middleware string, bytes int64)
	RecordGoroutineCount(middleware string, count int)

	// Metrics retrieval
	GetMetrics() map[string]interface{}
	GetMetricsByMiddleware(middleware string) map[string]interface{}
	ResetMetrics() error
}

// Logger provides structured logging interface
type Logger interface {
	Debug(msg string, fields ...LogField)
	Info(msg string, fields ...LogField)
	Warn(msg string, fields ...LogField)
	Error(msg string, fields ...LogField)
	Fatal(msg string, fields ...LogField)
	Log(level LogLevel, msg string, fields ...LogField)

	With(fields ...LogField) Logger
	WithContext(ctx context.Context) Logger
}

// EventBus handles event publishing and subscription
type EventBus interface {
	// Event publishing
	Publish(event Event) error
	PublishAsync(event Event) error

	// Event subscription
	Subscribe(eventType string, handler EventHandler) error
	Unsubscribe(eventType string, handler EventHandler) error

	// Lifecycle
	Start() error
	Stop() error
}

// CircuitBreaker provides circuit breaker functionality
type CircuitBreaker interface {
	// Execution
	Execute(ctx context.Context, operation Operation) error
	ExecuteWithFallback(ctx context.Context, operation Operation, fallback FallbackFunc) error

	// State management
	State() CircuitBreakerState
	Reset() error
	ForceOpen() error
	ForceClose() error

	// Statistics
	Counts() CircuitBreakerCounts
	Settings() CircuitBreakerSettings
}

// Cache provides caching interface
type Cache interface {
	// Basic operations
	Get(ctx context.Context, key string) (interface{}, bool)
	Set(ctx context.Context, key string, value interface{}) error
	SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error

	// Bulk operations
	GetMulti(ctx context.Context, keys []string) map[string]interface{}
	SetMulti(ctx context.Context, items map[string]interface{}) error
	DeleteMulti(ctx context.Context, keys []string) error

	// Cache management
	Clear() error
	Size() int
	Stats() CacheStats

	// Lifecycle
	Close() error
}

// Types and structures

// HandlerFunc defines the middleware handler function signature
type HandlerFunc func(ctx context.Context, req *Request) (*Response, error)

// Middleware interface for pipeline execution
type Middleware interface {
	Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error)
	Name() string
	Priority() int
}

// Factory function for dependency injection
type Factory func() (interface{}, error)

// Operation function for circuit breaker
type Operation func(ctx context.Context) error

// FallbackFunc for circuit breaker fallback
type FallbackFunc func(ctx context.Context, err error) error

// EventHandler for event bus
type EventHandler func(event Event) error

// ConfigChangeCallback for configuration changes
type ConfigChangeCallback func(old, new *FrameworkConfig) error

// Request represents an HTTP request in the framework
type Request struct {
	ID          string
	Method      string
	Path        string
	Headers     map[string][]string
	Body        []byte
	RemoteAddr  string
	UserAgent   string
	ContentType string
	Timestamp   time.Time
	Context     map[string]interface{}
}

// Response represents an HTTP response from the framework
type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Error      error
	Metadata   map[string]interface{}
}

// FrameworkConfig defines the main framework configuration
type FrameworkConfig struct {
	// Core settings
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Environment string `yaml:"environment" json:"environment"`
	LogLevel    string `yaml:"log_level" json:"log_level"`

	// Performance settings
	MaxConcurrency  int           `yaml:"max_concurrency" json:"max_concurrency"`
	RequestTimeout  time.Duration `yaml:"request_timeout" json:"request_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout"`

	// Plugin settings
	PluginDir     string                  `yaml:"plugin_dir" json:"plugin_dir"`
	PluginConfigs map[string]PluginConfig `yaml:"plugins" json:"plugins"`

	// Monitoring settings
	MetricsEnabled bool `yaml:"metrics_enabled" json:"metrics_enabled"`
	MetricsPort    int  `yaml:"metrics_port" json:"metrics_port"`
	TracingEnabled bool `yaml:"tracing_enabled" json:"tracing_enabled"`
	HealthEnabled  bool `yaml:"health_enabled" json:"health_enabled"`

	// Security settings
	Security LegacySecurityConfig `yaml:"security" json:"security"`
}

// PluginConfig defines configuration for individual plugins
type PluginConfig struct {
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Priority    int                    `yaml:"priority" json:"priority"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Environment string                 `yaml:"environment" json:"environment"`
}

// LegacySecurityConfig defines legacy security-related configuration
type LegacySecurityConfig struct {
	EnableHTTPS    bool     `yaml:"enable_https" json:"enable_https"`
	TLSCertFile    string   `yaml:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile     string   `yaml:"tls_key_file" json:"tls_key_file"`
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`
	RateLimitRPS   int      `yaml:"rate_limit_rps" json:"rate_limit_rps"`
}

// PluginMetadata provides detailed plugin information
type PluginMetadata struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Author       string       `json:"author"`
	Description  string       `json:"description"`
	Homepage     string       `json:"homepage"`
	License      string       `json:"license"`
	Tags         []string     `json:"tags"`
	Dependencies []Dependency `json:"dependencies"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// Dependency represents a plugin dependency
type Dependency struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Type    DependencyType `json:"type"`
}

// Event represents a framework event
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// LogField represents a structured log field
type LogField struct {
	Key   string
	Value interface{}
}

// CacheStats provides cache statistics
type CacheStats struct {
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	HitRate   float64 `json:"hit_rate"`
	Size      int     `json:"size"`
	Capacity  int     `json:"capacity"`
	Evictions int64   `json:"evictions"`
}

// CircuitBreakerCounts provides circuit breaker statistics
type CircuitBreakerCounts struct {
	Requests      uint32 `json:"requests"`
	TotalSuccess  uint32 `json:"total_success"`
	TotalFailures uint32 `json:"total_failures"`
	Consecutive   uint32 `json:"consecutive_failures"`
}

// CircuitBreakerSettings defines circuit breaker configuration
type CircuitBreakerSettings struct {
	Name          string                                          `json:"name"`
	MaxRequests   uint32                                          `json:"max_requests"`
	Interval      time.Duration                                   `json:"interval"`
	Timeout       time.Duration                                   `json:"timeout"`
	ReadyToTrip   func(counts CircuitBreakerCounts) bool          `json:"-"`
	OnStateChange func(name string, from, to CircuitBreakerState) `json:"-"`
}

// Enums

// HealthStatus represents the health status of a component
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusUnhealthy
	HealthStatusDegraded
)

func (hs HealthStatus) String() string {
	switch hs {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusUnhealthy:
		return "unhealthy"
	case HealthStatusDegraded:
		return "degraded"
	default:
		return "unknown"
	}
}

// DependencyType represents the type of dependency
type DependencyType int

const (
	DependencyRequired DependencyType = iota
	DependencyOptional
	DependencyConflict
)

func (dt DependencyType) String() string {
	switch dt {
	case DependencyRequired:
		return "required"
	case DependencyOptional:
		return "optional"
	case DependencyConflict:
		return "conflict"
	default:
		return "unknown"
	}
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerHalfOpen
	CircuitBreakerOpen
)

func (cbs CircuitBreakerState) String() string {
	switch cbs {
	case CircuitBreakerClosed:
		return "closed"
	case CircuitBreakerHalfOpen:
		return "half-open"
	case CircuitBreakerOpen:
		return "open"
	default:
		return "unknown"
	}
}

// Helper functions for creating log fields are defined in base_components.go
