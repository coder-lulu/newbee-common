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
	"reflect"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// DefaultConfigurationManager implements ConfigurationManager
type DefaultConfigurationManager struct {
	config        *FrameworkConfig
	pluginConfigs map[string]PluginConfig
	typedConfigs  map[string]*TypedPluginConfig
	configFactory *PluginConfigFactory
	watchers      []ConfigChangeCallback
	source        ConfigSource
	mu            sync.RWMutex
}

// NewConfigurationManager creates a new configuration manager
func NewConfigurationManager() ConfigurationManager {
	return &DefaultConfigurationManager{
		pluginConfigs: make(map[string]PluginConfig),
		typedConfigs:  make(map[string]*TypedPluginConfig),
		configFactory: NewPluginConfigFactory(),
		watchers:      make([]ConfigChangeCallback, 0),
	}
}

func (cm *DefaultConfigurationManager) Initialize(config *FrameworkConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.config = config

	// Load plugin configurations
	for name, pluginConfig := range config.PluginConfigs {
		cm.pluginConfigs[name] = pluginConfig
	}

	return nil
}

func (cm *DefaultConfigurationManager) LoadConfig(source ConfigSource) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.source = source
	config, err := source.Load()
	if err != nil {
		return err
	}

	oldConfig := cm.config
	cm.config = config

	// Update plugin configs
	for name, pluginConfig := range config.PluginConfigs {
		cm.pluginConfigs[name] = pluginConfig
	}

	// Notify watchers
	for _, callback := range cm.watchers {
		go callback(oldConfig, config)
	}

	return nil
}

func (cm *DefaultConfigurationManager) GetPluginConfig(pluginName string) PluginConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if config, exists := cm.pluginConfigs[pluginName]; exists {
		return config
	}

	return PluginConfig{
		Enabled:  true,
		Priority: 100,
		Config:   make(map[string]interface{}),
	}
}

func (cm *DefaultConfigurationManager) GetFrameworkConfig() *FrameworkConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

func (cm *DefaultConfigurationManager) WatchConfig(callback ConfigChangeCallback) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.watchers = append(cm.watchers, callback)
	return nil
}

func (cm *DefaultConfigurationManager) ReloadConfig() error {
	if cm.source == nil {
		return fmt.Errorf("no config source configured")
	}
	return cm.LoadConfig(cm.source)
}

func (cm *DefaultConfigurationManager) ValidateConfig(config *FrameworkConfig) error {
	if config.Name == "" {
		return fmt.Errorf("framework name is required")
	}
	if config.Version == "" {
		return fmt.Errorf("framework version is required")
	}

	// Validate plugin configurations
	for name, pluginConfig := range config.PluginConfigs {
		if err := cm.validatePluginConfig(name, pluginConfig); err != nil {
			return fmt.Errorf("invalid plugin config for %s: %w", name, err)
		}
	}

	// Validate framework-level settings
	if config.RequestTimeout < 0 {
		return fmt.Errorf("request timeout cannot be negative")
	}

	if config.RequestTimeout > 5*time.Minute {
		return fmt.Errorf("request timeout cannot exceed 5 minutes")
	}

	// Validate metrics configuration
	if config.MetricsEnabled {
		if config.MetricsPort < 1 || config.MetricsPort > 65535 {
			return fmt.Errorf("metrics port must be between 1 and 65535")
		}
	}

	return nil
}

// validatePluginConfig validates individual plugin configuration
func (cm *DefaultConfigurationManager) validatePluginConfig(name string, config PluginConfig) error {
	// Basic validation
	if config.Priority < 0 || config.Priority > 1000 {
		return fmt.Errorf("priority must be between 0 and 1000, got %d", config.Priority)
	}

	// Validate plugin-specific configuration based on plugin type
	switch name {
	case "audit":
		return cm.validateAuditPluginConfig(config)
	case "dataperm":
		return cm.validateDataPermPluginConfig(config)
	case "tenant":
		return cm.validateTenantPluginConfig(config)
	default:
		// Generic validation for unknown plugins
		return cm.validateGenericPluginConfig(config)
	}
}

// validateAuditPluginConfig validates audit plugin configuration
func (cm *DefaultConfigurationManager) validateAuditPluginConfig(config PluginConfig) error {
	if maxBodySize, exists := config.Config["max_body_size"]; exists {
		if size, ok := maxBodySize.(int); ok {
			if size < 0 || size > 10*1024*1024 { // Max 10MB
				return fmt.Errorf("max_body_size must be between 0 and 10MB, got %d", size)
			}
		} else {
			return fmt.Errorf("max_body_size must be an integer")
		}
	}

	if skipPaths, exists := config.Config["skip_paths"]; exists {
		if paths, ok := skipPaths.([]interface{}); ok {
			for i, path := range paths {
				if _, ok := path.(string); !ok {
					return fmt.Errorf("skip_paths[%d] must be a string", i)
				}
			}
		} else {
			return fmt.Errorf("skip_paths must be an array of strings")
		}
	}

	return nil
}

// validateDataPermPluginConfig validates data permission plugin configuration
func (cm *DefaultConfigurationManager) validateDataPermPluginConfig(config PluginConfig) error {
	if cacheSize, exists := config.Config["cache_size"]; exists {
		if size, ok := cacheSize.(int); ok {
			if size < 100 || size > 100000 {
				return fmt.Errorf("cache_size must be between 100 and 100000, got %d", size)
			}
		} else {
			return fmt.Errorf("cache_size must be an integer")
		}
	}

	if cacheTTL, exists := config.Config["cache_ttl"]; exists {
		if ttl, ok := cacheTTL.(string); ok {
			if _, err := time.ParseDuration(ttl); err != nil {
				return fmt.Errorf("cache_ttl must be a valid duration: %w", err)
			}
		} else {
			return fmt.Errorf("cache_ttl must be a duration string")
		}
	}

	return nil
}

// validateTenantPluginConfig validates tenant plugin configuration
func (cm *DefaultConfigurationManager) validateTenantPluginConfig(config PluginConfig) error {
	if jwtSecret, exists := config.Config["jwt_secret"]; exists {
		if secret, ok := jwtSecret.(string); ok {
			if len(secret) < 32 {
				return fmt.Errorf("jwt_secret must be at least 32 characters long")
			}
		} else {
			return fmt.Errorf("jwt_secret must be a string")
		}
	}

	if tokenExp, exists := config.Config["token_expiration"]; exists {
		if exp, ok := tokenExp.(string); ok {
			if _, err := time.ParseDuration(exp); err != nil {
				return fmt.Errorf("token_expiration must be a valid duration: %w", err)
			}
		} else {
			return fmt.Errorf("token_expiration must be a duration string")
		}
	}

	return nil
}

// validateGenericPluginConfig validates generic plugin configuration
func (cm *DefaultConfigurationManager) validateGenericPluginConfig(config PluginConfig) error {
	// Generic validation for any plugin

	// Check for common configuration keys
	if timeout, exists := config.Config["timeout"]; exists {
		if timeoutStr, ok := timeout.(string); ok {
			if _, err := time.ParseDuration(timeoutStr); err != nil {
				return fmt.Errorf("timeout must be a valid duration: %w", err)
			}
		} else {
			return fmt.Errorf("timeout must be a duration string")
		}
	}

	if retries, exists := config.Config["retries"]; exists {
		if r, ok := retries.(int); ok {
			if r < 0 || r > 10 {
				return fmt.Errorf("retries must be between 0 and 10, got %d", r)
			}
		} else {
			return fmt.Errorf("retries must be an integer")
		}
	}

	return nil
}

func (cm *DefaultConfigurationManager) ResolveEnvironmentVariables(config *FrameworkConfig) error {
	// TODO: Implement environment variable resolution
	return nil
}

func (cm *DefaultConfigurationManager) GetSecret(key string) (string, error) {
	// TODO: Implement secret management
	return "", fmt.Errorf("secret management not implemented")
}

// GetTypedPluginConfig returns a strongly typed configuration for the specified plugin
func (cm *DefaultConfigurationManager) GetTypedPluginConfig(pluginName string) *TypedPluginConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return existing typed config if available
	if typedConfig, exists := cm.typedConfigs[pluginName]; exists {
		return typedConfig
	}

	// Create typed config from legacy config
	legacyConfig := cm.GetPluginConfig(pluginName)
	typedConfig := CreateFromPluginConfig(pluginName, legacyConfig)

	// Try to enhance with predefined schema
	predefinedConfig := cm.configFactory.CreateTypedConfig(pluginName)
	if predefinedConfig != nil {
		// Copy schema from predefined config
		typedConfig.schema = predefinedConfig.schema
	}

	// Cache the typed config
	cm.typedConfigs[pluginName] = typedConfig

	return typedConfig
}

// SetTypedPluginConfig sets a strongly typed configuration for the specified plugin
func (cm *DefaultConfigurationManager) SetTypedPluginConfig(pluginName string, config *TypedPluginConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Store typed config
	cm.typedConfigs[pluginName] = config

	// Update legacy config for backward compatibility
	legacyConfig := config.ToLegacyPluginConfig()
	cm.pluginConfigs[pluginName] = legacyConfig

	return nil
}

// ValidateAllPluginConfigs validates all plugin configurations
func (cm *DefaultConfigurationManager) ValidateAllPluginConfigs() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var errors []string

	for pluginName, typedConfig := range cm.typedConfigs {
		if err := typedConfig.Validate(); err != nil {
			errors = append(errors, fmt.Sprintf("plugin %s: %v", pluginName, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %v", errors)
	}

	return nil
}

// GetPluginConfigFactory returns the plugin configuration factory
func (cm *DefaultConfigurationManager) GetPluginConfigFactory() *PluginConfigFactory {
	return cm.configFactory
}

// DefaultDIContainer implements DependencyInjector
type DefaultDIContainer struct {
	services   map[string]interface{}
	factories  map[string]Factory
	singletons map[string]interface{}
	mu         sync.RWMutex
}

// NewDIContainer creates a new dependency injection container
func NewDIContainer() DependencyInjector {
	return &DefaultDIContainer{
		services:   make(map[string]interface{}),
		factories:  make(map[string]Factory),
		singletons: make(map[string]interface{}),
	}
}

func (dic *DefaultDIContainer) Register(name string, service interface{}) error {
	dic.mu.Lock()
	defer dic.mu.Unlock()

	dic.services[name] = service
	return nil
}

func (dic *DefaultDIContainer) RegisterFactory(name string, factory Factory) error {
	dic.mu.Lock()
	defer dic.mu.Unlock()

	dic.factories[name] = factory
	return nil
}

func (dic *DefaultDIContainer) RegisterSingleton(name string, factory Factory) error {
	dic.mu.Lock()
	defer dic.mu.Unlock()

	dic.factories[name] = factory
	return nil
}

func (dic *DefaultDIContainer) Get(name string) (interface{}, error) {
	dic.mu.RLock()

	// Check services first
	if service, exists := dic.services[name]; exists {
		dic.mu.RUnlock()
		return service, nil
	}

	// Check singletons
	if singleton, exists := dic.singletons[name]; exists {
		dic.mu.RUnlock()
		return singleton, nil
	}

	// Check factories
	if factory, exists := dic.factories[name]; exists {
		dic.mu.RUnlock()

		instance, err := factory()
		if err != nil {
			return nil, err
		}

		// Cache as singleton
		dic.mu.Lock()
		dic.singletons[name] = instance
		dic.mu.Unlock()

		return instance, nil
	}

	dic.mu.RUnlock()
	return nil, fmt.Errorf("service %s not found", name)
}

func (dic *DefaultDIContainer) GetTyped(name string, target interface{}) error {
	service, err := dic.Get(name)
	if err != nil {
		return err
	}

	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	serviceValue := reflect.ValueOf(service)
	targetValue.Elem().Set(serviceValue)

	return nil
}

func (dic *DefaultDIContainer) Inject(target interface{}) error {
	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	targetType := targetValue.Elem().Type()

	for i := 0; i < targetType.NumField(); i++ {
		field := targetType.Field(i)
		tag := field.Tag.Get("inject")

		if tag != "" {
			service, err := dic.Get(tag)
			if err != nil {
				continue // Optional injection
			}

			fieldValue := targetValue.Elem().Field(i)
			if fieldValue.CanSet() {
				serviceValue := reflect.ValueOf(service)
				if serviceValue.Type().AssignableTo(fieldValue.Type()) {
					fieldValue.Set(serviceValue)
				}
			}
		}
	}

	return nil
}

func (dic *DefaultDIContainer) Initialize() error {
	return nil
}

func (dic *DefaultDIContainer) Shutdown() error {
	dic.mu.Lock()
	defer dic.mu.Unlock()

	// Clear all services
	dic.services = make(map[string]interface{})
	dic.factories = make(map[string]Factory)
	dic.singletons = make(map[string]interface{})

	return nil
}

// DefaultMiddlewarePipeline implements MiddlewarePipeline
type DefaultMiddlewarePipeline struct {
	middlewares []Middleware
	poolManager *PerformancePoolManager
	mu          sync.RWMutex
}

// NewMiddlewarePipeline creates a new middleware pipeline
func NewMiddlewarePipeline() MiddlewarePipeline {
	return &DefaultMiddlewarePipeline{
		middlewares: make([]Middleware, 0),
	}
}

// NewMiddlewarePipelineWithPools creates a new middleware pipeline with pool manager
func NewMiddlewarePipelineWithPools(poolManager *PerformancePoolManager) MiddlewarePipeline {
	return &DefaultMiddlewarePipeline{
		middlewares: make([]Middleware, 0),
		poolManager: poolManager,
	}
}

func (mp *DefaultMiddlewarePipeline) SetMiddlewares(middlewares []Middleware) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.middlewares = make([]Middleware, len(middlewares))
	copy(mp.middlewares, middlewares)

	return nil
}

func (mp *DefaultMiddlewarePipeline) AddMiddleware(middleware Middleware) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.middlewares = append(mp.middlewares, middleware)
	return nil
}

func (mp *DefaultMiddlewarePipeline) RemoveMiddleware(name string) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	newMiddlewares := make([]Middleware, 0, len(mp.middlewares))
	for _, mw := range mp.middlewares {
		if mw.Name() != name {
			newMiddlewares = append(newMiddlewares, mw)
		}
	}

	mp.middlewares = newMiddlewares
	return nil
}

func (mp *DefaultMiddlewarePipeline) Process(ctx context.Context, req *Request) (*Response, error) {
	return mp.executeChain(0)(ctx, req)
}

func (mp *DefaultMiddlewarePipeline) ProcessWithTimeout(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return mp.Process(timeoutCtx, req)
}

func (mp *DefaultMiddlewarePipeline) GetMiddlewares() []Middleware {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	result := make([]Middleware, len(mp.middlewares))
	copy(result, mp.middlewares)
	return result
}

func (mp *DefaultMiddlewarePipeline) GetExecutionOrder() []string {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	order := make([]string, len(mp.middlewares))
	for i, mw := range mp.middlewares {
		order[i] = mw.Name()
	}
	return order
}

func (mp *DefaultMiddlewarePipeline) executeChain(index int) HandlerFunc {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if index >= len(mp.middlewares) {
		return func(ctx context.Context, req *Request) (*Response, error) {
			// Use pipeline's pool manager first, then fallback to global
			var poolManager *PerformancePoolManager
			if mp.poolManager != nil {
				poolManager = mp.poolManager
			} else {
				poolManager = GlobalPoolManager
			}

			if poolManager != nil && poolManager.IsEnabled() {
				resp := poolManager.GetResponse()
				resp.StatusCode = 200
				return resp, nil
			}
			// Fallback to direct allocation
			return &Response{
				StatusCode: 200,
				Headers:    make(map[string][]string),
				Body:       []byte{},
				Metadata:   make(map[string]interface{}),
			}, nil
		}
	}

	middleware := mp.middlewares[index]
	next := mp.executeChain(index + 1)

	return func(ctx context.Context, req *Request) (*Response, error) {
		return middleware.Handle(ctx, req, next)
	}
}

// DefaultMetricsCollector implements MetricsCollector
type DefaultMetricsCollector struct {
	metrics map[string]interface{}
	mu      sync.RWMutex
}

// NewDefaultMetricsCollector creates a new metrics collector
func NewDefaultMetricsCollector() MetricsCollector {
	return &DefaultMetricsCollector{
		metrics: make(map[string]interface{}),
	}
}

func (mc *DefaultMetricsCollector) RecordRequest(middleware, method string, duration time.Duration, success bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := fmt.Sprintf("request_%s_%s", middleware, method)
	mc.metrics[key] = map[string]interface{}{
		"duration":  duration.Milliseconds(),
		"success":   success,
		"timestamp": time.Now(),
	}
}

func (mc *DefaultMetricsCollector) RecordError(middleware, errorType, errorCode string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := fmt.Sprintf("error_%s_%s_%s", middleware, errorType, errorCode)
	mc.metrics[key] = map[string]interface{}{
		"timestamp": time.Now(),
	}
}

func (mc *DefaultMetricsCollector) RecordCacheOperation(middleware, operation string, hit bool, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := fmt.Sprintf("cache_%s_%s", middleware, operation)
	mc.metrics[key] = map[string]interface{}{
		"hit":       hit,
		"duration":  duration.Microseconds(),
		"timestamp": time.Now(),
	}
}

func (mc *DefaultMetricsCollector) RecordCustomMetric(name string, value float64, tags map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics[name] = map[string]interface{}{
		"value":     value,
		"tags":      tags,
		"timestamp": time.Now(),
	}
}

func (mc *DefaultMetricsCollector) RecordHistogram(name string, value float64, tags map[string]string) {
	mc.RecordCustomMetric(name, value, tags)
}

func (mc *DefaultMetricsCollector) RecordCounter(name string, value float64, tags map[string]string) {
	mc.RecordCustomMetric(name, value, tags)
}

func (mc *DefaultMetricsCollector) RecordMemoryUsage(middleware string, bytes int64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := fmt.Sprintf("memory_%s", middleware)
	mc.metrics[key] = map[string]interface{}{
		"bytes":     bytes,
		"timestamp": time.Now(),
	}
}

func (mc *DefaultMetricsCollector) RecordGoroutineCount(middleware string, count int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := fmt.Sprintf("goroutines_%s", middleware)
	mc.metrics[key] = map[string]interface{}{
		"count":     count,
		"timestamp": time.Now(),
	}
}

func (mc *DefaultMetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range mc.metrics {
		result[k] = v
	}
	return result
}

func (mc *DefaultMetricsCollector) GetMetricsByMiddleware(middleware string) map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]interface{})
	prefix := middleware + "_"

	for k, v := range mc.metrics {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			result[k] = v
		}
	}
	return result
}

func (mc *DefaultMetricsCollector) ResetMetrics() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics = make(map[string]interface{})
	return nil
}

// DefaultLogger implements Logger using go-zero's logx
type DefaultLogger struct{}

// NewDefaultLogger creates a new logger
func NewDefaultLogger() Logger {
	return &DefaultLogger{}
}

func (l *DefaultLogger) Debug(msg string, fields ...LogField) {
	logFields := make([]logx.LogField, len(fields))
	for i, field := range fields {
		logFields[i] = logx.Field(field.Key, field.Value)
	}
	logx.Debugw(msg, logFields...)
}

func (l *DefaultLogger) Info(msg string, fields ...LogField) {
	logFields := make([]logx.LogField, len(fields))
	for i, field := range fields {
		logFields[i] = logx.Field(field.Key, field.Value)
	}
	logx.Infow(msg, logFields...)
}

func (l *DefaultLogger) Warn(msg string, fields ...LogField) {
	logFields := make([]logx.LogField, len(fields))
	for i, field := range fields {
		logFields[i] = logx.Field(field.Key, field.Value)
	}
	logx.Errorw(msg, logFields...) // go-zero doesn't have Warn, use Error
}

func (l *DefaultLogger) Error(msg string, fields ...LogField) {
	logFields := make([]logx.LogField, len(fields))
	for i, field := range fields {
		logFields[i] = logx.Field(field.Key, field.Value)
	}
	logx.Errorw(msg, logFields...)
}

func (l *DefaultLogger) Fatal(msg string, fields ...LogField) {
	logFields := make([]logx.LogField, len(fields))
	for i, field := range fields {
		logFields[i] = logx.Field(field.Key, field.Value)
	}
	logx.Errorw(msg, logFields...)
	panic(msg) // go-zero doesn't have Fatal, use panic
}

func (l *DefaultLogger) With(fields ...LogField) Logger {
	// For simplicity, return the same logger
	// In a real implementation, you might want to create a new logger with context
	return l
}

func (l *DefaultLogger) WithContext(ctx context.Context) Logger {
	// For simplicity, return the same logger
	return l
}

func (l *DefaultLogger) Log(level LogLevel, msg string, fields ...LogField) {
	switch level {
	case DebugLevel:
		l.Debug(msg, fields...)
	case InfoLevel:
		l.Info(msg, fields...)
	case WarnLevel:
		l.Warn(msg, fields...)
	case ErrorLevel:
		l.Error(msg, fields...)
	case FatalLevel:
		l.Fatal(msg, fields...)
	}
}

// Helper functions for creating log fields
func String(key, value string) LogField {
	return LogField{Key: key, Value: value}
}

func Int(key string, value int) LogField {
	return LogField{Key: key, Value: value}
}

func Duration(key string, value time.Duration) LogField {
	return LogField{Key: key, Value: value}
}

func Error(err error) LogField {
	return LogField{Key: "error", Value: err}
}

func Bool(key string, value bool) LogField {
	return LogField{Key: key, Value: value}
}

func Field(key string, value interface{}) LogField {
	return LogField{Key: key, Value: value}
}

// PluginMiddleware adapts a Plugin to the Middleware interface
type PluginMiddleware struct {
	plugin Plugin
	name   string
}

func (pm *PluginMiddleware) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	return pm.plugin.Handle(ctx, req, next)
}

func (pm *PluginMiddleware) Name() string {
	if pm.name != "" {
		return pm.name
	}
	return pm.plugin.Name()
}

func (pm *PluginMiddleware) Priority() int {
	return pm.plugin.Priority()
}
