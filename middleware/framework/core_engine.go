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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// CoreEngine implements the FrameworkCore interface
type CoreEngine struct {
	config           *FrameworkConfig
	plugins          map[string]Plugin
	pipeline         MiddlewarePipeline
	configManager    ConfigurationManager
	dependencyGraph  *DependencyGraph
	metricsCollector MetricsCollector
	logger           Logger
	diContainer      DependencyInjector

	// Framework management
	healthManager   *HealthEndpointManager
	shutdownManager *GracefulShutdownManager
	poolManager     *PerformancePoolManager
	startTime       time.Time

	mu      sync.RWMutex
	running bool
}

// NewCoreEngine creates a new framework core engine
func NewCoreEngine() *CoreEngine {
	engine := &CoreEngine{
		plugins:         make(map[string]Plugin),
		dependencyGraph: NewDependencyGraph(),
		startTime:       time.Now(),
	}

	// Initialize pool manager first
	engine.poolManager = NewPerformancePoolManager()

	// Initialize default components
	engine.configManager = NewConfigurationManager()
	engine.pipeline = NewMiddlewarePipelineWithPools(engine.poolManager)
	engine.metricsCollector = NewDefaultMetricsCollector()
	engine.logger = NewDefaultLogger()
	engine.diContainer = NewDIContainer()

	// Initialize management components
	engine.healthManager = NewHealthEndpointManager(engine)
	engine.shutdownManager = NewGracefulShutdownManager(engine)

	return engine
}

// Initialize initializes the framework with the given configuration
func (ce *CoreEngine) Initialize(config *FrameworkConfig) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.running {
		return fmt.Errorf("framework is already running")
	}

	ce.config = config
	ce.logger.Info("Initializing framework", String("name", config.Name), String("version", config.Version))

	// Initialize configuration manager
	if err := ce.configManager.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize config manager: %w", err)
	}

	// Initialize dependency injection container
	if err := ce.initializeDI(); err != nil {
		return fmt.Errorf("failed to initialize DI container: %w", err)
	}

	// Initialize metrics collector if enabled
	if config.MetricsEnabled {
		if err := ce.initializeMetrics(); err != nil {
			return fmt.Errorf("failed to initialize metrics collector: %w", err)
		}
	}

	// Initialize health manager
	if err := ce.healthManager.Initialize(nil); err != nil {
		return fmt.Errorf("failed to initialize health manager: %w", err)
	}

	// Initialize shutdown manager
	if err := ce.shutdownManager.Initialize(nil, ce.logger); err != nil {
		return fmt.Errorf("failed to initialize shutdown manager: %w", err)
	}

	ce.logger.Info("Framework initialized successfully")
	return nil
}

// Start starts the framework and all registered plugins
func (ce *CoreEngine) Start() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.running {
		return fmt.Errorf("framework is already running")
	}

	ce.logger.Info("Starting framework")

	// Validate plugin dependencies
	if err := ce.validateDependencies(); err != nil {
		return fmt.Errorf("dependency validation failed: %w", err)
	}

	// Get plugin start order based on dependencies and priorities
	startOrder, err := ce.getPluginStartOrder()
	if err != nil {
		return fmt.Errorf("failed to determine plugin start order: %w", err)
	}

	// Start plugins in order
	startedPlugins := make([]string, 0)
	for _, pluginName := range startOrder {
		plugin := ce.plugins[pluginName]

		ce.logger.Info("Starting plugin", String("plugin", pluginName))
		if err := plugin.Start(); err != nil {
			// Rollback started plugins
			ce.rollbackStart(startedPlugins)
			return fmt.Errorf("failed to start plugin %s: %w", pluginName, err)
		}

		startedPlugins = append(startedPlugins, pluginName)

		// Record plugin start metric
		if ce.config.MetricsEnabled {
			ce.metricsCollector.RecordCustomMetric("plugin_started", 1.0, map[string]string{
				"plugin": pluginName,
			})
		}
	}

	// Build middleware pipeline
	if err := ce.buildPipeline(); err != nil {
		ce.rollbackStart(startedPlugins)
		return fmt.Errorf("failed to build middleware pipeline: %w", err)
	}

	// Start health manager
	if err := ce.healthManager.Start(); err != nil {
		ce.rollbackStart(startedPlugins)
		return fmt.Errorf("failed to start health manager: %w", err)
	}

	ce.running = true
	ce.logger.Info("Framework started successfully", Int("plugins", len(startedPlugins)))

	return nil
}

// Stop stops the framework and all plugins
func (ce *CoreEngine) Stop() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if !ce.running {
		return nil
	}

	ce.logger.Info("Stopping framework")

	// Stop health manager first
	if err := ce.healthManager.Stop(); err != nil {
		ce.logger.Error("Failed to stop health manager", Error(err))
	}

	// Get stop order (reverse of start order)
	stopOrder := ce.getPluginStopOrder()

	// Stop plugins in reverse order
	for _, pluginName := range stopOrder {
		if plugin, exists := ce.plugins[pluginName]; exists {
			ce.logger.Info("Stopping plugin", String("plugin", pluginName))
			if err := plugin.Stop(); err != nil {
				ce.logger.Error("Failed to stop plugin", String("plugin", pluginName), Error(err))
			}
		}
	}

	// Shutdown DI container
	if err := ce.diContainer.Shutdown(); err != nil {
		ce.logger.Error("Failed to shutdown DI container", Error(err))
	}

	ce.running = false
	ce.logger.Info("Framework stopped successfully")

	return nil
}

// IsRunning returns whether the framework is currently running
func (ce *CoreEngine) IsRunning() bool {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.running
}

// RegisterPlugin registers a plugin with the framework
func (ce *CoreEngine) RegisterPlugin(plugin Plugin) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	name := plugin.Name()

	// Check if plugin is already registered
	if _, exists := ce.plugins[name]; exists {
		return fmt.Errorf("plugin %s is already registered", name)
	}

	// Validate plugin metadata
	if err := ce.validatePlugin(plugin); err != nil {
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	// Get plugin configuration
	pluginConfig := ce.configManager.GetPluginConfig(name)

	// Check if plugin is enabled
	if !pluginConfig.Enabled {
		ce.logger.Info("Plugin is disabled, skipping registration", String("plugin", name))
		return nil
	}

	// Initialize plugin
	ce.logger.Info("Initializing plugin", String("plugin", name))
	if err := plugin.Initialize(pluginConfig); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
	}

	// Add to dependency graph
	ce.dependencyGraph.AddNode(name, plugin.Dependencies())

	// Register plugin
	ce.plugins[name] = plugin

	// Inject dependencies
	if err := ce.diContainer.Inject(plugin); err != nil {
		delete(ce.plugins, name)
		return fmt.Errorf("failed to inject dependencies for plugin %s: %w", name, err)
	}

	// If framework is running, start the plugin immediately
	if ce.running {
		if err := plugin.Start(); err != nil {
			delete(ce.plugins, name)
			return fmt.Errorf("failed to start plugin %s: %w", name, err)
		}

		// Rebuild pipeline to include new plugin
		if err := ce.buildPipeline(); err != nil {
			plugin.Stop()
			delete(ce.plugins, name)
			return fmt.Errorf("failed to rebuild pipeline after adding plugin %s: %w", name, err)
		}
	}

	ce.logger.Info("Plugin registered successfully", String("plugin", name))
	return nil
}

// UnregisterPlugin unregisters a plugin from the framework
func (ce *CoreEngine) UnregisterPlugin(name string) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	plugin, exists := ce.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s is not registered", name)
	}

	// Check if other plugins depend on this one
	dependents := ce.dependencyGraph.GetDependents(name)
	if len(dependents) > 0 {
		return fmt.Errorf("cannot unregister plugin %s: depended on by %v", name, dependents)
	}

	// Stop plugin if framework is running
	if ce.running {
		ce.logger.Info("Stopping plugin", String("plugin", name))
		if err := plugin.Stop(); err != nil {
			ce.logger.Error("Failed to stop plugin during unregistration", String("plugin", name), Error(err))
		}
	}

	// Remove from dependency graph
	ce.dependencyGraph.RemoveNode(name)

	// Unregister plugin
	delete(ce.plugins, name)

	// Rebuild pipeline if framework is running
	if ce.running {
		if err := ce.buildPipeline(); err != nil {
			ce.logger.Error("Failed to rebuild pipeline after removing plugin", String("plugin", name), Error(err))
		}
	}

	ce.logger.Info("Plugin unregistered successfully", String("plugin", name))
	return nil
}

// GetPlugin returns a plugin by name
func (ce *CoreEngine) GetPlugin(name string) (Plugin, bool) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	plugin, exists := ce.plugins[name]
	return plugin, exists
}

// ListPlugins returns a list of all registered plugin names
func (ce *CoreEngine) ListPlugins() []string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	names := make([]string, 0, len(ce.plugins))
	for name := range ce.plugins {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// ProcessRequest processes a request through the middleware pipeline
func (ce *CoreEngine) ProcessRequest(ctx context.Context, req *Request) (*Response, error) {
	if !ce.running {
		return nil, fmt.Errorf("framework is not running")
	}

	// Record request metrics
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		ce.metricsCollector.RecordRequest("framework", req.Method, duration, true)
	}()

	// Apply request timeout if configured
	if ce.config.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ce.config.RequestTimeout)
		defer cancel()
	}

	// Process through pipeline
	return ce.pipeline.Process(ctx, req)
}

// CreateHandler creates an HTTP handler function
func (ce *CoreEngine) CreateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Convert HTTP request to framework request
		req := ce.convertHTTPRequest(r)
		defer ce.poolManager.PutRequest(req) // Return request to pool when done

		// Process request
		resp, err := ce.ProcessRequest(r.Context(), req)
		if err != nil {
			ce.logger.Error("Request processing failed", String("path", r.URL.Path), Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Write response (will also return response to pool)
		ce.writeHTTPResponse(w, resp)
	}
}

// GetConfig returns the framework configuration
func (ce *CoreEngine) GetConfig() *FrameworkConfig {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.config
}

// ReloadConfig reloads the framework configuration
func (ce *CoreEngine) ReloadConfig() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.logger.Info("Reloading configuration")

	// Reload configuration through config manager
	if err := ce.configManager.ReloadConfig(); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Update framework config
	ce.config = ce.configManager.GetFrameworkConfig()

	// Reload plugin configurations
	for name, plugin := range ce.plugins {
		if configurablePlugin, ok := plugin.(ConfigurablePlugin); ok {
			pluginConfig := ce.configManager.GetPluginConfig(name)
			if err := configurablePlugin.ReloadConfig(pluginConfig); err != nil {
				ce.logger.Error("Failed to reload plugin config", String("plugin", name), Error(err))
			}
		}
	}

	ce.logger.Info("Configuration reloaded successfully")
	return nil
}

// Private methods

func (ce *CoreEngine) initializeDI() error {
	// Register framework services
	if err := ce.diContainer.Register("config", ce.config); err != nil {
		return err
	}

	if err := ce.diContainer.Register("logger", ce.logger); err != nil {
		return err
	}

	if err := ce.diContainer.Register("metrics", ce.metricsCollector); err != nil {
		return err
	}

	return ce.diContainer.Initialize()
}

func (ce *CoreEngine) initializeMetrics() error {
	// Initialize metrics collector with framework-specific metrics
	ce.metricsCollector.RecordCustomMetric("framework_initialized", 1.0, map[string]string{
		"version": ce.config.Version,
	})

	return nil
}

func (ce *CoreEngine) validatePlugin(plugin Plugin) error {
	if plugin.Name() == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if plugin.Version() == "" {
		return fmt.Errorf("plugin version cannot be empty")
	}

	// Validate dependencies exist
	for _, dep := range plugin.Dependencies() {
		if _, exists := ce.plugins[dep]; !exists {
			return fmt.Errorf("dependency %s not found", dep)
		}
	}

	return nil
}

func (ce *CoreEngine) validateDependencies() error {
	// Check for circular dependencies
	if err := ce.dependencyGraph.DetectCycles(); err != nil {
		return err
	}

	// Check that all dependencies are satisfied
	for name, plugin := range ce.plugins {
		for _, dep := range plugin.Dependencies() {
			if _, exists := ce.plugins[dep]; !exists {
				return fmt.Errorf("plugin %s has unsatisfied dependency: %s", name, dep)
			}
		}
	}

	return nil
}

func (ce *CoreEngine) getPluginStartOrder() ([]string, error) {
	// Get topological order based on dependencies
	topologicalOrder, err := ce.dependencyGraph.TopologicalSort()
	if err != nil {
		return nil, err
	}

	// Group plugins by priority within dependency constraints
	pluginsByPriority := make(map[int][]string)
	for _, name := range topologicalOrder {
		if plugin, exists := ce.plugins[name]; exists {
			priority := plugin.Priority()
			pluginsByPriority[priority] = append(pluginsByPriority[priority], name)
		}
	}

	// Sort priorities
	priorities := make([]int, 0, len(pluginsByPriority))
	for priority := range pluginsByPriority {
		priorities = append(priorities, priority)
	}
	sort.Ints(priorities)

	// Build final order
	startOrder := make([]string, 0, len(ce.plugins))
	for _, priority := range priorities {
		plugins := pluginsByPriority[priority]
		sort.Strings(plugins) // Deterministic order within same priority
		startOrder = append(startOrder, plugins...)
	}

	return startOrder, nil
}

func (ce *CoreEngine) getPluginStopOrder() []string {
	startOrder, _ := ce.getPluginStartOrder()

	// Reverse the start order for stop order
	stopOrder := make([]string, len(startOrder))
	for i, j := 0, len(startOrder)-1; i < len(startOrder); i, j = i+1, j-1 {
		stopOrder[i] = startOrder[j]
	}

	return stopOrder
}

func (ce *CoreEngine) buildPipeline() error {
	// Get enabled plugins in execution order
	execOrder, err := ce.getPluginStartOrder()
	if err != nil {
		return err
	}

	// Create middleware list
	middlewares := make([]Middleware, 0, len(execOrder))
	for _, pluginName := range execOrder {
		if plugin, exists := ce.plugins[pluginName]; exists {
			middleware := &PluginMiddleware{
				plugin: plugin,
				name:   pluginName,
			}
			middlewares = append(middlewares, middleware)
		}
	}

	// Set middlewares in pipeline
	return ce.pipeline.SetMiddlewares(middlewares)
}

func (ce *CoreEngine) rollbackStart(startedPlugins []string) {
	for i := len(startedPlugins) - 1; i >= 0; i-- {
		pluginName := startedPlugins[i]
		if plugin, exists := ce.plugins[pluginName]; exists {
			ce.logger.Info("Rolling back plugin start", String("plugin", pluginName))
			if err := plugin.Stop(); err != nil {
				ce.logger.Error("Failed to stop plugin during rollback", String("plugin", pluginName), Error(err))
			}
		}
	}
}

func (ce *CoreEngine) convertHTTPRequest(r *http.Request) *Request {
	// Get request from pool for better performance
	req := ce.poolManager.GetRequest()

	// Set basic fields with string interning for memory efficiency
	req.ID = generateRequestID()
	req.Method = ce.poolManager.InternString(r.Method)
	req.Path = ce.poolManager.InternString(r.URL.Path)
	req.RemoteAddr = r.RemoteAddr
	req.UserAgent = r.UserAgent()
	req.ContentType = ce.poolManager.InternString(r.Header.Get("Content-Type"))
	req.Timestamp = time.Now()

	// Copy headers efficiently with string interning
	for key, values := range r.Header {
		internedKey := ce.poolManager.InternString(key)
		req.Headers[internedKey] = make([]string, len(values))
		for i, value := range values {
			req.Headers[internedKey][i] = ce.poolManager.InternString(value)
		}
	}

	// Read body efficiently using buffer pool
	if r.Body != nil {
		buf := ce.poolManager.GetBuffer()
		if _, err := buf.ReadFrom(r.Body); err == nil {
			req.Body = make([]byte, buf.Len())
			copy(req.Body, buf.Bytes())

			// Restore body for potential re-reading
			r.Body = io.NopCloser(bytes.NewReader(req.Body))
		}
		ce.poolManager.PutBuffer(buf)
	}

	return req
}

func (ce *CoreEngine) writeHTTPResponse(w http.ResponseWriter, resp *Response) {
	// Set headers
	for key, values := range resp.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Write body
	if len(resp.Body) > 0 {
		w.Write(resp.Body)
	}

	// Return response to pool for reuse
	defer ce.poolManager.PutResponse(resp)
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// GetHealthManager returns the health endpoint manager
func (ce *CoreEngine) GetHealthManager() *HealthEndpointManager {
	return ce.healthManager
}

// GetShutdownManager returns the graceful shutdown manager
func (ce *CoreEngine) GetShutdownManager() *GracefulShutdownManager {
	return ce.shutdownManager
}

// GetStartTime returns the framework start time
func (ce *CoreEngine) GetStartTime() time.Time {
	return ce.startTime
}

// GetUptime returns how long the framework has been running
func (ce *CoreEngine) GetUptime() time.Duration {
	return time.Since(ce.startTime)
}

// GracefulShutdown initiates graceful shutdown
func (ce *CoreEngine) GracefulShutdown(ctx context.Context) error {
	ce.logger.Info("Initiating graceful shutdown")
	return ce.shutdownManager.Shutdown(ctx)
}

// GetPoolManager returns the performance pool manager
func (ce *CoreEngine) GetPoolManager() *PerformancePoolManager {
	return ce.poolManager
}

// GetPoolMetrics returns performance metrics from object pools
func (ce *CoreEngine) GetPoolMetrics() map[string]interface{} {
	return ce.poolManager.GetAllMetrics()
}

// ResetPoolMetrics resets all pool metrics
func (ce *CoreEngine) ResetPoolMetrics() {
	ce.poolManager.ResetAllMetrics()
}

// SetPoolEnabled enables or disables object pooling
func (ce *CoreEngine) SetPoolEnabled(enabled bool) {
	ce.poolManager.SetEnabled(enabled)
}
