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
	"sync"
	"time"
)

// BasePlugin provides a base implementation of the Plugin interface
type BasePlugin struct {
	name         string
	version      string
	description  string
	dependencies []string
	priority     int
	config       PluginConfig
	metadata     *PluginMetadata
	running      bool

	logger           Logger           `inject:"logger"`
	metricsCollector MetricsCollector `inject:"metrics"`

	mu sync.RWMutex
}

// NewBasePlugin creates a new base plugin
func NewBasePlugin(name, version, description string) *BasePlugin {
	return &BasePlugin{
		name:         name,
		version:      version,
		description:  description,
		dependencies: make([]string, 0),
		priority:     100,
		running:      false,
		metadata: &PluginMetadata{
			Name:        name,
			Version:     version,
			Description: description,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}
}

// PluginInfo implementation
func (bp *BasePlugin) Name() string {
	return bp.name
}

func (bp *BasePlugin) Version() string {
	return bp.version
}

func (bp *BasePlugin) Description() string {
	return bp.description
}

func (bp *BasePlugin) Dependencies() []string {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	result := make([]string, len(bp.dependencies))
	copy(result, bp.dependencies)
	return result
}

func (bp *BasePlugin) Priority() int {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.priority
}

func (bp *BasePlugin) Metadata() *PluginMetadata {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.metadata
}

// PluginLifecycle implementation
func (bp *BasePlugin) Initialize(config PluginConfig) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.config = config

	// Override priority if specified in config
	if priority, exists := config.Config["priority"]; exists {
		if p, ok := priority.(int); ok {
			bp.priority = p
		}
	}

	if bp.logger != nil {
		bp.logger.Info("Plugin initialized", String("plugin", bp.name))
	}

	return nil
}

func (bp *BasePlugin) Start() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.running {
		return fmt.Errorf("plugin %s is already running", bp.name)
	}

	bp.running = true

	if bp.logger != nil {
		bp.logger.Info("Plugin started", String("plugin", bp.name))
	}

	if bp.metricsCollector != nil {
		bp.metricsCollector.RecordCustomMetric("plugin_start", 1.0, map[string]string{
			"plugin": bp.name,
		})
	}

	return nil
}

func (bp *BasePlugin) Stop() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if !bp.running {
		return nil
	}

	bp.running = false

	if bp.logger != nil {
		bp.logger.Info("Plugin stopped", String("plugin", bp.name))
	}

	if bp.metricsCollector != nil {
		bp.metricsCollector.RecordCustomMetric("plugin_stop", 1.0, map[string]string{
			"plugin": bp.name,
		})
	}

	return nil
}

func (bp *BasePlugin) Health() HealthStatus {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	if bp.running {
		return HealthStatusHealthy
	}
	return HealthStatusUnhealthy
}

// MiddlewareHandler implementation (default pass-through)
func (bp *BasePlugin) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	// Default implementation just passes through
	return next(ctx, req)
}

// Configuration methods
func (bp *BasePlugin) SetDependencies(dependencies []string) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.dependencies = make([]string, len(dependencies))
	copy(bp.dependencies, dependencies)
}

func (bp *BasePlugin) SetPriority(priority int) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.priority = priority
}

func (bp *BasePlugin) SetMetadata(metadata *PluginMetadata) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.metadata = metadata
}

func (bp *BasePlugin) GetConfig() PluginConfig {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.config
}

func (bp *BasePlugin) IsRunning() bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.running
}

// ConfigurablePlugin implementation
type ConfigurableBasePlugin struct {
	*BasePlugin
}

func NewConfigurableBasePlugin(name, version, description string) *ConfigurableBasePlugin {
	return &ConfigurableBasePlugin{
		BasePlugin: NewBasePlugin(name, version, description),
	}
}

func (cbp *ConfigurableBasePlugin) ReloadConfig(config PluginConfig) error {
	cbp.mu.Lock()
	defer cbp.mu.Unlock()

	oldConfig := cbp.config
	cbp.config = config

	// Override priority if specified in config
	if priority, exists := config.Config["priority"]; exists {
		if p, ok := priority.(int); ok {
			cbp.priority = p
		}
	}

	if cbp.logger != nil {
		cbp.logger.Info("Plugin config reloaded",
			String("plugin", cbp.name),
			Field("old_enabled", oldConfig.Enabled),
			Field("new_enabled", config.Enabled))
	}

	return nil
}

func (cbp *ConfigurableBasePlugin) ValidateConfig(config PluginConfig) error {
	// Basic validation - can be overridden
	if !config.Enabled {
		return nil // Disabled plugins don't need validation
	}

	// Check priority range
	if priority, exists := config.Config["priority"]; exists {
		if p, ok := priority.(int); ok {
			if p < 0 || p > 1000 {
				return fmt.Errorf("priority must be between 0 and 1000, got %d", p)
			}
		}
	}

	return nil
}

// MetricsPlugin implementation
type MetricsBasePlugin struct {
	*BasePlugin
	customMetrics map[string]interface{}
	metricsMu     sync.RWMutex
}

func NewMetricsBasePlugin(name, version, description string) *MetricsBasePlugin {
	return &MetricsBasePlugin{
		BasePlugin:    NewBasePlugin(name, version, description),
		customMetrics: make(map[string]interface{}),
	}
}

func (mbp *MetricsBasePlugin) GetMetrics() map[string]interface{} {
	mbp.metricsMu.RLock()
	defer mbp.metricsMu.RUnlock()

	result := make(map[string]interface{})

	// Add basic plugin metrics
	result["plugin_running"] = mbp.IsRunning()
	result["plugin_config_enabled"] = mbp.GetConfig().Enabled
	result["plugin_priority"] = mbp.Priority()

	// Add custom metrics
	for k, v := range mbp.customMetrics {
		result[k] = v
	}

	return result
}

func (mbp *MetricsBasePlugin) ResetMetrics() error {
	mbp.metricsMu.Lock()
	defer mbp.metricsMu.Unlock()

	mbp.customMetrics = make(map[string]interface{})
	return nil
}

func (mbp *MetricsBasePlugin) SetMetric(name string, value interface{}) {
	mbp.metricsMu.Lock()
	defer mbp.metricsMu.Unlock()

	mbp.customMetrics[name] = value
}

// HealthCheckPlugin implementation
type HealthCheckBasePlugin struct {
	*BasePlugin
	healthDetails map[string]interface{}
	healthMu      sync.RWMutex
}

func NewHealthCheckBasePlugin(name, version, description string) *HealthCheckBasePlugin {
	return &HealthCheckBasePlugin{
		BasePlugin:    NewBasePlugin(name, version, description),
		healthDetails: make(map[string]interface{}),
	}
}

func (hbp *HealthCheckBasePlugin) HealthCheck() HealthStatus {
	// Extended health check logic
	status := hbp.Health()

	// Add custom health check logic here
	// For example, check external dependencies, resource availability, etc.

	return status
}

func (hbp *HealthCheckBasePlugin) GetHealthDetails() map[string]interface{} {
	hbp.healthMu.RLock()
	defer hbp.healthMu.RUnlock()

	result := make(map[string]interface{})

	// Add basic health info
	result["status"] = hbp.Health().String()
	result["running"] = hbp.IsRunning()
	result["last_check"] = time.Now()

	// Add custom health details
	for k, v := range hbp.healthDetails {
		result[k] = v
	}

	return result
}

func (hbp *HealthCheckBasePlugin) SetHealthDetail(name string, value interface{}) {
	hbp.healthMu.Lock()
	defer hbp.healthMu.Unlock()

	hbp.healthDetails[name] = value
}

// CompositePlugin combines multiple plugin capabilities
type CompositePlugin struct {
	base                 *BasePlugin
	configurableFeatures *ConfigurableBasePlugin
	metricsFeatures      *MetricsBasePlugin
	healthFeatures       *HealthCheckBasePlugin
}

func NewCompositePlugin(name, version, description string) *CompositePlugin {
	base := NewBasePlugin(name, version, description)

	return &CompositePlugin{
		base:                 base,
		configurableFeatures: &ConfigurableBasePlugin{BasePlugin: base},
		metricsFeatures:      &MetricsBasePlugin{BasePlugin: base, customMetrics: make(map[string]interface{})},
		healthFeatures:       &HealthCheckBasePlugin{BasePlugin: base, healthDetails: make(map[string]interface{})},
	}
}

// PluginInfo implementation - delegate to base
func (cp *CompositePlugin) Name() string {
	return cp.base.Name()
}

func (cp *CompositePlugin) Version() string {
	return cp.base.Version()
}

func (cp *CompositePlugin) Description() string {
	return cp.base.Description()
}

func (cp *CompositePlugin) Dependencies() []string {
	return cp.base.Dependencies()
}

func (cp *CompositePlugin) Priority() int {
	return cp.base.Priority()
}

func (cp *CompositePlugin) Metadata() *PluginMetadata {
	return cp.base.Metadata()
}

// PluginLifecycle implementation - delegate to base
func (cp *CompositePlugin) Initialize(config PluginConfig) error {
	return cp.base.Initialize(config)
}

func (cp *CompositePlugin) Start() error {
	return cp.base.Start()
}

func (cp *CompositePlugin) Stop() error {
	return cp.base.Stop()
}

func (cp *CompositePlugin) Health() HealthStatus {
	return cp.base.Health()
}

// MiddlewareHandler implementation - delegate to base
func (cp *CompositePlugin) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	return cp.base.Handle(ctx, req, next)
}

// ConfigurablePlugin implementation - delegate to configurable features
func (cp *CompositePlugin) ReloadConfig(config PluginConfig) error {
	return cp.configurableFeatures.ReloadConfig(config)
}

func (cp *CompositePlugin) ValidateConfig(config PluginConfig) error {
	return cp.configurableFeatures.ValidateConfig(config)
}

// MetricsPlugin implementation - delegate to metrics features
func (cp *CompositePlugin) GetMetrics() map[string]interface{} {
	return cp.metricsFeatures.GetMetrics()
}

func (cp *CompositePlugin) ResetMetrics() error {
	return cp.metricsFeatures.ResetMetrics()
}

func (cp *CompositePlugin) SetMetric(name string, value interface{}) {
	cp.metricsFeatures.SetMetric(name, value)
}

// HealthCheckPlugin implementation - delegate to health features
func (cp *CompositePlugin) HealthCheck() HealthStatus {
	return cp.healthFeatures.HealthCheck()
}

func (cp *CompositePlugin) GetHealthDetails() map[string]interface{} {
	return cp.healthFeatures.GetHealthDetails()
}

func (cp *CompositePlugin) SetHealthDetail(name string, value interface{}) {
	cp.healthFeatures.SetHealthDetail(name, value)
}

// Additional helper methods
func (cp *CompositePlugin) SetDependencies(dependencies []string) {
	cp.base.SetDependencies(dependencies)
}

func (cp *CompositePlugin) SetPriority(priority int) {
	cp.base.SetPriority(priority)
}

func (cp *CompositePlugin) SetMetadata(metadata *PluginMetadata) {
	cp.base.SetMetadata(metadata)
}

func (cp *CompositePlugin) GetConfig() PluginConfig {
	return cp.base.GetConfig()
}

func (cp *CompositePlugin) IsRunning() bool {
	return cp.base.IsRunning()
}

// Ensure CompositePlugin implements all interfaces
var _ Plugin = (*CompositePlugin)(nil)
var _ ConfigurablePlugin = (*CompositePlugin)(nil)
var _ MetricsPlugin = (*CompositePlugin)(nil)
var _ HealthCheckPlugin = (*CompositePlugin)(nil)
