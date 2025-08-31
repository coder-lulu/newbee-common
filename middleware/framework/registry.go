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
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// DefaultRegistry is the global middleware registry
var DefaultRegistry = NewRegistry()

// MiddlewareRegistry implements the Registry interface
type MiddlewareRegistry struct {
	factories map[string]MiddlewareFactory
	instances map[string]StandardMiddleware
	metadata  map[string]MiddlewareMetadata
	mutex     sync.RWMutex
	validator *ConfigValidator
}

// MiddlewareMetadata contains information about registered middleware
type MiddlewareMetadata struct {
	Name              string    `json:"name"`
	Factory           string    `json:"factory"`
	Version           string    `json:"version"`
	Description       string    `json:"description"`
	SupportedVersions []string  `json:"supported_versions"`
	RegisteredAt      time.Time `json:"registered_at"`
	Dependencies      []string  `json:"dependencies"`
	Tags              []string  `json:"tags"`
}

// NewRegistry creates a new middleware registry
func NewRegistry() Registry {
	return &MiddlewareRegistry{
		factories: make(map[string]MiddlewareFactory),
		instances: make(map[string]StandardMiddleware),
		metadata:  make(map[string]MiddlewareMetadata),
		validator: CreateStandardRules(),
	}
}

// RegisterFactory registers a middleware factory with the registry
func (r *MiddlewareRegistry) RegisterFactory(name string, factory MiddlewareFactory) error {
	if name == "" {
		return errors.New("middleware name cannot be empty")
	}

	if factory == nil {
		return errors.New("middleware factory cannot be nil")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if already registered
	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("middleware factory '%s' is already registered", name)
	}

	// Register factory
	r.factories[name] = factory

	// Store metadata
	r.metadata[name] = MiddlewareMetadata{
		Name:              name,
		Factory:           factory.Name(),
		SupportedVersions: factory.SupportedVersions(),
		RegisteredAt:      time.Now(),
	}

	return nil
}

// CreateMiddleware creates a middleware instance using the registered factory
func (r *MiddlewareRegistry) CreateMiddleware(name string, config interface{}) (StandardMiddleware, error) {
	r.mutex.RLock()
	factory, exists := r.factories[name]
	r.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("middleware factory '%s' not found", name)
	}

	// Validate configuration if provided
	if config != nil {
		if errors := r.validator.ValidateConfig(config); len(errors) > 0 {
			return nil, fmt.Errorf("configuration validation failed for '%s': %v", name, errors)
		}
	}

	// Create middleware instance
	middleware, err := factory.Create(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create middleware '%s': %w", name, err)
	}

	// Store instance
	r.mutex.Lock()
	r.instances[name] = middleware
	r.mutex.Unlock()

	return middleware, nil
}

// GetMiddleware returns a middleware instance by name
func (r *MiddlewareRegistry) GetMiddleware(name string) (StandardMiddleware, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	middleware, exists := r.instances[name]
	if !exists {
		return nil, fmt.Errorf("middleware instance '%s' not found", name)
	}

	return middleware, nil
}

// ListMiddleware returns all registered middleware names
func (r *MiddlewareRegistry) ListMiddleware() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// GetMetadata returns metadata for a specific middleware
func (r *MiddlewareRegistry) GetMetadata(name string) (MiddlewareMetadata, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metadata, exists := r.metadata[name]
	if !exists {
		return MiddlewareMetadata{}, fmt.Errorf("middleware '%s' not found", name)
	}

	return metadata, nil
}

// GetAllMetadata returns metadata for all registered middleware
func (r *MiddlewareRegistry) GetAllMetadata() map[string]MiddlewareMetadata {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]MiddlewareMetadata)
	for name, metadata := range r.metadata {
		result[name] = metadata
	}

	return result
}

// UnregisterMiddleware removes a middleware from the registry
func (r *MiddlewareRegistry) UnregisterMiddleware(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Close middleware instance if it exists
	if instance, exists := r.instances[name]; exists {
		if err := instance.Close(); err != nil {
			return fmt.Errorf("failed to close middleware '%s': %w", name, err)
		}
		delete(r.instances, name)
	}

	// Remove factory and metadata
	delete(r.factories, name)
	delete(r.metadata, name)

	return nil
}

// HealthCheck returns health status of all middleware instances
func (r *MiddlewareRegistry) HealthCheck() map[string]HealthStatus {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	healthStatuses := make(map[string]HealthStatus)

	for name, instance := range r.instances {
		healthStatuses[name] = instance.Health()
	}

	return healthStatuses
}

// GetMetrics returns metrics for all monitorable middleware
func (r *MiddlewareRegistry) GetMetrics() map[string]MiddlewareMetrics {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metrics := make(map[string]MiddlewareMetrics)

	for name, instance := range r.instances {
		if monitorable, ok := instance.(MonitorableMiddleware); ok {
			metrics[name] = monitorable.GetMetrics()
		}
	}

	return metrics
}

// InvalidateAllCaches invalidates caches for all cacheable middleware
func (r *MiddlewareRegistry) InvalidateAllCaches() error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var errors []error

	for name, instance := range r.instances {
		if cacheable, ok := instance.(CacheableMiddleware); ok {
			if err := cacheable.InvalidateCache(); err != nil {
				errors = append(errors, fmt.Errorf("failed to invalidate cache for '%s': %w", name, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cache invalidation failed for some middleware: %v", errors)
	}

	return nil
}

// Close gracefully closes all middleware instances and clears the registry
func (r *MiddlewareRegistry) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var errors []error

	// Close all instances
	for name, instance := range r.instances {
		if err := instance.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close middleware '%s': %w", name, err))
		}
	}

	// Clear all maps
	r.instances = make(map[string]StandardMiddleware)
	r.factories = make(map[string]MiddlewareFactory)
	r.metadata = make(map[string]MiddlewareMetadata)

	if len(errors) > 0 {
		return fmt.Errorf("some middleware failed to close: %v", errors)
	}

	return nil
}

// RegistryStats provides statistics about the registry
type RegistryStats struct {
	TotalFactories     int            `json:"total_factories"`
	TotalInstances     int            `json:"total_instances"`
	HealthyInstances   int            `json:"healthy_instances"`
	UnhealthyInstances int            `json:"unhealthy_instances"`
	MiddlewaresByType  map[string]int `json:"middleware_by_type"`
	LastHealthCheck    time.Time      `json:"last_health_check"`
}

// GetStats returns statistics about the registry
func (r *MiddlewareRegistry) GetStats() RegistryStats {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	stats := RegistryStats{
		TotalFactories:    len(r.factories),
		TotalInstances:    len(r.instances),
		MiddlewaresByType: make(map[string]int),
		LastHealthCheck:   time.Now(),
	}

	// Count healthy/unhealthy instances
	for _, instance := range r.instances {
		health := instance.Health()
		if health == HealthStatusHealthy {
			stats.HealthyInstances++
		} else {
			stats.UnhealthyInstances++
		}

		// Count by type (using interface checks)
		middlewareType := "basic"
		if _, ok := instance.(ConfigurableMiddleware); ok {
			middlewareType = "configurable"
		}
		if _, ok := instance.(MonitorableMiddleware); ok {
			middlewareType = "monitorable"
		}
		if _, ok := instance.(CacheableMiddleware); ok {
			middlewareType = "cacheable"
		}

		stats.MiddlewaresByType[middlewareType]++
	}

	return stats
}

// Convenience functions for the default registry

// Register registers a middleware factory with the default registry
func Register(name string, factory MiddlewareFactory) error {
	return DefaultRegistry.RegisterFactory(name, factory)
}

// Create creates a middleware instance using the default registry
func Create(name string, config interface{}) (StandardMiddleware, error) {
	return DefaultRegistry.CreateMiddleware(name, config)
}

// Get returns a middleware instance from the default registry
func Get(name string) (StandardMiddleware, error) {
	return DefaultRegistry.GetMiddleware(name)
}

// List returns all registered middleware names from the default registry
func List() []string {
	return DefaultRegistry.ListMiddleware()
}

// CheckAllHealth returns health status of all middleware in the default registry
func CheckAllHealth() map[string]HealthStatus {
	return DefaultRegistry.HealthCheck()
}

// GetAllMetrics returns metrics for all middleware in the default registry
func GetAllMetrics() map[string]MiddlewareMetrics {
	return DefaultRegistry.GetMetrics()
}
