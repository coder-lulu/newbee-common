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
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// HealthEndpointManager provides HTTP endpoints for health checking
type HealthEndpointManager struct {
	engine  *CoreEngine
	mu      sync.RWMutex
	started bool

	// Health check configuration
	config *HealthEndpointConfig

	// Health check results cache
	lastHealthCheck time.Time
	cachedResult    *FrameworkHealthReport
	cacheTTL        time.Duration
}

// HealthEndpointConfig configures the health endpoints
type HealthEndpointConfig struct {
	Enabled        bool          `json:"enabled"`
	BasePath       string        `json:"base_path"`
	CacheTTL       time.Duration `json:"cache_ttl"`
	DetailedHealth bool          `json:"detailed_health"`
	IncludeMetrics bool          `json:"include_metrics"`
	Timeout        time.Duration `json:"timeout"`
}

// FrameworkHealthReport represents the overall health status
type FrameworkHealthReport struct {
	Status        string                       `json:"status"`
	Timestamp     time.Time                    `json:"timestamp"`
	Version       string                       `json:"version"`
	Uptime        time.Duration                `json:"uptime"`
	FrameworkInfo *FrameworkInfo               `json:"framework_info"`
	PluginHealth  map[string]*PluginHealth     `json:"plugin_health,omitempty"`
	SystemHealth  *SystemHealth                `json:"system_health,omitempty"`
	Dependencies  map[string]*DependencyHealth `json:"dependencies,omitempty"`
	Metrics       map[string]interface{}       `json:"metrics,omitempty"`
}

// FrameworkInfo contains basic framework information
type FrameworkInfo struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	StartTime      time.Time `json:"start_time"`
	PluginCount    int       `json:"plugin_count"`
	RunningPlugins int       `json:"running_plugins"`
}

// PluginHealth represents the health status of a plugin
type PluginHealth struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Status       string                 `json:"status"`
	LastCheck    time.Time              `json:"last_check"`
	Dependencies []string               `json:"dependencies,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
	Metrics      map[string]interface{} `json:"metrics,omitempty"`
}

// SystemHealth represents system-level health information
type SystemHealth struct {
	MemoryUsage    *MemoryStats `json:"memory_usage"`
	GoroutineCount int          `json:"goroutine_count"`
	GCStats        *GCStats     `json:"gc_stats"`
	CPUUsage       float64      `json:"cpu_usage,omitempty"`
	LoadAverage    []float64    `json:"load_average,omitempty"`
}

// MemoryStats contains memory usage statistics
type MemoryStats struct {
	Alloc        uint64  `json:"alloc"`
	TotalAlloc   uint64  `json:"total_alloc"`
	Sys          uint64  `json:"sys"`
	Lookups      uint64  `json:"lookups"`
	Mallocs      uint64  `json:"mallocs"`
	Frees        uint64  `json:"frees"`
	HeapAlloc    uint64  `json:"heap_alloc"`
	HeapSys      uint64  `json:"heap_sys"`
	HeapInuse    uint64  `json:"heap_inuse"`
	HeapReleased uint64  `json:"heap_released"`
	HeapObjects  uint64  `json:"heap_objects"`
	StackInuse   uint64  `json:"stack_inuse"`
	StackSys     uint64  `json:"stack_sys"`
	UsagePercent float64 `json:"usage_percent"`
}

// GCStats contains garbage collection statistics
type GCStats struct {
	NumGC      uint32        `json:"num_gc"`
	PauseTotal time.Duration `json:"pause_total"`
	PauseNs    []uint64      `json:"pause_ns,omitempty"`
	LastGC     time.Time     `json:"last_gc"`
	NextGC     uint64        `json:"next_gc"`
	EnabledGC  bool          `json:"enabled_gc"`
}

// DependencyHealth represents the health of external dependencies
type DependencyHealth struct {
	Name         string        `json:"name"`
	Type         string        `json:"type"`
	Status       string        `json:"status"`
	LastCheck    time.Time     `json:"last_check"`
	ResponseTime time.Duration `json:"response_time,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// NewHealthEndpointManager creates a new health endpoint manager
func NewHealthEndpointManager(engine *CoreEngine) *HealthEndpointManager {
	return &HealthEndpointManager{
		engine: engine,
		config: &HealthEndpointConfig{
			Enabled:        true,
			BasePath:       "/health",
			CacheTTL:       5 * time.Second,
			DetailedHealth: true,
			IncludeMetrics: false,
			Timeout:        30 * time.Second,
		},
		cacheTTL: 5 * time.Second,
	}
}

// Initialize configures the health endpoint manager
func (hem *HealthEndpointManager) Initialize(config *HealthEndpointConfig) error {
	hem.mu.Lock()
	defer hem.mu.Unlock()

	if config != nil {
		hem.config = config
		hem.cacheTTL = config.CacheTTL
	}

	return nil
}

// RegisterRoutes registers health check routes with an HTTP mux
func (hem *HealthEndpointManager) RegisterRoutes(mux *http.ServeMux) {
	if !hem.config.Enabled {
		return
	}

	basePath := hem.config.BasePath
	if basePath == "" {
		basePath = "/health"
	}

	// Basic health check
	mux.HandleFunc(basePath, hem.handleHealthCheck)

	// Detailed health check
	mux.HandleFunc(basePath+"/detailed", hem.handleDetailedHealthCheck)

	// Ready check (for Kubernetes readiness probes)
	mux.HandleFunc(basePath+"/ready", hem.handleReadyCheck)

	// Live check (for Kubernetes liveness probes)
	mux.HandleFunc(basePath+"/live", hem.handleLiveCheck)

	// Plugin-specific health
	mux.HandleFunc(basePath+"/plugins", hem.handlePluginHealth)

	// System health
	mux.HandleFunc(basePath+"/system", hem.handleSystemHealth)
}

// handleHealthCheck handles basic health check requests
func (hem *HealthEndpointManager) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	report, err := hem.getHealthReport(false)
	if err != nil {
		http.Error(w, fmt.Sprintf("Health check failed: %v", err), http.StatusInternalServerError)
		return
	}

	statusCode := http.StatusOK
	if report.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Simple response for basic health check
	basicResponse := map[string]interface{}{
		"status":    report.Status,
		"timestamp": report.Timestamp,
		"version":   report.Version,
		"uptime":    report.Uptime.String(),
	}

	json.NewEncoder(w).Encode(basicResponse)
}

// handleDetailedHealthCheck handles detailed health check requests
func (hem *HealthEndpointManager) handleDetailedHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	includeMetrics := r.URL.Query().Get("metrics") == "true"

	report, err := hem.getHealthReport(includeMetrics)
	if err != nil {
		http.Error(w, fmt.Sprintf("Detailed health check failed: %v", err), http.StatusInternalServerError)
		return
	}

	statusCode := http.StatusOK
	if report.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(report)
}

// handleReadyCheck handles readiness probe requests
func (hem *HealthEndpointManager) handleReadyCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if framework is running and all plugins are ready
	if !hem.engine.IsRunning() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Framework not running"))
		return
	}

	// Check if all plugins are healthy
	pluginHealth := hem.checkPluginHealth()
	for _, health := range pluginHealth {
		if health.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(fmt.Sprintf("Plugin %s not ready", health.Name)))
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleLiveCheck handles liveness probe requests
func (hem *HealthEndpointManager) handleLiveCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Basic liveness check - just ensure the framework is initialized
	if hem.engine == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Framework not initialized"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handlePluginHealth handles plugin-specific health requests
func (hem *HealthEndpointManager) handlePluginHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pluginName := r.URL.Query().Get("name")
	pluginHealth := hem.checkPluginHealth()

	if pluginName != "" {
		if health, exists := pluginHealth[pluginName]; exists {
			statusCode := http.StatusOK
			if health.Status != "healthy" {
				statusCode = http.StatusServiceUnavailable
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(health)
		} else {
			http.Error(w, "Plugin not found", http.StatusNotFound)
		}
		return
	}

	// Return all plugin health
	allHealthy := true
	for _, health := range pluginHealth {
		if health.Status != "healthy" {
			allHealthy = false
			break
		}
	}

	statusCode := http.StatusOK
	if !allHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plugins": pluginHealth,
		"summary": map[string]interface{}{
			"total":   len(pluginHealth),
			"healthy": allHealthy,
		},
	})
}

// handleSystemHealth handles system health requests
func (hem *HealthEndpointManager) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	systemHealth := hem.getSystemHealth()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(systemHealth)
}

// getHealthReport generates a comprehensive health report
func (hem *HealthEndpointManager) getHealthReport(includeMetrics bool) (*FrameworkHealthReport, error) {
	hem.mu.Lock()
	defer hem.mu.Unlock()

	// Check cache
	if hem.cachedResult != nil && time.Since(hem.lastHealthCheck) < hem.cacheTTL {
		if includeMetrics && hem.config.IncludeMetrics {
			// Add current metrics to cached result
			hem.cachedResult.Metrics = hem.getFrameworkMetrics()
		}
		return hem.cachedResult, nil
	}

	// Generate new health report
	ctx, cancel := context.WithTimeout(context.Background(), hem.config.Timeout)
	defer cancel()

	report := &FrameworkHealthReport{
		Timestamp: time.Now(),
	}

	// Framework info
	config := hem.engine.GetConfig()
	if config != nil {
		report.Version = config.Version
		report.FrameworkInfo = &FrameworkInfo{
			Name:           config.Name,
			Version:        config.Version,
			StartTime:      time.Now().Add(-time.Hour), // TODO: Track actual start time
			PluginCount:    len(hem.engine.ListPlugins()),
			RunningPlugins: hem.countRunningPlugins(),
		}
		report.Uptime = time.Since(report.FrameworkInfo.StartTime)
	}

	// Check framework status
	if !hem.engine.IsRunning() {
		report.Status = "unhealthy"
	} else {
		report.Status = "healthy"
	}

	// Plugin health (if detailed health is enabled)
	if hem.config.DetailedHealth {
		pluginHealth := hem.checkPluginHealthWithContext(ctx)
		report.PluginHealth = pluginHealth

		// Update overall status based on plugin health
		for _, health := range pluginHealth {
			if health.Status == "unhealthy" {
				report.Status = "unhealthy"
			} else if health.Status == "degraded" && report.Status == "healthy" {
				report.Status = "degraded"
			}
		}
	}

	// System health
	report.SystemHealth = hem.getSystemHealth()

	// Dependencies health
	report.Dependencies = hem.checkDependencyHealth(ctx)

	// Metrics (if requested and enabled)
	if includeMetrics && hem.config.IncludeMetrics {
		report.Metrics = hem.getFrameworkMetrics()
	}

	// Cache the result
	hem.cachedResult = report
	hem.lastHealthCheck = time.Now()

	return report, nil
}

// checkPluginHealth checks the health of all plugins
func (hem *HealthEndpointManager) checkPluginHealth() map[string]*PluginHealth {
	return hem.checkPluginHealthWithContext(context.Background())
}

// checkPluginHealthWithContext checks plugin health with context
func (hem *HealthEndpointManager) checkPluginHealthWithContext(ctx context.Context) map[string]*PluginHealth {
	pluginNames := hem.engine.ListPlugins()
	health := make(map[string]*PluginHealth)

	for _, name := range pluginNames {
		plugin, exists := hem.engine.GetPlugin(name)
		if !exists {
			continue
		}

		pluginHealth := &PluginHealth{
			Name:         plugin.Name(),
			Version:      plugin.Version(),
			LastCheck:    time.Now(),
			Dependencies: plugin.Dependencies(),
		}

		// Check plugin health
		select {
		case <-ctx.Done():
			pluginHealth.Status = "timeout"
		default:
			status := plugin.Health()
			switch status {
			case HealthStatusHealthy:
				pluginHealth.Status = "healthy"
			case HealthStatusDegraded:
				pluginHealth.Status = "degraded"
			case HealthStatusUnhealthy:
				pluginHealth.Status = "unhealthy"
			default:
				pluginHealth.Status = "unknown"
			}
		}

		// Get additional details for health check plugins
		if healthCheckPlugin, ok := plugin.(HealthCheckPlugin); ok {
			pluginHealth.Details = healthCheckPlugin.GetHealthDetails()
		}

		// Get metrics for metrics plugins
		if metricsPlugin, ok := plugin.(MetricsPlugin); ok {
			pluginHealth.Metrics = metricsPlugin.GetMetrics()
		}

		health[name] = pluginHealth
	}

	return health
}

// countRunningPlugins counts the number of running plugins
func (hem *HealthEndpointManager) countRunningPlugins() int {
	pluginNames := hem.engine.ListPlugins()
	count := 0

	for _, name := range pluginNames {
		if plugin, exists := hem.engine.GetPlugin(name); exists {
			if plugin.Health() == HealthStatusHealthy {
				count++
			}
		}
	}

	return count
}

// getSystemHealth gets system-level health information
func (hem *HealthEndpointManager) getSystemHealth() *SystemHealth {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	memoryStats := &MemoryStats{
		Alloc:        memStats.Alloc,
		TotalAlloc:   memStats.TotalAlloc,
		Sys:          memStats.Sys,
		Lookups:      memStats.Lookups,
		Mallocs:      memStats.Mallocs,
		Frees:        memStats.Frees,
		HeapAlloc:    memStats.HeapAlloc,
		HeapSys:      memStats.HeapSys,
		HeapInuse:    memStats.HeapInuse,
		HeapReleased: memStats.HeapReleased,
		HeapObjects:  memStats.HeapObjects,
		StackInuse:   memStats.StackInuse,
		StackSys:     memStats.StackSys,
	}

	// Calculate memory usage percentage
	if memStats.Sys > 0 {
		memoryStats.UsagePercent = float64(memStats.Alloc) / float64(memStats.Sys) * 100
	}

	gcStats := &GCStats{
		NumGC:      memStats.NumGC,
		PauseTotal: time.Duration(memStats.PauseTotalNs),
		EnabledGC:  memStats.EnableGC,
		NextGC:     memStats.NextGC,
	}

	// Get recent GC pause times (last 10)
	if len(memStats.PauseNs) > 0 && memStats.NumGC > 0 {
		recentPauses := make([]uint64, 0, 10)
		for i := 0; i < 10 && i < len(memStats.PauseNs) && i < int(memStats.NumGC); i++ {
			idx := (int(memStats.NumGC) - 1 - i) % len(memStats.PauseNs)
			if idx >= 0 && memStats.PauseNs[idx] > 0 {
				recentPauses = append(recentPauses, memStats.PauseNs[idx])
			}
		}
		gcStats.PauseNs = recentPauses
	}

	// Calculate last GC time
	if memStats.LastGC > 0 {
		gcStats.LastGC = time.Unix(0, int64(memStats.LastGC))
	}

	return &SystemHealth{
		MemoryUsage:    memoryStats,
		GoroutineCount: runtime.NumGoroutine(),
		GCStats:        gcStats,
	}
}

// checkDependencyHealth checks the health of external dependencies
func (hem *HealthEndpointManager) checkDependencyHealth(ctx context.Context) map[string]*DependencyHealth {
	// This is a placeholder - in a real implementation, you would check
	// actual dependencies like Redis, databases, external APIs, etc.
	dependencies := make(map[string]*DependencyHealth)

	// Example: Check if we have essential services registered in DI container
	// This could be expanded to actually ping services

	return dependencies
}

// getFrameworkMetrics gets framework-level metrics
func (hem *HealthEndpointManager) getFrameworkMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Get system metrics
	systemHealth := hem.getSystemHealth()
	metrics["memory_usage_mb"] = float64(systemHealth.MemoryUsage.Alloc) / 1024 / 1024
	metrics["goroutine_count"] = systemHealth.GoroutineCount
	metrics["gc_count"] = systemHealth.GCStats.NumGC

	// Get plugin count
	metrics["plugin_count"] = len(hem.engine.ListPlugins())
	metrics["running_plugins"] = hem.countRunningPlugins()

	return metrics
}

// Start starts the health endpoint manager
func (hem *HealthEndpointManager) Start() error {
	hem.mu.Lock()
	defer hem.mu.Unlock()

	if hem.started {
		return nil
	}

	hem.started = true
	return nil
}

// Stop stops the health endpoint manager
func (hem *HealthEndpointManager) Stop() error {
	hem.mu.Lock()
	defer hem.mu.Unlock()

	if !hem.started {
		return nil
	}

	hem.started = false
	hem.cachedResult = nil

	return nil
}
