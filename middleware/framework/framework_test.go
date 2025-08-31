// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFrameworkBasicFunctionality tests basic framework operations
func TestFrameworkBasicFunctionality(t *testing.T) {
	// Create framework
	engine := NewCoreEngine()

	// Test basic configuration
	config := &FrameworkConfig{
		Name:           "test-framework",
		Version:        "1.0.0",
		Environment:    "test",
		MetricsEnabled: true,
		MetricsPort:    8080,
		RequestTimeout: 30 * time.Second,
		PluginConfigs:  make(map[string]PluginConfig),
	}

	// Initialize framework
	err := engine.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	// Test framework is not running initially
	if engine.IsRunning() {
		t.Error("Framework should not be running before Start()")
	}

	// Start framework
	err = engine.Start()
	if err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}

	// Test framework is running
	if !engine.IsRunning() {
		t.Error("Framework should be running after Start()")
	}

	// Test health manager
	healthManager := engine.GetHealthManager()
	if healthManager == nil {
		t.Error("Health manager should not be nil")
	}

	// Test shutdown manager
	shutdownManager := engine.GetShutdownManager()
	if shutdownManager == nil {
		t.Error("Shutdown manager should not be nil")
	}

	// Test uptime
	uptime := engine.GetUptime()
	if uptime <= 0 {
		t.Error("Uptime should be positive")
	}

	// Stop framework
	err = engine.Stop()
	if err != nil {
		t.Fatalf("Failed to stop framework: %v", err)
	}

	// Test framework is not running after stop
	if engine.IsRunning() {
		t.Error("Framework should not be running after Stop()")
	}
}

// TestHealthEndpoints tests health check endpoints
func TestHealthEndpoints(t *testing.T) {
	// Create framework
	engine := NewCoreEngine()

	config := &FrameworkConfig{
		Name:           "test-framework",
		Version:        "1.0.0",
		Environment:    "test",
		MetricsEnabled: true,
		PluginConfigs:  make(map[string]PluginConfig),
	}

	err := engine.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	err = engine.Start()
	if err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}
	defer engine.Stop()

	// Test health endpoints
	healthManager := engine.GetHealthManager()

	// Create HTTP mux for testing
	mux := http.NewServeMux()
	healthManager.RegisterRoutes(mux)

	// Test basic health endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Test detailed health endpoint
	req = httptest.NewRequest("GET", "/health/detailed", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Test readiness endpoint
	req = httptest.NewRequest("GET", "/health/ready", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Test liveness endpoint
	req = httptest.NewRequest("GET", "/health/live", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestPluginRegistration tests plugin registration and management
func TestPluginRegistration(t *testing.T) {
	// Create framework
	engine := NewCoreEngine()

	config := &FrameworkConfig{
		Name:          "test-framework",
		Version:       "1.0.0",
		Environment:   "test",
		PluginConfigs: make(map[string]PluginConfig),
	}

	err := engine.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	// Create test plugin
	testPlugin := NewCompositePlugin("test-plugin", "1.0.0", "Test plugin")

	// Register plugin
	err = engine.RegisterPlugin(testPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test plugin is registered
	plugins := engine.ListPlugins()
	if len(plugins) != 1 {
		t.Errorf("Expected 1 plugin, got %d", len(plugins))
	}

	if plugins[0] != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got '%s'", plugins[0])
	}

	// Test get plugin
	retrievedPlugin, exists := engine.GetPlugin("test-plugin")
	if !exists {
		t.Error("Plugin should exist")
	}

	if retrievedPlugin.Name() != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got '%s'", retrievedPlugin.Name())
	}

	// Start framework
	err = engine.Start()
	if err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}

	// Test plugin is running
	if retrievedPlugin.Health() != HealthStatusHealthy {
		t.Error("Plugin should be healthy after framework start")
	}

	// Stop framework
	err = engine.Stop()
	if err != nil {
		t.Fatalf("Failed to stop framework: %v", err)
	}
}

// TestConfigurationValidation tests configuration validation
func TestConfigurationValidation(t *testing.T) {
	configManager := NewConfigurationManager()

	// Test valid configuration
	validConfig := &FrameworkConfig{
		Name:           "test-framework",
		Version:        "1.0.0",
		Environment:    "test",
		MetricsEnabled: true,
		MetricsPort:    8080,
		RequestTimeout: 30 * time.Second,
		PluginConfigs:  make(map[string]PluginConfig),
	}

	err := configManager.ValidateConfig(validConfig)
	if err != nil {
		t.Errorf("Valid configuration should pass validation: %v", err)
	}

	// Test invalid configuration - missing name
	invalidConfig := &FrameworkConfig{
		Version:       "1.0.0",
		Environment:   "test",
		PluginConfigs: make(map[string]PluginConfig),
	}

	err = configManager.ValidateConfig(invalidConfig)
	if err == nil {
		t.Error("Invalid configuration should fail validation")
	}

	// Test invalid configuration - invalid metrics port
	invalidPortConfig := &FrameworkConfig{
		Name:           "test-framework",
		Version:        "1.0.0",
		Environment:    "test",
		MetricsEnabled: true,
		MetricsPort:    -1,
		PluginConfigs:  make(map[string]PluginConfig),
	}

	err = configManager.ValidateConfig(invalidPortConfig)
	if err == nil {
		t.Error("Configuration with invalid port should fail validation")
	}
}

// TestGracefulShutdown tests graceful shutdown functionality
func TestGracefulShutdown(t *testing.T) {
	// Create framework
	engine := NewCoreEngine()

	config := &FrameworkConfig{
		Name:          "test-framework",
		Version:       "1.0.0",
		Environment:   "test",
		PluginConfigs: make(map[string]PluginConfig),
	}

	err := engine.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	err = engine.Start()
	if err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}

	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = engine.GracefulShutdown(ctx)
	if err != nil {
		t.Errorf("Graceful shutdown failed: %v", err)
	}

	// Framework should not be running after graceful shutdown
	if engine.IsRunning() {
		t.Error("Framework should not be running after graceful shutdown")
	}
}
