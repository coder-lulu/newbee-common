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
	"sync/atomic"
	"time"
)

// GracefulShutdownManager handles graceful shutdown of the framework
type GracefulShutdownManager struct {
	engine *CoreEngine
	config *ShutdownConfig

	// Shutdown state
	shuttingDown int32
	shutdownChan chan struct{}
	shutdownOnce sync.Once

	// Active request tracking
	activeRequests int64
	requestWg      sync.WaitGroup

	// Plugin shutdown coordination
	pluginShutdown map[string]chan struct{}
	shutdownMu     sync.RWMutex

	// Shutdown hooks
	hooks   []ShutdownHook
	hooksMu sync.RWMutex

	// Monitoring
	logger Logger
}

// ShutdownConfig configures graceful shutdown behavior
type ShutdownConfig struct {
	// Timeout for complete shutdown
	Timeout time.Duration `json:"timeout"`

	// Grace period to stop accepting new requests
	GracePeriod time.Duration `json:"grace_period"`

	// Timeout for draining active requests
	DrainTimeout time.Duration `json:"drain_timeout"`

	// Timeout for individual plugin shutdown
	PluginShutdownTimeout time.Duration `json:"plugin_shutdown_timeout"`

	// Whether to wait for active requests to complete
	WaitForRequests bool `json:"wait_for_requests"`

	// Whether to force shutdown after timeout
	ForceShutdown bool `json:"force_shutdown"`

	// Maximum number of retries for plugin shutdown
	MaxRetries int `json:"max_retries"`
}

// ShutdownHook represents a function to be called during shutdown
type ShutdownHook func(ctx context.Context) error

// ShutdownPhase represents different phases of shutdown
type ShutdownPhase int

const (
	ShutdownPhaseStarting ShutdownPhase = iota
	ShutdownPhaseGrace
	ShutdownPhaseDraining
	ShutdownPhasePlugins
	ShutdownPhaseCleanup
	ShutdownPhaseComplete
)

// ShutdownStatus represents the current shutdown status
type ShutdownStatus struct {
	Phase          ShutdownPhase `json:"phase"`
	StartTime      time.Time     `json:"start_time"`
	ActiveRequests int64         `json:"active_requests"`
	PluginsLeft    int           `json:"plugins_left"`
	Elapsed        time.Duration `json:"elapsed"`
	Error          string        `json:"error,omitempty"`
}

// NewGracefulShutdownManager creates a new graceful shutdown manager
func NewGracefulShutdownManager(engine *CoreEngine) *GracefulShutdownManager {
	return &GracefulShutdownManager{
		engine:         engine,
		shutdownChan:   make(chan struct{}),
		pluginShutdown: make(map[string]chan struct{}),
		hooks:          make([]ShutdownHook, 0),
		config: &ShutdownConfig{
			Timeout:               60 * time.Second,
			GracePeriod:           10 * time.Second,
			DrainTimeout:          30 * time.Second,
			PluginShutdownTimeout: 15 * time.Second,
			WaitForRequests:       true,
			ForceShutdown:         true,
			MaxRetries:            3,
		},
		logger: NewDefaultLogger(),
	}
}

// Initialize configures the shutdown manager
func (gsm *GracefulShutdownManager) Initialize(config *ShutdownConfig, logger Logger) error {
	if config != nil {
		gsm.config = config
	}

	if logger != nil {
		gsm.logger = logger
	}

	// Validate configuration
	if gsm.config.Timeout <= 0 {
		gsm.config.Timeout = 60 * time.Second
	}

	if gsm.config.GracePeriod <= 0 {
		gsm.config.GracePeriod = 10 * time.Second
	}

	if gsm.config.DrainTimeout <= 0 {
		gsm.config.DrainTimeout = 30 * time.Second
	}

	if gsm.config.PluginShutdownTimeout <= 0 {
		gsm.config.PluginShutdownTimeout = 15 * time.Second
	}

	return nil
}

// IsShuttingDown returns true if shutdown has been initiated
func (gsm *GracefulShutdownManager) IsShuttingDown() bool {
	return atomic.LoadInt32(&gsm.shuttingDown) == 1
}

// GetShutdownChannel returns a channel that is closed when shutdown starts
func (gsm *GracefulShutdownManager) GetShutdownChannel() <-chan struct{} {
	return gsm.shutdownChan
}

// Shutdown initiates graceful shutdown
func (gsm *GracefulShutdownManager) Shutdown(ctx context.Context) error {
	var shutdownErr error

	gsm.shutdownOnce.Do(func() {
		shutdownErr = gsm.performShutdown(ctx)
	})

	return shutdownErr
}

// performShutdown executes the shutdown sequence
func (gsm *GracefulShutdownManager) performShutdown(ctx context.Context) error {
	startTime := time.Now()

	// Set shutdown flag
	atomic.StoreInt32(&gsm.shuttingDown, 1)
	close(gsm.shutdownChan)

	gsm.logger.Info("Starting graceful shutdown",
		String("timeout", gsm.config.Timeout.String()),
		String("grace_period", gsm.config.GracePeriod.String()))

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, gsm.config.Timeout)
	defer cancel()

	// Phase 1: Grace period - stop accepting new requests
	if err := gsm.gracePeriod(shutdownCtx, startTime); err != nil {
		gsm.logger.Error("Grace period failed", Error(err))
		if !gsm.config.ForceShutdown {
			return err
		}
	}

	// Phase 2: Drain active requests
	if err := gsm.drainRequests(shutdownCtx, startTime); err != nil {
		gsm.logger.Error("Request draining failed", Error(err))
		if !gsm.config.ForceShutdown {
			return err
		}
	}

	// Phase 3: Shutdown plugins
	if err := gsm.shutdownPlugins(shutdownCtx, startTime); err != nil {
		gsm.logger.Error("Plugin shutdown failed", Error(err))
		if !gsm.config.ForceShutdown {
			return err
		}
	}

	// Phase 4: Execute shutdown hooks
	if err := gsm.executeShutdownHooks(shutdownCtx); err != nil {
		gsm.logger.Error("Shutdown hooks failed", Error(err))
		if !gsm.config.ForceShutdown {
			return err
		}
	}

	// Phase 5: Final cleanup
	if err := gsm.finalCleanup(shutdownCtx); err != nil {
		gsm.logger.Error("Final cleanup failed", Error(err))
		return err
	}

	elapsed := time.Since(startTime)
	gsm.logger.Info("Graceful shutdown completed",
		String("elapsed", elapsed.String()))

	return nil
}

// gracePeriod implements the grace period phase
func (gsm *GracefulShutdownManager) gracePeriod(ctx context.Context, startTime time.Time) error {
	gsm.logger.Info("Entering grace period - stopping new request acceptance")

	graceCtx, cancel := context.WithTimeout(ctx, gsm.config.GracePeriod)
	defer cancel()

	// Wait for grace period or context cancellation
	select {
	case <-graceCtx.Done():
		if graceCtx.Err() == context.DeadlineExceeded {
			gsm.logger.Info("Grace period completed")
			return nil
		}
		return fmt.Errorf("grace period interrupted: %w", graceCtx.Err())
	case <-ctx.Done():
		return fmt.Errorf("shutdown context cancelled during grace period: %w", ctx.Err())
	}
}

// drainRequests waits for active requests to complete
func (gsm *GracefulShutdownManager) drainRequests(ctx context.Context, startTime time.Time) error {
	if !gsm.config.WaitForRequests {
		gsm.logger.Info("Skipping request draining (disabled)")
		return nil
	}

	activeCount := atomic.LoadInt64(&gsm.activeRequests)
	if activeCount == 0 {
		gsm.logger.Info("No active requests to drain")
		return nil
	}

	gsm.logger.Info("Draining active requests",
		Field("active_count", activeCount),
		String("drain_timeout", gsm.config.DrainTimeout.String()))

	drainCtx, cancel := context.WithTimeout(ctx, gsm.config.DrainTimeout)
	defer cancel()

	// Create a channel to signal when all requests are drained
	drained := make(chan struct{})

	// Monitor active request count
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-drainCtx.Done():
				return
			case <-ticker.C:
				current := atomic.LoadInt64(&gsm.activeRequests)
				if current == 0 {
					close(drained)
					return
				}

				gsm.logger.Debug("Waiting for requests to drain",
					Field("remaining", current))
			}
		}
	}()

	// Wait for either all requests to drain or timeout
	select {
	case <-drained:
		gsm.logger.Info("All requests drained successfully")
		return nil
	case <-drainCtx.Done():
		remaining := atomic.LoadInt64(&gsm.activeRequests)
		if drainCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("request drain timeout exceeded, %d requests still active", remaining)
		}
		return fmt.Errorf("request draining interrupted: %w", drainCtx.Err())
	}
}

// shutdownPlugins shuts down all plugins in reverse dependency order
func (gsm *GracefulShutdownManager) shutdownPlugins(ctx context.Context, startTime time.Time) error {
	pluginNames := gsm.engine.ListPlugins()
	if len(pluginNames) == 0 {
		gsm.logger.Info("No plugins to shutdown")
		return nil
	}

	gsm.logger.Info("Shutting down plugins",
		Int("plugin_count", len(pluginNames)))

	// Get plugin stop order (reverse of start order)
	stopOrder := gsm.engine.getPluginStopOrder()

	// Initialize plugin shutdown channels
	gsm.shutdownMu.Lock()
	for _, name := range stopOrder {
		gsm.pluginShutdown[name] = make(chan struct{})
	}
	gsm.shutdownMu.Unlock()

	// Shutdown plugins in order with individual timeouts
	for _, pluginName := range stopOrder {
		if err := gsm.shutdownSinglePlugin(ctx, pluginName); err != nil {
			gsm.logger.Error("Plugin shutdown failed",
				String("plugin", pluginName),
				Error(err))

			if !gsm.config.ForceShutdown {
				return fmt.Errorf("failed to shutdown plugin %s: %w", pluginName, err)
			}
		}
	}

	gsm.logger.Info("All plugins shutdown completed")
	return nil
}

// shutdownSinglePlugin shuts down a single plugin with retry logic
func (gsm *GracefulShutdownManager) shutdownSinglePlugin(ctx context.Context, pluginName string) error {
	plugin, exists := gsm.engine.GetPlugin(pluginName)
	if !exists {
		gsm.logger.Warn("Plugin not found during shutdown", String("plugin", pluginName))
		return nil
	}

	gsm.logger.Info("Shutting down plugin", String("plugin", pluginName))

	var lastErr error
	for attempt := 1; attempt <= gsm.config.MaxRetries; attempt++ {
		pluginCtx, cancel := context.WithTimeout(ctx, gsm.config.PluginShutdownTimeout)

		// Execute plugin stop with timeout
		done := make(chan error, 1)
		go func() {
			done <- plugin.Stop()
		}()

		select {
		case err := <-done:
			cancel()
			if err == nil {
				gsm.logger.Info("Plugin shutdown successful",
					String("plugin", pluginName),
					Int("attempt", attempt))

				// Mark plugin as shutdown
				gsm.shutdownMu.Lock()
				if ch, exists := gsm.pluginShutdown[pluginName]; exists {
					close(ch)
					delete(gsm.pluginShutdown, pluginName)
				}
				gsm.shutdownMu.Unlock()

				return nil
			}

			lastErr = err
			gsm.logger.Warn("Plugin shutdown attempt failed",
				String("plugin", pluginName),
				Int("attempt", attempt),
				Int("max_retries", gsm.config.MaxRetries),
				Error(err))

		case <-pluginCtx.Done():
			cancel()
			lastErr = fmt.Errorf("plugin shutdown timeout: %w", pluginCtx.Err())
			gsm.logger.Warn("Plugin shutdown timeout",
				String("plugin", pluginName),
				Int("attempt", attempt),
				String("timeout", gsm.config.PluginShutdownTimeout.String()))
		}

		// Wait before retry (except on last attempt)
		if attempt < gsm.config.MaxRetries {
			retryDelay := time.Duration(attempt) * time.Second
			gsm.logger.Info("Retrying plugin shutdown",
				String("plugin", pluginName),
				String("delay", retryDelay.String()))

			select {
			case <-time.After(retryDelay):
			case <-ctx.Done():
				return fmt.Errorf("shutdown context cancelled during retry: %w", ctx.Err())
			}
		}
	}

	return fmt.Errorf("plugin shutdown failed after %d attempts: %w", gsm.config.MaxRetries, lastErr)
}

// executeShutdownHooks executes all registered shutdown hooks
func (gsm *GracefulShutdownManager) executeShutdownHooks(ctx context.Context) error {
	gsm.hooksMu.RLock()
	hooks := make([]ShutdownHook, len(gsm.hooks))
	copy(hooks, gsm.hooks)
	gsm.hooksMu.RUnlock()

	if len(hooks) == 0 {
		gsm.logger.Info("No shutdown hooks to execute")
		return nil
	}

	gsm.logger.Info("Executing shutdown hooks", Int("hook_count", len(hooks)))

	for i, hook := range hooks {
		gsm.logger.Debug("Executing shutdown hook", Int("hook_index", i))

		if err := hook(ctx); err != nil {
			gsm.logger.Error("Shutdown hook failed",
				Int("hook_index", i),
				Error(err))

			if !gsm.config.ForceShutdown {
				return fmt.Errorf("shutdown hook %d failed: %w", i, err)
			}
		}
	}

	gsm.logger.Info("All shutdown hooks completed")
	return nil
}

// finalCleanup performs final cleanup operations
func (gsm *GracefulShutdownManager) finalCleanup(ctx context.Context) error {
	gsm.logger.Info("Performing final cleanup")

	// Stop the core engine
	if err := gsm.engine.Stop(); err != nil {
		gsm.logger.Error("Core engine stop failed", Error(err))
		return fmt.Errorf("core engine stop failed: %w", err)
	}

	// Clear shutdown channels
	gsm.shutdownMu.Lock()
	for name, ch := range gsm.pluginShutdown {
		select {
		case <-ch:
			// Already closed
		default:
			close(ch)
		}
		delete(gsm.pluginShutdown, name)
	}
	gsm.shutdownMu.Unlock()

	gsm.logger.Info("Final cleanup completed")
	return nil
}

// RegisterShutdownHook registers a function to be called during shutdown
func (gsm *GracefulShutdownManager) RegisterShutdownHook(hook ShutdownHook) {
	gsm.hooksMu.Lock()
	defer gsm.hooksMu.Unlock()

	gsm.hooks = append(gsm.hooks, hook)
}

// TrackRequest increments the active request counter
func (gsm *GracefulShutdownManager) TrackRequest() func() {
	if gsm.IsShuttingDown() {
		// Return a no-op function if shutdown has started
		return func() {}
	}

	atomic.AddInt64(&gsm.activeRequests, 1)
	gsm.requestWg.Add(1)

	// Return a function to be called when the request completes
	return func() {
		atomic.AddInt64(&gsm.activeRequests, -1)
		gsm.requestWg.Done()
	}
}

// GetStatus returns the current shutdown status
func (gsm *GracefulShutdownManager) GetStatus() *ShutdownStatus {
	status := &ShutdownStatus{
		ActiveRequests: atomic.LoadInt64(&gsm.activeRequests),
	}

	if gsm.IsShuttingDown() {
		// Estimate current phase based on time elapsed
		// This is simplified - in a real implementation you'd track phase explicitly
		status.Phase = ShutdownPhaseStarting

		gsm.shutdownMu.RLock()
		status.PluginsLeft = len(gsm.pluginShutdown)
		gsm.shutdownMu.RUnlock()
	}

	return status
}

// WaitForShutdown blocks until shutdown is complete or context is cancelled
func (gsm *GracefulShutdownManager) WaitForShutdown(ctx context.Context) error {
	select {
	case <-gsm.shutdownChan:
		// Shutdown has started, wait for completion
		// In a full implementation, you'd have a completion channel
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
