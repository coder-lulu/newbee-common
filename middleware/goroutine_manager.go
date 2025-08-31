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

package middleware

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// GoroutineManager provides safe goroutine lifecycle management
type GoroutineManager interface {
	// Go starts a new goroutine with automatic cleanup
	Go(name string, fn func(ctx context.Context) error) error

	// GoWithTimeout starts a goroutine with timeout
	GoWithTimeout(name string, timeout time.Duration, fn func(ctx context.Context) error) error

	// Wait waits for all goroutines to complete
	Wait() error

	// Stop gracefully stops all goroutines
	Stop() error

	// ForceStop forcibly stops all goroutines after timeout
	ForceStop(timeout time.Duration) error

	// GetStats returns goroutine statistics
	GetStats() GoroutineStats

	// IsRunning returns true if the manager is running
	IsRunning() bool
}

// GoroutineStats provides statistics about managed goroutines
type GoroutineStats struct {
	ActiveGoroutines int           `json:"active_goroutines"`
	TotalLaunched    int64         `json:"total_launched"`
	TotalCompleted   int64         `json:"total_completed"`
	TotalErrors      int64         `json:"total_errors"`
	TotalTimeouts    int64         `json:"total_timeouts"`
	AverageRuntime   time.Duration `json:"average_runtime"`
	LongestRuntime   time.Duration `json:"longest_runtime"`
	ManagerUptime    time.Duration `json:"manager_uptime"`
	MemoryUsage      int64         `json:"memory_usage_bytes"`
	SystemGoroutines int           `json:"system_goroutines"`
}

// SafeGoroutineManager implements GoroutineManager with leak prevention
type SafeGoroutineManager struct {
	name    string
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	stopped int32

	// Goroutine tracking
	goroutines    map[string]*goroutineInfo
	goroutinesMux sync.RWMutex

	// Statistics
	stats     *atomicStats
	startTime time.Time

	// Configuration
	config *GoroutineManagerConfig
}

// GoroutineManagerConfig defines configuration for goroutine management
type GoroutineManagerConfig struct {
	MaxGoroutines       int           `json:"max_goroutines"`        // Maximum concurrent goroutines
	DefaultTimeout      time.Duration `json:"default_timeout"`       // Default timeout for goroutines
	GracefulShutdown    time.Duration `json:"graceful_shutdown"`     // Timeout for graceful shutdown
	EnableMetrics       bool          `json:"enable_metrics"`        // Enable metrics collection
	EnableStackTrace    bool          `json:"enable_stack_trace"`    // Enable stack trace on errors
	LeakDetection       bool          `json:"leak_detection"`        // Enable goroutine leak detection
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Health check interval
}

// DefaultGoroutineManagerConfig returns default configuration
func DefaultGoroutineManagerConfig() *GoroutineManagerConfig {
	return &GoroutineManagerConfig{
		MaxGoroutines:       100,
		DefaultTimeout:      30 * time.Second,
		GracefulShutdown:    10 * time.Second,
		EnableMetrics:       true,
		EnableStackTrace:    true,
		LeakDetection:       true,
		HealthCheckInterval: 30 * time.Second,
	}
}

type goroutineInfo struct {
	name      string
	startTime time.Time
	cancel    context.CancelFunc
	done      chan struct{}
}

type atomicStats struct {
	totalLaunched  int64
	totalCompleted int64
	totalErrors    int64
	totalTimeouts  int64
	totalRuntime   int64 // nanoseconds
	longestRuntime int64 // nanoseconds
}

// NewGoroutineManager creates a new goroutine manager
func NewGoroutineManager(name string, config *GoroutineManagerConfig) GoroutineManager {
	if config == nil {
		config = DefaultGoroutineManagerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &SafeGoroutineManager{
		name:       name,
		ctx:        ctx,
		cancel:     cancel,
		goroutines: make(map[string]*goroutineInfo),
		stats:      &atomicStats{},
		startTime:  time.Now(),
		config:     config,
	}

	// Start health monitoring if enabled
	if config.HealthCheckInterval > 0 {
		go manager.healthMonitor()
	}

	logx.Infow("Goroutine manager initialized",
		logx.Field("name", name),
		logx.Field("maxGoroutines", config.MaxGoroutines),
		logx.Field("defaultTimeout", config.DefaultTimeout))

	return manager
}

// Go starts a new goroutine with automatic cleanup
func (gm *SafeGoroutineManager) Go(name string, fn func(ctx context.Context) error) error {
	return gm.GoWithTimeout(name, gm.config.DefaultTimeout, fn)
}

// GoWithTimeout starts a goroutine with timeout
func (gm *SafeGoroutineManager) GoWithTimeout(name string, timeout time.Duration, fn func(ctx context.Context) error) error {
	if atomic.LoadInt32(&gm.stopped) == 1 {
		return fmt.Errorf("goroutine manager is stopped")
	}

	// Check goroutine limit
	gm.goroutinesMux.RLock()
	activeCount := len(gm.goroutines)
	gm.goroutinesMux.RUnlock()

	if activeCount >= gm.config.MaxGoroutines {
		atomic.AddInt64(&gm.stats.totalErrors, 1)
		return fmt.Errorf("goroutine limit exceeded: %d >= %d", activeCount, gm.config.MaxGoroutines)
	}

	// Create goroutine context
	ctx, cancel := context.WithTimeout(gm.ctx, timeout)
	info := &goroutineInfo{
		name:      name,
		startTime: time.Now(),
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	// Track goroutine
	goroutineID := fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	gm.goroutinesMux.Lock()
	gm.goroutines[goroutineID] = info
	gm.goroutinesMux.Unlock()

	atomic.AddInt64(&gm.stats.totalLaunched, 1)
	gm.wg.Add(1)

	go func() {
		defer func() {
			// Cleanup
			close(info.done)
			cancel()
			gm.wg.Done()

			// Remove from tracking
			gm.goroutinesMux.Lock()
			delete(gm.goroutines, goroutineID)
			gm.goroutinesMux.Unlock()

			// Update statistics
			runtime := time.Since(info.startTime)
			atomic.AddInt64(&gm.stats.totalCompleted, 1)
			atomic.AddInt64(&gm.stats.totalRuntime, runtime.Nanoseconds())

			// Update longest runtime
			for {
				current := atomic.LoadInt64(&gm.stats.longestRuntime)
				if runtime.Nanoseconds() <= current {
					break
				}
				if atomic.CompareAndSwapInt64(&gm.stats.longestRuntime, current, runtime.Nanoseconds()) {
					break
				}
			}

			// Handle panic
			if r := recover(); r != nil {
				atomic.AddInt64(&gm.stats.totalErrors, 1)
				logx.Errorw("Goroutine panic recovered",
					logx.Field("manager", gm.name),
					logx.Field("goroutine", goroutineID),
					logx.Field("panic", r),
					logx.Field("runtime", runtime))

				if gm.config.EnableStackTrace {
					logx.Errorw("Goroutine stack trace",
						logx.Field("goroutine", goroutineID),
						logx.Field("stack", string(debug.Stack())))
				}
			}
		}()

		// Execute function
		err := fn(ctx)
		if err != nil {
			atomic.AddInt64(&gm.stats.totalErrors, 1)

			// Check if it's a timeout error
			if ctx.Err() == context.DeadlineExceeded {
				atomic.AddInt64(&gm.stats.totalTimeouts, 1)
				logx.Errorw("Goroutine timeout",
					logx.Field("manager", gm.name),
					logx.Field("goroutine", goroutineID),
					logx.Field("timeout", timeout),
					logx.Field("error", err))
			} else {
				logx.Errorw("Goroutine error",
					logx.Field("manager", gm.name),
					logx.Field("goroutine", goroutineID),
					logx.Field("error", err))
			}
		}
	}()

	return nil
}

// Wait waits for all goroutines to complete
func (gm *SafeGoroutineManager) Wait() error {
	gm.wg.Wait()
	return nil
}

// Stop gracefully stops all goroutines
func (gm *SafeGoroutineManager) Stop() error {
	if !atomic.CompareAndSwapInt32(&gm.stopped, 0, 1) {
		return fmt.Errorf("goroutine manager already stopped")
	}

	logx.Infow("Stopping goroutine manager", logx.Field("name", gm.name))

	// Cancel all goroutines
	gm.cancel()

	// Wait for graceful shutdown
	done := make(chan struct{})
	go func() {
		gm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logx.Infow("Goroutine manager stopped gracefully",
			logx.Field("name", gm.name))
		return nil
	case <-time.After(gm.config.GracefulShutdown):
		logx.Infow("Goroutine manager graceful shutdown timeout",
			logx.Field("name", gm.name),
			logx.Field("timeout", gm.config.GracefulShutdown))
		return fmt.Errorf("graceful shutdown timeout")
	}
}

// ForceStop forcibly stops all goroutines after timeout
func (gm *SafeGoroutineManager) ForceStop(timeout time.Duration) error {
	if atomic.LoadInt32(&gm.stopped) == 0 {
		if err := gm.Stop(); err == nil {
			return nil
		}
	}

	logx.Infow("Force stopping goroutine manager",
		logx.Field("name", gm.name),
		logx.Field("timeout", timeout))

	// Force cancel all goroutines
	gm.goroutinesMux.RLock()
	for _, info := range gm.goroutines {
		info.cancel()
	}
	gm.goroutinesMux.RUnlock()

	// Wait for force stop timeout
	done := make(chan struct{})
	go func() {
		gm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logx.Infow("Goroutine manager force stopped",
			logx.Field("name", gm.name))
		return nil
	case <-time.After(timeout):
		// Log remaining goroutines for debugging
		gm.goroutinesMux.RLock()
		remaining := make([]string, 0, len(gm.goroutines))
		for id := range gm.goroutines {
			remaining = append(remaining, id)
		}
		gm.goroutinesMux.RUnlock()

		logx.Errorw("Goroutine manager force stop timeout",
			logx.Field("name", gm.name),
			logx.Field("remainingGoroutines", remaining))

		return fmt.Errorf("force stop timeout, %d goroutines remaining", len(remaining))
	}
}

// GetStats returns goroutine statistics
func (gm *SafeGoroutineManager) GetStats() GoroutineStats {
	gm.goroutinesMux.RLock()
	activeCount := len(gm.goroutines)
	gm.goroutinesMux.RUnlock()

	totalLaunched := atomic.LoadInt64(&gm.stats.totalLaunched)
	totalCompleted := atomic.LoadInt64(&gm.stats.totalCompleted)
	totalRuntime := atomic.LoadInt64(&gm.stats.totalRuntime)
	longestRuntime := atomic.LoadInt64(&gm.stats.longestRuntime)

	var avgRuntime time.Duration
	if totalCompleted > 0 {
		avgRuntime = time.Duration(totalRuntime / totalCompleted)
	}

	// Get memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return GoroutineStats{
		ActiveGoroutines: activeCount,
		TotalLaunched:    totalLaunched,
		TotalCompleted:   totalCompleted,
		TotalErrors:      atomic.LoadInt64(&gm.stats.totalErrors),
		TotalTimeouts:    atomic.LoadInt64(&gm.stats.totalTimeouts),
		AverageRuntime:   avgRuntime,
		LongestRuntime:   time.Duration(longestRuntime),
		ManagerUptime:    time.Since(gm.startTime),
		MemoryUsage:      int64(memStats.Alloc),
		SystemGoroutines: runtime.NumGoroutine(),
	}
}

// IsRunning returns true if the manager is running
func (gm *SafeGoroutineManager) IsRunning() bool {
	return atomic.LoadInt32(&gm.stopped) == 0
}

// healthMonitor monitors goroutine health
func (gm *SafeGoroutineManager) healthMonitor() {
	ticker := time.NewTicker(gm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gm.performHealthCheck()
		case <-gm.ctx.Done():
			return
		}
	}
}

// performHealthCheck performs health monitoring
func (gm *SafeGoroutineManager) performHealthCheck() {
	stats := gm.GetStats()

	// Check for potential leaks
	if gm.config.LeakDetection && stats.ActiveGoroutines > gm.config.MaxGoroutines/2 {
		logx.Infow("High goroutine count detected",
			logx.Field("manager", gm.name),
			logx.Field("activeGoroutines", stats.ActiveGoroutines),
			logx.Field("maxGoroutines", gm.config.MaxGoroutines))
	}

	// Check for long-running goroutines
	now := time.Now()
	gm.goroutinesMux.RLock()
	for id, info := range gm.goroutines {
		runtime := now.Sub(info.startTime)
		if runtime > gm.config.DefaultTimeout*2 {
			logx.Infow("Long-running goroutine detected",
				logx.Field("manager", gm.name),
				logx.Field("goroutine", id),
				logx.Field("runtime", runtime))
		}
	}
	gm.goroutinesMux.RUnlock()

	// Log periodic statistics
	if gm.config.EnableMetrics {
		logx.Infow("Goroutine manager health check",
			logx.Field("manager", gm.name),
			logx.Field("activeGoroutines", stats.ActiveGoroutines),
			logx.Field("totalLaunched", stats.TotalLaunched),
			logx.Field("totalCompleted", stats.TotalCompleted),
			logx.Field("totalErrors", stats.TotalErrors),
			logx.Field("averageRuntime", stats.AverageRuntime),
			logx.Field("systemGoroutines", stats.SystemGoroutines))
	}
}
