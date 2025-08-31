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
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// GCOptimizer optimizes garbage collection behavior for better memory management
type GCOptimizer struct {
	targetPercent    int
	forceInterval    time.Duration
	metricsCollector MetricsCollector

	// GC control
	ticker *time.Ticker
	done   chan struct{}

	// GC statistics
	totalForceGCs int64
	totalGCTime   time.Duration
	lastGCStats   debug.GCStats

	// Adaptive tuning
	adaptiveEnabled bool
	memoryPressure  float64
	cpuUsage        float64

	mu sync.RWMutex
}

// GCOptimizerConfig defines configuration for GC optimization
type GCOptimizerConfig struct {
	TargetPercent    int           `json:"target_percent"`
	ForceInterval    time.Duration `json:"force_interval"`
	AdaptiveEnabled  bool          `json:"adaptive_enabled"`
	MinTargetPercent int           `json:"min_target_percent"`
	MaxTargetPercent int           `json:"max_target_percent"`
	CPUThreshold     float64       `json:"cpu_threshold"`
	MemoryThreshold  float64       `json:"memory_threshold"`
}

// DefaultGCOptimizerConfig returns default GC optimizer configuration
func DefaultGCOptimizerConfig() *GCOptimizerConfig {
	return &GCOptimizerConfig{
		TargetPercent:    50, // Lower than Go's default 100
		ForceInterval:    5 * time.Minute,
		AdaptiveEnabled:  true,
		MinTargetPercent: 20,
		MaxTargetPercent: 200,
		CPUThreshold:     0.7, // 70% CPU usage threshold
		MemoryThreshold:  0.8, // 80% memory usage threshold
	}
}

// NewGCOptimizer creates a new GC optimizer
func NewGCOptimizer(targetPercent int, forceInterval time.Duration, metricsCollector MetricsCollector) *GCOptimizer {
	optimizer := &GCOptimizer{
		targetPercent:    targetPercent,
		forceInterval:    forceInterval,
		metricsCollector: metricsCollector,
		done:             make(chan struct{}),
		adaptiveEnabled:  true,
	}

	// Set initial GC target
	debug.SetGCPercent(targetPercent)

	// Initialize GC stats
	debug.ReadGCStats(&optimizer.lastGCStats)

	logx.Infow("GC optimizer initialized",
		logx.Field("targetPercent", targetPercent),
		logx.Field("forceInterval", forceInterval),
		logx.Field("adaptiveEnabled", optimizer.adaptiveEnabled))

	return optimizer
}

// Start begins GC optimization
func (gco *GCOptimizer) Start() {
	if gco.forceInterval > 0 {
		gco.ticker = time.NewTicker(gco.forceInterval)
		go gco.optimizationLoop()
	}

	// Start adaptive tuning if enabled
	if gco.adaptiveEnabled {
		go gco.adaptiveTuningLoop()
	}

	logx.Info("GC optimizer started")
}

// Stop stops GC optimization
func (gco *GCOptimizer) Stop() {
	if gco.ticker != nil {
		gco.ticker.Stop()
	}
	close(gco.done)

	logx.Info("GC optimizer stopped")
}

// optimizationLoop is the main GC optimization loop
func (gco *GCOptimizer) optimizationLoop() {
	defer gco.ticker.Stop()

	for {
		select {
		case <-gco.ticker.C:
			gco.performOptimization()
		case <-gco.done:
			return
		}
	}
}

// performOptimization performs GC optimization tasks
func (gco *GCOptimizer) performOptimization() {
	// Collect GC stats before optimization
	var beforeStats debug.GCStats
	debug.ReadGCStats(&beforeStats)

	// Determine if forced GC is needed
	if gco.shouldForceGC(&beforeStats) {
		gco.ForceGC()
	}

	// Update adaptive tuning
	if gco.adaptiveEnabled {
		gco.updateAdaptiveTuning()
	}

	// Record GC metrics
	gco.recordGCMetrics(&beforeStats)
}

// shouldForceGC determines if a forced GC should be triggered
func (gco *GCOptimizer) shouldForceGC(stats *debug.GCStats) bool {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Force GC if:
	// 1. Memory usage is high relative to NextGC
	// 2. Time since last GC is significant
	// 3. Allocation rate is high

	memoryPressure := float64(memStats.Alloc) / float64(memStats.NextGC)
	timeSinceLastGC := time.Since(time.Unix(0, int64(memStats.LastGC)))

	return memoryPressure > 0.8 || timeSinceLastGC > gco.forceInterval*2
}

// ForceGC forces a garbage collection
func (gco *GCOptimizer) ForceGC() {
	start := time.Now()

	// Collect before stats
	var beforeStats runtime.MemStats
	runtime.ReadMemStats(&beforeStats)

	// Force GC
	runtime.GC()
	debug.FreeOSMemory()

	// Collect after stats
	var afterStats runtime.MemStats
	runtime.ReadMemStats(&afterStats)

	duration := time.Since(start)
	freedBytes := int64(beforeStats.Alloc) - int64(afterStats.Alloc)

	// Update statistics
	atomic.AddInt64(&gco.totalForceGCs, 1)
	gco.mu.Lock()
	gco.totalGCTime += duration
	gco.mu.Unlock()

	logx.Infow("Forced GC completed",
		logx.Field("duration", duration),
		logx.Field("freedMB", freedBytes/(1024*1024)),
		logx.Field("beforeMB", beforeStats.Alloc/(1024*1024)),
		logx.Field("afterMB", afterStats.Alloc/(1024*1024)))

	// Record metrics
	if gco.metricsCollector != nil {
		gco.metricsCollector.RecordCustomMetric("gc_forced_count", 1.0, nil)
		gco.metricsCollector.RecordCustomMetric("gc_forced_duration_ms", float64(duration.Milliseconds()), nil)
		gco.metricsCollector.RecordCustomMetric("gc_freed_bytes", float64(freedBytes), nil)
	}
}

// SetTargetPercent sets the GC target percentage
func (gco *GCOptimizer) SetTargetPercent(percent int) {
	gco.mu.Lock()
	defer gco.mu.Unlock()

	oldPercent := gco.targetPercent
	gco.targetPercent = percent
	debug.SetGCPercent(percent)

	logx.Infow("GC target percent updated",
		logx.Field("oldPercent", oldPercent),
		logx.Field("newPercent", percent))

	if gco.metricsCollector != nil {
		gco.metricsCollector.RecordCustomMetric("gc_target_percent", float64(percent), nil)
	}
}

// adaptiveTuningLoop continuously adjusts GC settings based on system conditions
func (gco *GCOptimizer) adaptiveTuningLoop() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gco.updateAdaptiveTuning()
		case <-gco.done:
			return
		}
	}
}

// updateAdaptiveTuning adjusts GC parameters based on current system state
func (gco *GCOptimizer) updateAdaptiveTuning() {
	if !gco.adaptiveEnabled {
		return
	}

	// Get current system metrics
	memoryPressure := gco.calculateMemoryPressure()
	cpuUsage := gco.estimateCPUUsage()

	gco.mu.Lock()
	gco.memoryPressure = memoryPressure
	gco.cpuUsage = cpuUsage
	currentPercent := gco.targetPercent
	gco.mu.Unlock()

	// Calculate optimal GC target based on conditions
	newPercent := gco.calculateOptimalGCTarget(memoryPressure, cpuUsage)

	// Only change if the difference is significant
	if absInt(newPercent-currentPercent) >= 10 {
		gco.SetTargetPercent(newPercent)

		logx.Infow("Adaptive GC tuning applied",
			logx.Field("memoryPressure", memoryPressure),
			logx.Field("cpuUsage", cpuUsage),
			logx.Field("newGCPercent", newPercent))
	}
}

// calculateMemoryPressure calculates current memory pressure (0.0 to 1.0)
func (gco *GCOptimizer) calculateMemoryPressure() float64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if memStats.NextGC == 0 {
		return 0.0
	}

	pressure := float64(memStats.Alloc) / float64(memStats.NextGC)
	if pressure > 1.0 {
		pressure = 1.0
	}

	return pressure
}

// estimateCPUUsage estimates current CPU usage (simplified)
func (gco *GCOptimizer) estimateCPUUsage() float64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Use GC CPU fraction as a proxy for overall CPU usage
	// This is simplified - in production you might use more sophisticated metrics
	cpuUsage := memStats.GCCPUFraction * 10 // Scale up the GC CPU fraction

	if cpuUsage > 1.0 {
		cpuUsage = 1.0
	}

	return cpuUsage
}

// calculateOptimalGCTarget calculates optimal GC target based on system conditions
func (gco *GCOptimizer) calculateOptimalGCTarget(memoryPressure, cpuUsage float64) int {
	config := DefaultGCOptimizerConfig()
	basePercent := gco.targetPercent

	// Adjust based on memory pressure
	memoryAdjustment := 0
	if memoryPressure > config.MemoryThreshold {
		// High memory pressure - reduce GC target for more frequent collection
		memoryAdjustment = -int((memoryPressure - config.MemoryThreshold) * 50)
	} else if memoryPressure < 0.3 {
		// Low memory pressure - increase GC target for less frequent collection
		memoryAdjustment = int((0.3 - memoryPressure) * 30)
	}

	// Adjust based on CPU usage
	cpuAdjustment := 0
	if cpuUsage > config.CPUThreshold {
		// High CPU usage - increase GC target to reduce GC overhead
		cpuAdjustment = int((cpuUsage - config.CPUThreshold) * 40)
	}

	// Calculate new target
	newPercent := basePercent + memoryAdjustment + cpuAdjustment

	// Clamp to reasonable bounds
	if newPercent < config.MinTargetPercent {
		newPercent = config.MinTargetPercent
	} else if newPercent > config.MaxTargetPercent {
		newPercent = config.MaxTargetPercent
	}

	return newPercent
}

// recordGCMetrics records GC-related metrics
func (gco *GCOptimizer) recordGCMetrics(beforeStats *debug.GCStats) {
	if gco.metricsCollector == nil {
		return
	}

	var currentStats debug.GCStats
	debug.ReadGCStats(&currentStats)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Record basic GC metrics
	gco.metricsCollector.RecordCustomMetric("gc_target_percent", float64(gco.targetPercent), nil)
	gco.metricsCollector.RecordCustomMetric("gc_num_gc", float64(memStats.NumGC), nil)
	gco.metricsCollector.RecordCustomMetric("gc_cpu_fraction", memStats.GCCPUFraction, nil)
	gco.metricsCollector.RecordCustomMetric("gc_next_gc_bytes", float64(memStats.NextGC), nil)

	// Record adaptive tuning metrics
	gco.mu.RLock()
	memoryPressure := gco.memoryPressure
	cpuUsage := gco.cpuUsage
	totalForceGCs := atomic.LoadInt64(&gco.totalForceGCs)
	totalGCTime := gco.totalGCTime
	gco.mu.RUnlock()

	gco.metricsCollector.RecordCustomMetric("gc_memory_pressure", memoryPressure, nil)
	gco.metricsCollector.RecordCustomMetric("gc_cpu_usage", cpuUsage, nil)
	gco.metricsCollector.RecordCustomMetric("gc_total_forced", float64(totalForceGCs), nil)
	gco.metricsCollector.RecordCustomMetric("gc_total_time_ms", float64(totalGCTime.Milliseconds()), nil)

	// Record GC pause time if available
	if len(currentStats.Pause) > len(gco.lastGCStats.Pause) {
		newPauses := currentStats.Pause[len(gco.lastGCStats.Pause):]
		for _, pause := range newPauses {
			gco.metricsCollector.RecordCustomMetric("gc_pause_time_ms", float64(pause.Nanoseconds())/1e6, nil)
		}
	}

	// Update last stats
	gco.mu.Lock()
	gco.lastGCStats = currentStats
	gco.mu.Unlock()
}

// GetGCStats returns current GC statistics
func (gco *GCOptimizer) GetGCStats() *GCStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	var gcStats debug.GCStats
	debug.ReadGCStats(&gcStats)

	gco.mu.RLock()
	totalForceGCs := atomic.LoadInt64(&gco.totalForceGCs)
	totalGCTime := gco.totalGCTime
	memoryPressure := gco.memoryPressure
	cpuUsage := gco.cpuUsage
	targetPercent := gco.targetPercent
	gco.mu.RUnlock()

	return &GCStats{
		TargetPercent:   targetPercent,
		NumGC:           memStats.NumGC,
		GCCPUFraction:   memStats.GCCPUFraction,
		NextGC:          memStats.NextGC,
		LastGC:          time.Unix(0, int64(memStats.LastGC)),
		TotalForcedGCs:  totalForceGCs,
		TotalGCTime:     totalGCTime,
		MemoryPressure:  memoryPressure,
		CPUUsage:        cpuUsage,
		AdaptiveEnabled: gco.adaptiveEnabled,
	}
}

// EnableAdaptiveTuning enables or disables adaptive GC tuning
func (gco *GCOptimizer) EnableAdaptiveTuning(enabled bool) {
	gco.mu.Lock()
	defer gco.mu.Unlock()

	oldEnabled := gco.adaptiveEnabled
	gco.adaptiveEnabled = enabled

	logx.Infow("Adaptive GC tuning setting changed",
		logx.Field("oldEnabled", oldEnabled),
		logx.Field("newEnabled", enabled))

	if enabled && !oldEnabled {
		go gco.adaptiveTuningLoop()
	}
}

// OptimizeForLowMemory optimizes GC settings for low memory environments
func (gco *GCOptimizer) OptimizeForLowMemory() {
	gco.SetTargetPercent(20) // Very aggressive GC

	// Force GC immediately
	gco.ForceGC()

	logx.Info("GC optimized for low memory environment")
}

// OptimizeForHighThroughput optimizes GC settings for high throughput scenarios
func (gco *GCOptimizer) OptimizeForHighThroughput() {
	gco.SetTargetPercent(150) // Less frequent GC

	logx.Info("GC optimized for high throughput")
}

// OptimizeForLowLatency optimizes GC settings for low latency requirements
func (gco *GCOptimizer) OptimizeForLowLatency() {
	gco.SetTargetPercent(50) // Balanced approach

	logx.Info("GC optimized for low latency")
}

// GCStats represents GC statistics
type GCStats struct {
	TargetPercent   int           `json:"target_percent"`
	NumGC           uint32        `json:"num_gc"`
	GCCPUFraction   float64       `json:"gc_cpu_fraction"`
	NextGC          uint64        `json:"next_gc"`
	LastGC          time.Time     `json:"last_gc"`
	TotalForcedGCs  int64         `json:"total_forced_gcs"`
	TotalGCTime     time.Duration `json:"total_gc_time"`
	MemoryPressure  float64       `json:"memory_pressure"`
	CPUUsage        float64       `json:"cpu_usage"`
	AdaptiveEnabled bool          `json:"adaptive_enabled"`
}

// absInt returns the absolute value of an integer
func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
