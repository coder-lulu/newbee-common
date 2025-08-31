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
	"bytes"
	"runtime"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// MemoryOptimizer provides comprehensive memory optimization for middleware components
type MemoryOptimizer struct {
	config           *MemoryOptimizerConfig
	bufferPool       *sync.Pool
	stringInterner   *StringInterner
	objectPoolMgr    *ObjectPoolManager
	memoryMonitor    *MemoryMonitor
	gcOptimizer      *GCOptimizer
	leakDetector     *LeakDetector
	metricsCollector MetricsCollector
	mu               sync.RWMutex
}

// MemoryOptimizerConfig defines configuration for memory optimization
type MemoryOptimizerConfig struct {
	// Buffer pool configuration
	BufferPoolInitialSize int `json:"buffer_pool_initial_size"`
	BufferPoolMaxSize     int `json:"buffer_pool_max_size"`
	BufferReuseThreshold  int `json:"buffer_reuse_threshold"`

	// String interning configuration
	StringInterningEnabled bool          `json:"string_interning_enabled"`
	MaxInternedStrings     int           `json:"max_interned_strings"`
	InternedStringTTL      time.Duration `json:"interned_string_ttl"`

	// Object pooling configuration
	ObjectPoolingEnabled bool          `json:"object_pooling_enabled"`
	PoolCleanupInterval  time.Duration `json:"pool_cleanup_interval"`

	// Memory monitoring configuration
	MemoryMonitorEnabled bool          `json:"memory_monitor_enabled"`
	MonitorInterval      time.Duration `json:"monitor_interval"`
	MemoryAlertThreshold int64         `json:"memory_alert_threshold"`

	// GC optimization configuration
	GCOptimizationEnabled bool          `json:"gc_optimization_enabled"`
	GCTargetPercent       int           `json:"gc_target_percent"`
	GCForceInterval       time.Duration `json:"gc_force_interval"`

	// Leak detection configuration
	LeakDetectionEnabled   bool          `json:"leak_detection_enabled"`
	LeakCheckInterval      time.Duration `json:"leak_check_interval"`
	GoroutineLeakThreshold int           `json:"goroutine_leak_threshold"`
}

// DefaultMemoryOptimizerConfig returns default memory optimizer configuration
func DefaultMemoryOptimizerConfig() *MemoryOptimizerConfig {
	return &MemoryOptimizerConfig{
		BufferPoolInitialSize:  1024,
		BufferPoolMaxSize:      64 * 1024,  // 64KB
		BufferReuseThreshold:   128 * 1024, // 128KB
		StringInterningEnabled: true,
		MaxInternedStrings:     10000,
		InternedStringTTL:      30 * time.Minute,
		ObjectPoolingEnabled:   true,
		PoolCleanupInterval:    5 * time.Minute,
		MemoryMonitorEnabled:   true,
		MonitorInterval:        30 * time.Second,
		MemoryAlertThreshold:   100 * 1024 * 1024, // 100MB
		GCOptimizationEnabled:  true,
		GCTargetPercent:        50, // Lower than default 100 for better memory efficiency
		GCForceInterval:        5 * time.Minute,
		LeakDetectionEnabled:   true,
		LeakCheckInterval:      1 * time.Minute,
		GoroutineLeakThreshold: 1000,
	}
}

// NewMemoryOptimizer creates a new memory optimizer
func NewMemoryOptimizer(config *MemoryOptimizerConfig, metricsCollector MetricsCollector) *MemoryOptimizer {
	if config == nil {
		config = DefaultMemoryOptimizerConfig()
	}

	optimizer := &MemoryOptimizer{
		config:           config,
		metricsCollector: metricsCollector,
	}

	// Initialize buffer pool
	optimizer.bufferPool = &sync.Pool{
		New: func() interface{} {
			buffer := bytes.NewBuffer(make([]byte, 0, config.BufferPoolInitialSize))
			optimizer.recordMetric("buffer_pool_new", 1.0)
			return buffer
		},
	}

	// Initialize string interner
	if config.StringInterningEnabled {
		optimizer.stringInterner = NewStringInterner(config.MaxInternedStrings, config.InternedStringTTL)
	}

	// Initialize object pool manager
	if config.ObjectPoolingEnabled {
		optimizer.objectPoolMgr = NewObjectPoolManager(config.PoolCleanupInterval)
	}

	// Initialize memory monitor
	if config.MemoryMonitorEnabled {
		optimizer.memoryMonitor = NewMemoryMonitor(config.MonitorInterval, config.MemoryAlertThreshold, metricsCollector)
		optimizer.memoryMonitor.Start()
	}

	// Initialize GC optimizer
	if config.GCOptimizationEnabled {
		optimizer.gcOptimizer = NewGCOptimizer(config.GCTargetPercent, config.GCForceInterval, metricsCollector)
		optimizer.gcOptimizer.Start()
	}

	// Initialize leak detector
	if config.LeakDetectionEnabled {
		optimizer.leakDetector = NewLeakDetector(config.LeakCheckInterval, config.GoroutineLeakThreshold, metricsCollector)
		optimizer.leakDetector.Start()
	}

	logx.Infow("Memory optimizer initialized",
		logx.Field("bufferPoolEnabled", true),
		logx.Field("stringInterningEnabled", config.StringInterningEnabled),
		logx.Field("objectPoolingEnabled", config.ObjectPoolingEnabled),
		logx.Field("memoryMonitorEnabled", config.MemoryMonitorEnabled),
		logx.Field("gcOptimizationEnabled", config.GCOptimizationEnabled),
		logx.Field("leakDetectionEnabled", config.LeakDetectionEnabled))

	return optimizer
}

// GetBuffer gets a buffer from the pool
func (mo *MemoryOptimizer) GetBuffer() *bytes.Buffer {
	buffer := mo.bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	mo.recordMetric("buffer_pool_get", 1.0)
	return buffer
}

// PutBuffer returns a buffer to the pool
func (mo *MemoryOptimizer) PutBuffer(buffer *bytes.Buffer) {
	// Only return buffers that haven't grown too large
	if buffer.Cap() <= mo.config.BufferReuseThreshold {
		mo.bufferPool.Put(buffer)
		mo.recordMetric("buffer_pool_put", 1.0)
	} else {
		mo.recordMetric("buffer_pool_discard", 1.0)
	}
}

// InternString interns a string for memory efficiency
func (mo *MemoryOptimizer) InternString(s string) string {
	if mo.stringInterner == nil {
		return s
	}
	return mo.stringInterner.Intern(s)
}

// GetObjectPool gets an object pool for the specified type
func (mo *MemoryOptimizer) GetObjectPool(poolType string) *sync.Pool {
	if mo.objectPoolMgr == nil {
		return nil
	}
	return mo.objectPoolMgr.GetPool(poolType)
}

// RegisterObjectPool registers a new object pool
func (mo *MemoryOptimizer) RegisterObjectPool(poolType string, newFunc func() interface{}) {
	if mo.objectPoolMgr != nil {
		mo.objectPoolMgr.RegisterPool(poolType, newFunc)
	}
}

// GetMemoryStats returns current memory statistics
func (mo *MemoryOptimizer) GetMemoryStats() *MemoryStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	stats := &MemoryStats{
		AllocBytes:      memStats.Alloc,
		TotalAllocBytes: memStats.TotalAlloc,
		SysBytes:        memStats.Sys,
		NumGC:           memStats.NumGC,
		GCCPUFraction:   memStats.GCCPUFraction,
		NumGoroutines:   runtime.NumGoroutine(),
		Timestamp:       time.Now(),
	}

	if mo.stringInterner != nil {
		stats.StringInternerStats = mo.stringInterner.GetStats()
	}

	if mo.objectPoolMgr != nil {
		stats.ObjectPoolStats = mo.objectPoolMgr.GetStats()
	}

	return stats
}

// ForceGC forces garbage collection
func (mo *MemoryOptimizer) ForceGC() {
	if mo.gcOptimizer != nil {
		mo.gcOptimizer.ForceGC()
	} else {
		runtime.GC()
	}
}

// OptimizeForHighThroughput optimizes settings for high throughput scenarios
func (mo *MemoryOptimizer) OptimizeForHighThroughput() {
	mo.mu.Lock()
	defer mo.mu.Unlock()

	// Adjust GC target for high throughput
	if mo.gcOptimizer != nil {
		mo.gcOptimizer.SetTargetPercent(100) // Higher GC target for throughput
	}

	// Increase buffer pool sizes
	mo.config.BufferPoolInitialSize = 2048
	mo.config.BufferPoolMaxSize = 128 * 1024

	logx.Info("Memory optimizer configured for high throughput")
	mo.recordMetric("optimization_high_throughput", 1.0)
}

// OptimizeForLowMemory optimizes settings for low memory scenarios
func (mo *MemoryOptimizer) OptimizeForLowMemory() {
	mo.mu.Lock()
	defer mo.mu.Unlock()

	// Adjust GC target for low memory usage
	if mo.gcOptimizer != nil {
		mo.gcOptimizer.SetTargetPercent(30) // Lower GC target for memory efficiency
	}

	// Reduce buffer pool sizes
	mo.config.BufferPoolInitialSize = 512
	mo.config.BufferPoolMaxSize = 32 * 1024

	// Force GC more frequently
	if mo.gcOptimizer != nil {
		mo.gcOptimizer.ForceGC()
	}

	logx.Info("Memory optimizer configured for low memory")
	mo.recordMetric("optimization_low_memory", 1.0)
}

// recordMetric records a metric with the metrics collector
func (mo *MemoryOptimizer) recordMetric(name string, value float64) {
	if mo.metricsCollector != nil {
		mo.metricsCollector.RecordCustomMetric("memory_optimizer_"+name, value, nil)
	}
}

// Close gracefully shuts down the memory optimizer
func (mo *MemoryOptimizer) Close() error {
	if mo.memoryMonitor != nil {
		mo.memoryMonitor.Stop()
	}

	if mo.gcOptimizer != nil {
		mo.gcOptimizer.Stop()
	}

	if mo.leakDetector != nil {
		mo.leakDetector.Stop()
	}

	if mo.objectPoolMgr != nil {
		mo.objectPoolMgr.Close()
	}

	if mo.stringInterner != nil {
		mo.stringInterner.Close()
	}

	logx.Info("Memory optimizer closed")
	return nil
}

// MemoryStats represents memory usage statistics
type MemoryStats struct {
	AllocBytes          uint64                `json:"alloc_bytes"`
	TotalAllocBytes     uint64                `json:"total_alloc_bytes"`
	SysBytes            uint64                `json:"sys_bytes"`
	NumGC               uint32                `json:"num_gc"`
	GCCPUFraction       float64               `json:"gc_cpu_fraction"`
	NumGoroutines       int                   `json:"num_goroutines"`
	Timestamp           time.Time             `json:"timestamp"`
	StringInternerStats *StringInternerStats  `json:"string_interner_stats,omitempty"`
	ObjectPoolStats     map[string]*PoolStats `json:"object_pool_stats,omitempty"`
}

// StringInternerStats represents string interner statistics
type StringInternerStats struct {
	TotalStrings  int     `json:"total_strings"`
	UniqueStrings int     `json:"unique_strings"`
	HitRate       float64 `json:"hit_rate"`
	MemorySaved   int64   `json:"memory_saved"`
}

// PoolStats represents object pool statistics
type PoolStats struct {
	Gets        int64 `json:"gets"`
	Puts        int64 `json:"puts"`
	Misses      int64 `json:"misses"`
	CurrentSize int   `json:"current_size"`
}

// Global memory optimizer instance
var globalMemoryOptimizer *MemoryOptimizer
var memoryOptimizerOnce sync.Once

// GetGlobalMemoryOptimizer returns the global memory optimizer instance
func GetGlobalMemoryOptimizer() *MemoryOptimizer {
	memoryOptimizerOnce.Do(func() {
		globalMemoryOptimizer = NewMemoryOptimizer(
			DefaultMemoryOptimizerConfig(),
			GetDefaultMetricsCollector(),
		)
	})
	return globalMemoryOptimizer
}

// InitializeMemoryOptimizer initializes the global memory optimizer with custom config
func InitializeMemoryOptimizer(config *MemoryOptimizerConfig, metricsCollector MetricsCollector) {
	if globalMemoryOptimizer != nil {
		globalMemoryOptimizer.Close()
	}
	globalMemoryOptimizer = NewMemoryOptimizer(config, metricsCollector)
}
