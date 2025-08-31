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

package monitoring

import (
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// MemoryMonitor monitors memory usage and provides alerts and statistics
type MemoryMonitor struct {
	interval         time.Duration
	alertThreshold   int64
	metricsCollector MetricsCollector
	ticker           *time.Ticker
	done             chan struct{}

	// Memory tracking
	lastMemStats   runtime.MemStats
	memoryHistory  []MemorySnapshot
	maxHistorySize int

	// Alert state
	alertState    MemoryAlertState
	lastAlertTime time.Time
	alertCooldown time.Duration

	mu sync.RWMutex
}

// MemoryAlertState represents the current memory alert state
type MemoryAlertState int

const (
	MemoryAlertNormal MemoryAlertState = iota
	MemoryAlertWarning
	MemoryAlertCritical
)

func (s MemoryAlertState) String() string {
	switch s {
	case MemoryAlertNormal:
		return "normal"
	case MemoryAlertWarning:
		return "warning"
	case MemoryAlertCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MemorySnapshot represents a point-in-time memory snapshot
type MemorySnapshot struct {
	Timestamp       time.Time `json:"timestamp"`
	AllocBytes      uint64    `json:"alloc_bytes"`
	TotalAllocBytes uint64    `json:"total_alloc_bytes"`
	SysBytes        uint64    `json:"sys_bytes"`
	NumGC           uint32    `json:"num_gc"`
	GCCPUFraction   float64   `json:"gc_cpu_fraction"`
	NumGoroutines   int       `json:"num_goroutines"`
	HeapObjects     uint64    `json:"heap_objects"`
	StackInUse      uint64    `json:"stack_in_use"`
	MSpanInUse      uint64    `json:"mspan_in_use"`
	MCacheInUse     uint64    `json:"mcache_in_use"`
	NextGC          uint64    `json:"next_gc"`
	LastGC          time.Time `json:"last_gc"`
}

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(interval time.Duration, alertThreshold int64, metricsCollector MetricsCollector) *MemoryMonitor {
	monitor := &MemoryMonitor{
		interval:         interval,
		alertThreshold:   alertThreshold,
		metricsCollector: metricsCollector,
		done:             make(chan struct{}),
		maxHistorySize:   100,             // Keep last 100 snapshots
		alertCooldown:    5 * time.Minute, // 5 minute cooldown between alerts
		alertState:       MemoryAlertNormal,
	}

	// Initialize with current memory stats
	runtime.ReadMemStats(&monitor.lastMemStats)

	logx.Infow("Memory monitor initialized",
		logx.Field("interval", interval),
		logx.Field("alertThreshold", alertThreshold),
		logx.Field("maxHistory", monitor.maxHistorySize))

	return monitor
}

// Start begins memory monitoring
func (mm *MemoryMonitor) Start() {
	mm.ticker = time.NewTicker(mm.interval)
	go mm.monitorLoop()

	logx.Info("Memory monitor started")
}

// Stop stops memory monitoring
func (mm *MemoryMonitor) Stop() {
	if mm.ticker != nil {
		mm.ticker.Stop()
	}
	close(mm.done)

	logx.Info("Memory monitor stopped")
}

// monitorLoop is the main monitoring loop
func (mm *MemoryMonitor) monitorLoop() {
	defer mm.ticker.Stop()

	for {
		select {
		case <-mm.ticker.C:
			mm.collectMemoryStats()
		case <-mm.done:
			return
		}
	}
}

// collectMemoryStats collects and processes memory statistics
func (mm *MemoryMonitor) collectMemoryStats() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	snapshot := mm.createSnapshot(&memStats)
	mm.addSnapshot(snapshot)

	// Record metrics
	mm.recordMetrics(&memStats, snapshot)

	// Check for alerts
	mm.checkMemoryAlerts(&memStats)

	// Update last stats
	mm.mu.Lock()
	mm.lastMemStats = memStats
	mm.mu.Unlock()
}

// createSnapshot creates a memory snapshot from MemStats
func (mm *MemoryMonitor) createSnapshot(memStats *runtime.MemStats) MemorySnapshot {
	var lastGC time.Time
	if memStats.LastGC > 0 {
		lastGC = time.Unix(0, int64(memStats.LastGC))
	}

	return MemorySnapshot{
		Timestamp:       time.Now(),
		AllocBytes:      memStats.Alloc,
		TotalAllocBytes: memStats.TotalAlloc,
		SysBytes:        memStats.Sys,
		NumGC:           memStats.NumGC,
		GCCPUFraction:   memStats.GCCPUFraction,
		NumGoroutines:   runtime.NumGoroutine(),
		HeapObjects:     memStats.HeapObjects,
		StackInUse:      memStats.StackInuse,
		MSpanInUse:      memStats.MSpanInuse,
		MCacheInUse:     memStats.MCacheInuse,
		NextGC:          memStats.NextGC,
		LastGC:          lastGC,
	}
}

// addSnapshot adds a snapshot to the history
func (mm *MemoryMonitor) addSnapshot(snapshot MemorySnapshot) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.memoryHistory = append(mm.memoryHistory, snapshot)

	// Trim history if it exceeds max size
	if len(mm.memoryHistory) > mm.maxHistorySize {
		mm.memoryHistory = mm.memoryHistory[1:]
	}
}

// recordMetrics records memory metrics
func (mm *MemoryMonitor) recordMetrics(memStats *runtime.MemStats, snapshot MemorySnapshot) {
	if mm.metricsCollector == nil {
		return
	}

	// Record basic memory metrics
	mm.metricsCollector.RecordMemoryUsage("memory_monitor", int64(memStats.Alloc))
	mm.metricsCollector.RecordCustomMetric("memory_alloc_bytes", float64(memStats.Alloc), nil)
	mm.metricsCollector.RecordCustomMetric("memory_total_alloc_bytes", float64(memStats.TotalAlloc), nil)
	mm.metricsCollector.RecordCustomMetric("memory_sys_bytes", float64(memStats.Sys), nil)
	mm.metricsCollector.RecordCustomMetric("memory_num_gc", float64(memStats.NumGC), nil)
	mm.metricsCollector.RecordCustomMetric("memory_gc_cpu_fraction", memStats.GCCPUFraction, nil)
	mm.metricsCollector.RecordCustomMetric("memory_num_goroutines", float64(snapshot.NumGoroutines), nil)
	mm.metricsCollector.RecordCustomMetric("memory_heap_objects", float64(memStats.HeapObjects), nil)

	// Record detailed memory metrics
	mm.metricsCollector.RecordCustomMetric("memory_stack_inuse", float64(memStats.StackInuse), nil)
	mm.metricsCollector.RecordCustomMetric("memory_mspan_inuse", float64(memStats.MSpanInuse), nil)
	mm.metricsCollector.RecordCustomMetric("memory_mcache_inuse", float64(memStats.MCacheInuse), nil)
	mm.metricsCollector.RecordCustomMetric("memory_next_gc", float64(memStats.NextGC), nil)

	// Calculate and record derived metrics
	mm.recordDerivedMetrics(memStats, snapshot)
}

// recordDerivedMetrics records calculated metrics based on memory stats
func (mm *MemoryMonitor) recordDerivedMetrics(memStats *runtime.MemStats, snapshot MemorySnapshot) {
	mm.mu.RLock()
	lastStats := mm.lastMemStats
	history := mm.memoryHistory
	mm.mu.RUnlock()

	// Memory allocation rate (bytes per second)
	if len(history) >= 2 {
		prev := history[len(history)-2]
		timeDiff := snapshot.Timestamp.Sub(prev.Timestamp).Seconds()
		if timeDiff > 0 {
			allocRate := float64(snapshot.TotalAllocBytes-prev.TotalAllocBytes) / timeDiff
			mm.metricsCollector.RecordCustomMetric("memory_alloc_rate_bytes_per_sec", allocRate, nil)
		}
	}

	// GC frequency (GCs per minute)
	if memStats.NumGC > lastStats.NumGC {
		gcsSinceLastCheck := memStats.NumGC - lastStats.NumGC
		gcFreq := float64(gcsSinceLastCheck) * 60.0 / mm.interval.Seconds()
		mm.metricsCollector.RecordCustomMetric("memory_gc_frequency_per_minute", gcFreq, nil)
	}

	// Memory utilization percentage
	if memStats.NextGC > 0 {
		utilization := float64(memStats.Alloc) / float64(memStats.NextGC) * 100
		mm.metricsCollector.RecordCustomMetric("memory_utilization_percent", utilization, nil)
	}

	// Goroutine growth rate
	if len(history) >= 2 {
		prev := history[len(history)-2]
		goroutineGrowth := float64(snapshot.NumGoroutines - prev.NumGoroutines)
		mm.metricsCollector.RecordCustomMetric("memory_goroutine_growth", goroutineGrowth, nil)
	}
}

// checkMemoryAlerts checks if memory usage exceeds thresholds
func (mm *MemoryMonitor) checkMemoryAlerts(memStats *runtime.MemStats) {
	currentAlloc := int64(memStats.Alloc)

	mm.mu.Lock()
	defer mm.mu.Unlock()

	newState := mm.calculateAlertState(currentAlloc)

	// Only send alerts if state changed and cooldown has passed
	if newState != mm.alertState && time.Since(mm.lastAlertTime) > mm.alertCooldown {
		mm.sendMemoryAlert(newState, currentAlloc, memStats)
		mm.lastAlertTime = time.Now()
	}

	mm.alertState = newState
}

// calculateAlertState determines the current alert state based on memory usage
func (mm *MemoryMonitor) calculateAlertState(currentAlloc int64) MemoryAlertState {
	warningThreshold := mm.alertThreshold
	criticalThreshold := int64(float64(mm.alertThreshold) * 1.5)

	switch {
	case currentAlloc >= criticalThreshold:
		return MemoryAlertCritical
	case currentAlloc >= warningThreshold:
		return MemoryAlertWarning
	default:
		return MemoryAlertNormal
	}
}

// sendMemoryAlert sends a memory alert
func (mm *MemoryMonitor) sendMemoryAlert(state MemoryAlertState, currentAlloc int64, memStats *runtime.MemStats) {
	switch state {
	case MemoryAlertCritical:
		logx.Errorw("Memory alert - Critical",
			logx.Field("state", state),
			logx.Field("current_alloc_mb", float64(currentAlloc)/1024/1024),
			logx.Field("sys_mb", float64(memStats.Sys)/1024/1024),
			logx.Field("heap_alloc_mb", float64(memStats.HeapAlloc)/1024/1024),
			logx.Field("heap_sys_mb", float64(memStats.HeapSys)/1024/1024),
			logx.Field("gc_cpu_fraction", memStats.GCCPUFraction))
		return
	case MemoryAlertWarning:
		logx.Errorw("Memory alert - Warning",
			logx.Field("state", state),
			logx.Field("current_alloc_mb", float64(currentAlloc)/1024/1024),
			logx.Field("sys_mb", float64(memStats.Sys)/1024/1024),
			logx.Field("heap_alloc_mb", float64(memStats.HeapAlloc)/1024/1024),
			logx.Field("heap_sys_mb", float64(memStats.HeapSys)/1024/1024),
			logx.Field("gc_cpu_fraction", memStats.GCCPUFraction))
		return
	default:
		logx.Infow("Memory alert - Info",
			logx.Field("state", state),
			logx.Field("current_alloc_mb", float64(currentAlloc)/1024/1024),
			logx.Field("sys_mb", float64(memStats.Sys)/1024/1024),
			logx.Field("heap_alloc_mb", float64(memStats.HeapAlloc)/1024/1024),
			logx.Field("heap_sys_mb", float64(memStats.HeapSys)/1024/1024),
			logx.Field("gc_cpu_fraction", memStats.GCCPUFraction))
		return
	}

	// Record alert metric
	if mm.metricsCollector != nil {
		mm.metricsCollector.RecordCustomMetric("memory_alert", 1.0, map[string]string{
			"state": state.String(),
		})
	}
}

// GetCurrentStats returns current memory statistics
func (mm *MemoryMonitor) GetCurrentStats() MemorySnapshot {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return mm.createSnapshot(&memStats)
}

// GetMemoryHistory returns the memory history
func (mm *MemoryMonitor) GetMemoryHistory() []MemorySnapshot {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Return a copy to avoid race conditions
	history := make([]MemorySnapshot, len(mm.memoryHistory))
	copy(history, mm.memoryHistory)
	return history
}

// GetAlertState returns the current alert state
func (mm *MemoryMonitor) GetAlertState() MemoryAlertState {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	return mm.alertState
}

// ForceMemoryCheck forces an immediate memory check
func (mm *MemoryMonitor) ForceMemoryCheck() {
	mm.collectMemoryStats()
}

// GetMemoryTrends analyzes memory trends over time
func (mm *MemoryMonitor) GetMemoryTrends() *MemoryTrends {
	mm.mu.RLock()
	history := make([]MemorySnapshot, len(mm.memoryHistory))
	copy(history, mm.memoryHistory)
	mm.mu.RUnlock()

	if len(history) < 2 {
		return &MemoryTrends{}
	}

	trends := &MemoryTrends{
		SampleCount: len(history),
		TimeSpan:    history[len(history)-1].Timestamp.Sub(history[0].Timestamp),
	}

	// Calculate allocation trend
	firstAlloc := float64(history[0].AllocBytes)
	lastAlloc := float64(history[len(history)-1].AllocBytes)
	trends.AllocationTrend = (lastAlloc - firstAlloc) / firstAlloc * 100

	// Calculate GC trend
	firstGC := float64(history[0].NumGC)
	lastGC := float64(history[len(history)-1].NumGC)
	if trends.TimeSpan.Minutes() > 0 {
		trends.GCFrequency = (lastGC - firstGC) / trends.TimeSpan.Minutes()
	}

	// Calculate goroutine trend
	firstGoroutines := float64(history[0].NumGoroutines)
	lastGoroutines := float64(history[len(history)-1].NumGoroutines)
	trends.GoroutineTrend = (lastGoroutines - firstGoroutines) / firstGoroutines * 100

	// Calculate average CPU fraction
	var totalGCCPU float64
	for _, snapshot := range history {
		totalGCCPU += snapshot.GCCPUFraction
	}
	trends.AverageGCCPUFraction = totalGCCPU / float64(len(history))

	return trends
}

// MemoryTrends represents memory usage trends over time
type MemoryTrends struct {
	SampleCount          int           `json:"sample_count"`
	TimeSpan             time.Duration `json:"time_span"`
	AllocationTrend      float64       `json:"allocation_trend_percent"`
	GCFrequency          float64       `json:"gc_frequency_per_minute"`
	GoroutineTrend       float64       `json:"goroutine_trend_percent"`
	AverageGCCPUFraction float64       `json:"average_gc_cpu_fraction"`
}

// LogMemorySummary logs a summary of current memory usage
func (mm *MemoryMonitor) LogMemorySummary() {
	current := mm.GetCurrentStats()
	trends := mm.GetMemoryTrends()

	logx.Infow("Memory summary",
		logx.Field("allocMB", current.AllocBytes/(1024*1024)),
		logx.Field("sysMB", current.SysBytes/(1024*1024)),
		logx.Field("numGC", current.NumGC),
		logx.Field("gcCPU", current.GCCPUFraction),
		logx.Field("goroutines", current.NumGoroutines),
		logx.Field("allocationTrend", trends.AllocationTrend),
		logx.Field("gcFrequency", trends.GCFrequency),
		logx.Field("goroutineTrend", trends.GoroutineTrend))
}

// TriggerGCAndReport triggers GC and reports before/after stats
func (mm *MemoryMonitor) TriggerGCAndReport() {
	before := mm.GetCurrentStats()

	// Force GC
	runtime.GC()
	debug.FreeOSMemory()

	// Wait a bit for GC to complete
	time.Sleep(100 * time.Millisecond)

	after := mm.GetCurrentStats()

	freedBytes := int64(before.AllocBytes) - int64(after.AllocBytes)

	logx.Infow("Forced GC completed",
		logx.Field("beforeMB", before.AllocBytes/(1024*1024)),
		logx.Field("afterMB", after.AllocBytes/(1024*1024)),
		logx.Field("freedMB", freedBytes/(1024*1024)),
		logx.Field("gcCount", after.NumGC-before.NumGC))

	if mm.metricsCollector != nil {
		mm.metricsCollector.RecordCustomMetric("memory_forced_gc_freed_bytes", float64(freedBytes), nil)
	}
}
