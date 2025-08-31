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
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// PermissionResult 权限结果结构
type PermissionResult struct {
	DataScope     string        `json:"data_scope"`
	SubDept       string        `json:"sub_dept"`
	CustomDept    string        `json:"custom_dept"`
	Level         string        `json:"level"`
	Source        string        `json:"source"`
	ExecutionTime time.Duration `json:"execution_time"`
	CacheHit      bool          `json:"cache_hit"`
	FallbackUsed  bool          `json:"fallback_used"`
	ErrorMessage  string        `json:"error_message,omitempty"`
}

// PermissionRequest 权限请求结构
type PermissionRequest struct {
	RoleCodes []string  `json:"role_codes"`
	TenantID  uint64    `json:"tenant_id"`
	DeptID    uint64    `json:"dept_id"`
	Operation string    `json:"operation"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

// MemoryPoolOptimizer 内存池优化器
type MemoryPoolOptimizer struct {
	permissionResultPool  *PermissionResultPool
	permissionRequestPool *PermissionRequestPool
	stringBuilderPool     *StringBuilderPool
	slicePool             *SlicePool

	// 内存统计
	stats *MemoryPoolStats

	// 配置
	config *MemoryPoolConfig
}

// MemoryPoolConfig 内存池配置
type MemoryPoolConfig struct {
	MaxObjectsPerPool int           `json:"max_objects_per_pool"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
	EnableMetrics     bool          `json:"enable_metrics"`
	PreAllocateSize   int           `json:"pre_allocate_size"`
	GCForceInterval   time.Duration `json:"gc_force_interval"`
	MemoryThresholdMB int64         `json:"memory_threshold_mb"`
}

// MemoryPoolStats 内存池统计
type MemoryPoolStats struct {
	TotalGets          int64     `json:"total_gets"`
	TotalPuts          int64     `json:"total_puts"`
	PoolHits           int64     `json:"pool_hits"`
	PoolMisses         int64     `json:"pool_misses"`
	HitRate            float64   `json:"hit_rate"`
	CurrentAllocatedMB float64   `json:"current_allocated_mb"`
	PeakAllocatedMB    float64   `json:"peak_allocated_mb"`
	GCRunCount         int64     `json:"gc_run_count"`
	LastGCTime         time.Time `json:"last_gc_time"`
	LastCleanupTime    time.Time `json:"last_cleanup_time"`
}

// PermissionResultPool 权限结果对象池
type PermissionResultPool struct {
	pool   sync.Pool
	gets   int64
	puts   int64
	hits   int64
	misses int64
}

// PermissionRequestPool 权限请求对象池
type PermissionRequestPool struct {
	pool   sync.Pool
	gets   int64
	puts   int64
	hits   int64
	misses int64
}

// StringBuilderPool 字符串构建器池
type StringBuilderPool struct {
	pool     sync.Pool
	capacity int
	gets     int64
	puts     int64
	hits     int64
	misses   int64
}

// SlicePool 切片对象池
type SlicePool struct {
	stringSlicePool sync.Pool
	intSlicePool    sync.Pool
	gets            int64
	puts            int64
	hits            int64
	misses          int64
}

// NewMemoryPoolOptimizer 创建内存池优化器
func NewMemoryPoolOptimizer(config *MemoryPoolConfig) *MemoryPoolOptimizer {
	if config == nil {
		config = &MemoryPoolConfig{
			MaxObjectsPerPool: 1000,
			CleanupInterval:   time.Minute * 5,
			EnableMetrics:     true,
			PreAllocateSize:   100,
			GCForceInterval:   time.Second * 30,
			MemoryThresholdMB: 512,
		}
	}

	optimizer := &MemoryPoolOptimizer{
		config: config,
		stats:  &MemoryPoolStats{},
	}

	// 初始化对象池
	optimizer.initializePools()

	return optimizer
}

// Start 启动内存池优化器的后台服务
func (mpo *MemoryPoolOptimizer) Start(ctx context.Context) error {
	// 启动清理协程
	if mpo.config.CleanupInterval > 0 {
		go mpo.startCleanupRoutine(ctx)
	}

	// 启动GC协程
	if mpo.config.GCForceInterval > 0 {
		go mpo.startGCRoutine(ctx)
	}

	return nil
}

// Stop 停止内存池优化器
func (mpo *MemoryPoolOptimizer) Stop() {
	// 优雅关闭，清理资源
	runtime.GC()
}

// initializePools 初始化所有对象池
func (mpo *MemoryPoolOptimizer) initializePools() {
	// 初始化权限结果池
	mpo.permissionResultPool = &PermissionResultPool{
		pool: sync.Pool{
			New: func() interface{} {
				atomic.AddInt64(&mpo.permissionResultPool.misses, 1)
				return &PermissionResult{}
			},
		},
	}

	// 初始化权限请求池
	mpo.permissionRequestPool = &PermissionRequestPool{
		pool: sync.Pool{
			New: func() interface{} {
				atomic.AddInt64(&mpo.permissionRequestPool.misses, 1)
				return &PermissionRequest{
					RoleCodes: make([]string, 0, 8), // 预分配8个元素
				}
			},
		},
	}

	// 初始化字符串构建器池
	mpo.stringBuilderPool = &StringBuilderPool{
		capacity: 256, // 默认容量
		pool: sync.Pool{
			New: func() interface{} {
				atomic.AddInt64(&mpo.stringBuilderPool.misses, 1)
				builder := &Builder{}
				builder.Grow(256) // 预分配256字节
				return builder
			},
		},
	}

	// 初始化切片池
	mpo.slicePool = &SlicePool{
		stringSlicePool: sync.Pool{
			New: func() interface{} {
				atomic.AddInt64(&mpo.slicePool.misses, 1)
				return make([]string, 0, 16) // 预分配16个元素
			},
		},
		intSlicePool: sync.Pool{
			New: func() interface{} {
				atomic.AddInt64(&mpo.slicePool.misses, 1)
				return make([]int, 0, 16) // 预分配16个元素
			},
		},
	}

	// 预分配对象以提高性能
	mpo.preAllocateObjects()
}

// preAllocateObjects 预分配对象
func (mpo *MemoryPoolOptimizer) preAllocateObjects() {
	// 预分配权限结果对象
	permResults := make([]*PermissionResult, mpo.config.PreAllocateSize)
	for i := 0; i < mpo.config.PreAllocateSize; i++ {
		permResults[i] = &PermissionResult{}
	}
	for _, result := range permResults {
		mpo.permissionResultPool.pool.Put(result)
	}

	// 预分配权限请求对象
	permRequests := make([]*PermissionRequest, mpo.config.PreAllocateSize)
	for i := 0; i < mpo.config.PreAllocateSize; i++ {
		permRequests[i] = &PermissionRequest{
			RoleCodes: make([]string, 0, 8),
		}
	}
	for _, request := range permRequests {
		mpo.permissionRequestPool.pool.Put(request)
	}

	// 预分配字符串构建器
	builders := make([]*Builder, mpo.config.PreAllocateSize)
	for i := 0; i < mpo.config.PreAllocateSize; i++ {
		builder := &Builder{}
		builder.Grow(mpo.stringBuilderPool.capacity)
		builders[i] = builder
	}
	for _, builder := range builders {
		mpo.stringBuilderPool.pool.Put(builder)
	}
}

// GetPermissionResult 从池中获取权限结果对象
func (mpo *MemoryPoolOptimizer) GetPermissionResult() *PermissionResult {
	atomic.AddInt64(&mpo.permissionResultPool.gets, 1)

	if v := mpo.permissionResultPool.pool.Get(); v != nil {
		atomic.AddInt64(&mpo.permissionResultPool.hits, 1)
		result := v.(*PermissionResult)
		// 重置对象状态
		mpo.resetPermissionResult(result)
		return result
	}

	atomic.AddInt64(&mpo.permissionResultPool.misses, 1)
	return &PermissionResult{}
}

// PutPermissionResult 将权限结果对象放回池中
func (mpo *MemoryPoolOptimizer) PutPermissionResult(result *PermissionResult) {
	if result == nil {
		return
	}

	atomic.AddInt64(&mpo.permissionResultPool.puts, 1)

	// 重置对象状态
	mpo.resetPermissionResult(result)

	mpo.permissionResultPool.pool.Put(result)
}

// resetPermissionResult 重置权限结果对象
func (mpo *MemoryPoolOptimizer) resetPermissionResult(result *PermissionResult) {
	result.DataScope = ""
	result.SubDept = ""
	result.CustomDept = ""
	result.Level = ""
	result.Source = ""
	result.ExecutionTime = 0
	result.CacheHit = false
	result.FallbackUsed = false
	result.ErrorMessage = ""
}

// GetPermissionRequest 从池中获取权限请求对象
func (mpo *MemoryPoolOptimizer) GetPermissionRequest() *PermissionRequest {
	atomic.AddInt64(&mpo.permissionRequestPool.gets, 1)

	if v := mpo.permissionRequestPool.pool.Get(); v != nil {
		atomic.AddInt64(&mpo.permissionRequestPool.hits, 1)
		request := v.(*PermissionRequest)
		// 重置对象状态
		mpo.resetPermissionRequest(request)
		return request
	}

	atomic.AddInt64(&mpo.permissionRequestPool.misses, 1)
	return &PermissionRequest{
		RoleCodes: make([]string, 0, 8),
	}
}

// PutPermissionRequest 将权限请求对象放回池中
func (mpo *MemoryPoolOptimizer) PutPermissionRequest(request *PermissionRequest) {
	if request == nil {
		return
	}

	atomic.AddInt64(&mpo.permissionRequestPool.puts, 1)

	// 重置对象状态
	mpo.resetPermissionRequest(request)

	mpo.permissionRequestPool.pool.Put(request)
}

// resetPermissionRequest 重置权限请求对象
func (mpo *MemoryPoolOptimizer) resetPermissionRequest(request *PermissionRequest) {
	request.RoleCodes = request.RoleCodes[:0] // 保留底层数组，只重置长度
	request.TenantID = 0
	request.DeptID = 0
	request.Operation = ""
	request.RequestID = ""
	request.Timestamp = time.Time{}
}

// GetStringBuilder 从池中获取字符串构建器
func (mpo *MemoryPoolOptimizer) GetStringBuilder() *Builder {
	atomic.AddInt64(&mpo.stringBuilderPool.gets, 1)

	if v := mpo.stringBuilderPool.pool.Get(); v != nil {
		atomic.AddInt64(&mpo.stringBuilderPool.hits, 1)
		builder := v.(*Builder)
		builder.Reset()
		return builder
	}

	atomic.AddInt64(&mpo.stringBuilderPool.misses, 1)
	builder := &Builder{}
	builder.Grow(mpo.stringBuilderPool.capacity)
	return builder
}

// PutStringBuilder 将字符串构建器放回池中
func (mpo *MemoryPoolOptimizer) PutStringBuilder(builder *Builder) {
	if builder == nil {
		return
	}

	atomic.AddInt64(&mpo.stringBuilderPool.puts, 1)

	// 如果构建器太大，不放回池中以避免内存浪费
	if builder.Cap() > mpo.stringBuilderPool.capacity*4 {
		return
	}

	builder.Reset()
	mpo.stringBuilderPool.pool.Put(builder)
}

// GetStringSlice 从池中获取字符串切片
func (mpo *MemoryPoolOptimizer) GetStringSlice() []string {
	atomic.AddInt64(&mpo.slicePool.gets, 1)

	if v := mpo.slicePool.stringSlicePool.Get(); v != nil {
		atomic.AddInt64(&mpo.slicePool.hits, 1)
		slice := v.([]string)
		return slice[:0] // 重置长度但保留容量
	}

	atomic.AddInt64(&mpo.slicePool.misses, 1)
	return make([]string, 0, 16)
}

// PutStringSlice 将字符串切片放回池中
func (mpo *MemoryPoolOptimizer) PutStringSlice(slice []string) {
	if slice == nil {
		return
	}

	atomic.AddInt64(&mpo.slicePool.puts, 1)

	// 如果切片太大，不放回池中
	if cap(slice) > 64 {
		return
	}

	// 清除引用以避免内存泄漏
	for i := range slice {
		slice[i] = ""
	}
	slice = slice[:0]

	mpo.slicePool.stringSlicePool.Put(slice)
}

// GetIntSlice 从池中获取整数切片
func (mpo *MemoryPoolOptimizer) GetIntSlice() []int {
	atomic.AddInt64(&mpo.slicePool.gets, 1)

	if v := mpo.slicePool.intSlicePool.Get(); v != nil {
		atomic.AddInt64(&mpo.slicePool.hits, 1)
		slice := v.([]int)
		return slice[:0] // 重置长度但保留容量
	}

	atomic.AddInt64(&mpo.slicePool.misses, 1)
	return make([]int, 0, 16)
}

// PutIntSlice 将整数切片放回池中
func (mpo *MemoryPoolOptimizer) PutIntSlice(slice []int) {
	if slice == nil {
		return
	}

	atomic.AddInt64(&mpo.slicePool.puts, 1)

	// 如果切片太大，不放回池中
	if cap(slice) > 64 {
		return
	}

	slice = slice[:0]
	mpo.slicePool.intSlicePool.Put(slice)
}

// GetStats 获取内存池统计信息
func (mpo *MemoryPoolOptimizer) GetStats() *MemoryPoolStats {
	// 计算命中率
	totalGets := atomic.LoadInt64(&mpo.permissionResultPool.gets) +
		atomic.LoadInt64(&mpo.permissionRequestPool.gets) +
		atomic.LoadInt64(&mpo.stringBuilderPool.gets) +
		atomic.LoadInt64(&mpo.slicePool.gets)

	totalHits := atomic.LoadInt64(&mpo.permissionResultPool.hits) +
		atomic.LoadInt64(&mpo.permissionRequestPool.hits) +
		atomic.LoadInt64(&mpo.stringBuilderPool.hits) +
		atomic.LoadInt64(&mpo.slicePool.hits)

	totalPuts := atomic.LoadInt64(&mpo.permissionResultPool.puts) +
		atomic.LoadInt64(&mpo.permissionRequestPool.puts) +
		atomic.LoadInt64(&mpo.stringBuilderPool.puts) +
		atomic.LoadInt64(&mpo.slicePool.puts)

	hitRate := float64(0)
	if totalGets > 0 {
		hitRate = float64(totalHits) / float64(totalGets)
	}

	// 获取内存使用情况
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	currentAllocatedMB := float64(memStats.Alloc) / 1024 / 1024

	// 更新峰值内存使用
	if currentAllocatedMB > mpo.stats.PeakAllocatedMB {
		mpo.stats.PeakAllocatedMB = currentAllocatedMB
	}

	return &MemoryPoolStats{
		TotalGets:          totalGets,
		TotalPuts:          totalPuts,
		PoolHits:           totalHits,
		PoolMisses:         totalGets - totalHits,
		HitRate:            hitRate,
		CurrentAllocatedMB: currentAllocatedMB,
		PeakAllocatedMB:    mpo.stats.PeakAllocatedMB,
		GCRunCount:         mpo.stats.GCRunCount,
		LastGCTime:         mpo.stats.LastGCTime,
		LastCleanupTime:    mpo.stats.LastCleanupTime,
	}
}

// startCleanupRoutine 启动清理协程
func (mpo *MemoryPoolOptimizer) startCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(mpo.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mpo.cleanup()
			mpo.stats.LastCleanupTime = time.Now()
		}
	}
}

// startGCRoutine 启动GC协程
func (mpo *MemoryPoolOptimizer) startGCRoutine(ctx context.Context) {
	ticker := time.NewTicker(mpo.config.GCForceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 检查内存使用情况，如果超过阈值则强制GC
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			currentMB := int64(memStats.Alloc / 1024 / 1024)

			if currentMB > mpo.config.MemoryThresholdMB {
				runtime.GC()
				atomic.AddInt64(&mpo.stats.GCRunCount, 1)
				mpo.stats.LastGCTime = time.Now()
			}
		}
	}
}

// cleanup 清理过期对象
func (mpo *MemoryPoolOptimizer) cleanup() {
	// 这里可以实现更复杂的清理逻辑
	// 例如清理长时间未使用的对象池
	runtime.GC()
	atomic.AddInt64(&mpo.stats.GCRunCount, 1)
	mpo.stats.LastGCTime = time.Now()
}

// ResetStats 重置统计信息
func (mpo *MemoryPoolOptimizer) ResetStats() {
	atomic.StoreInt64(&mpo.permissionResultPool.gets, 0)
	atomic.StoreInt64(&mpo.permissionResultPool.puts, 0)
	atomic.StoreInt64(&mpo.permissionResultPool.hits, 0)
	atomic.StoreInt64(&mpo.permissionResultPool.misses, 0)

	atomic.StoreInt64(&mpo.permissionRequestPool.gets, 0)
	atomic.StoreInt64(&mpo.permissionRequestPool.puts, 0)
	atomic.StoreInt64(&mpo.permissionRequestPool.hits, 0)
	atomic.StoreInt64(&mpo.permissionRequestPool.misses, 0)

	atomic.StoreInt64(&mpo.stringBuilderPool.gets, 0)
	atomic.StoreInt64(&mpo.stringBuilderPool.puts, 0)
	atomic.StoreInt64(&mpo.stringBuilderPool.hits, 0)
	atomic.StoreInt64(&mpo.stringBuilderPool.misses, 0)

	atomic.StoreInt64(&mpo.slicePool.gets, 0)
	atomic.StoreInt64(&mpo.slicePool.puts, 0)
	atomic.StoreInt64(&mpo.slicePool.hits, 0)
	atomic.StoreInt64(&mpo.slicePool.misses, 0)

	// 原子性地重置stats以避免并发访问问题
	newStats := &MemoryPoolStats{}
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&mpo.stats)), unsafe.Pointer(newStats))
}

// Builder 简化的字符串构建器接口
type Builder interface {
	WriteString(s string) (int, error)
	WriteByte(c byte) error
	String() string
	Reset()
	Grow(n int)
	Cap() int
}
