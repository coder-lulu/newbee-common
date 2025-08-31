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
	"sync"
	"sync/atomic"
	"time"
)

// L1Cache L1本地缓存实现
type L1Cache struct {
	// 核心存储
	storage map[string]*CacheEntry
	lruList *LRUList
	mu      sync.RWMutex

	// 配置参数
	config *L1CacheConfig

	// 性能指标
	metrics *L1CacheMetrics

	// 后台清理控制
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	cleanupOnce   sync.Once

	// 预热控制
	isWarming   int32
	warmupMutex sync.Mutex
}

// L1CacheConfig L1缓存配置
type L1CacheConfig struct {
	MaxSize           int           `json:"max_size"`           // 最大缓存条目数
	DefaultTTL        time.Duration `json:"default_ttl"`        // 默认TTL
	CleanupInterval   time.Duration `json:"cleanup_interval"`   // 清理间隔
	PreWarmSize       int           `json:"pre_warm_size"`      // 预热大小
	EnableMetrics     bool          `json:"enable_metrics"`     // 启用指标
	MaxMemoryMB       int64         `json:"max_memory_mb"`      // 最大内存限制(MB)
	EvictionPolicy    string        `json:"eviction_policy"`    // 淘汰策略: "lru", "lfu", "ttl"
	EnableCompression bool          `json:"enable_compression"` // 启用压缩
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Key         string            `json:"key"`
	Value       *PermissionResult `json:"value"`
	ExpireTime  time.Time         `json:"expire_time"`
	AccessTime  time.Time         `json:"access_time"`
	CreateTime  time.Time         `json:"create_time"`
	AccessCount int64             `json:"access_count"` // 需要在锁保护下访问
	Size        int64             `json:"size"`         // 条目大小(字节)

	// LRU链表节点
	prev *CacheEntry
	next *CacheEntry
}

// L1CacheMetrics L1缓存指标
type L1CacheMetrics struct {
	// 基础指标
	TotalRequests int64 `json:"total_requests"`
	HitCount      int64 `json:"hit_count"`
	MissCount     int64 `json:"miss_count"`
	EvictionCount int64 `json:"eviction_count"`

	// 性能指标
	AvgAccessTime time.Duration `json:"avg_access_time"`
	HitRate       float64       `json:"hit_rate"`

	// 容量指标
	CurrentSize   int64   `json:"current_size"`
	MaxSize       int64   `json:"max_size"`
	MemoryUsageMB float64 `json:"memory_usage_mb"`

	// 时间统计
	LastAccessTime  time.Time `json:"last_access_time"`
	LastEvictTime   time.Time `json:"last_evict_time"`
	LastCleanupTime time.Time `json:"last_cleanup_time"`
}

// LRUList LRU双向链表
type LRUList struct {
	head    *CacheEntry
	tail    *CacheEntry
	size    int64
	maxSize int64
}

// NewL1Cache 创建L1缓存实例
func NewL1Cache(config *L1CacheConfig) *L1Cache {
	if config == nil {
		config = &L1CacheConfig{
			MaxSize:           1000,
			DefaultTTL:        time.Minute * 5,
			CleanupInterval:   time.Minute * 1,
			PreWarmSize:       100,
			EnableMetrics:     true,
			MaxMemoryMB:       64,
			EvictionPolicy:    "lru",
			EnableCompression: false,
		}
	}

	cache := &L1Cache{
		storage:     make(map[string]*CacheEntry, config.MaxSize),
		lruList:     NewLRUList(int64(config.MaxSize)),
		config:      config,
		metrics:     &L1CacheMetrics{MaxSize: int64(config.MaxSize)},
		stopCleanup: make(chan struct{}),
	}

	return cache
}

// Start 启动L1缓存服务
func (c *L1Cache) Start(ctx context.Context) error {
	// 启动后台清理协程
	if c.config.CleanupInterval > 0 {
		c.cleanupTicker = time.NewTicker(c.config.CleanupInterval)
		go c.backgroundCleanup(ctx)
	}

	return nil
}

// Stop 停止L1缓存服务
func (c *L1Cache) Stop() error {
	c.cleanupOnce.Do(func() {
		if c.cleanupTicker != nil {
			c.cleanupTicker.Stop()
		}
		close(c.stopCleanup)
	})

	c.mu.Lock()
	defer c.mu.Unlock()

	// 正确清理缓存避免内存泄漏
	for key := range c.storage {
		delete(c.storage, key)
	}
	c.lruList = NewLRUList(int64(c.config.MaxSize))
	atomic.StoreInt64(&c.metrics.CurrentSize, 0)

	return nil
}

// Get 获取缓存值
func (c *L1Cache) Get(key string) (*PermissionResult, bool) {
	startTime := time.Now()

	atomic.AddInt64(&c.metrics.TotalRequests, 1)

	c.mu.RLock()
	entry, exists := c.storage[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddInt64(&c.metrics.MissCount, 1)
		c.updateAccessTime(startTime)
		return nil, false
	}

	// 检查是否过期
	now := time.Now()
	if now.After(entry.ExpireTime) {
		c.mu.Lock()
		delete(c.storage, key)
		c.lruList.Remove(entry)
		c.mu.Unlock()

		atomic.AddInt64(&c.metrics.MissCount, 1)
		c.updateAccessTime(startTime)
		return nil, false
	}

	// 更新访问信息（确保所有访问都在锁保护下）
	c.mu.Lock()
	entry.AccessTime = now
	entry.AccessCount++ // 改用非原子操作，因为已经在锁保护下
	c.lruList.MoveToFront(entry)
	c.mu.Unlock()

	atomic.AddInt64(&c.metrics.HitCount, 1)
	c.updateAccessTime(startTime)

	// 返回值的深拷贝以避免并发修改
	return c.copyPermissionResult(entry.Value), true
}

// Set 设置缓存值
func (c *L1Cache) Set(key string, value *PermissionResult, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	now := time.Now()
	expireTime := now.Add(ttl)

	// 创建新条目
	entry := &CacheEntry{
		Key:         key,
		Value:       c.copyPermissionResult(value),
		ExpireTime:  expireTime,
		AccessTime:  now,
		CreateTime:  now,
		AccessCount: 1,
		Size:        c.calculateEntrySize(key, value),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查是否已存在
	if oldEntry, exists := c.storage[key]; exists {
		// 更新现有条目
		c.lruList.Remove(oldEntry)
		atomic.AddInt64(&c.metrics.CurrentSize, -oldEntry.Size)
	}

	// 检查容量限制
	for c.lruList.Size() >= c.lruList.MaxSize() || c.needEviction() {
		if err := c.evictLRU(); err != nil {
			return err
		}
	}

	// 添加新条目
	c.storage[key] = entry
	c.lruList.AddToFront(entry)
	atomic.AddInt64(&c.metrics.CurrentSize, entry.Size)

	return nil
}

// Delete 删除缓存值
func (c *L1Cache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.storage[key]; exists {
		delete(c.storage, key)
		c.lruList.Remove(entry)
		atomic.AddInt64(&c.metrics.CurrentSize, -entry.Size)
		return true
	}

	return false
}

// Clear 清空缓存
func (c *L1Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 正确清理现有条目以避免内存泄漏
	for key := range c.storage {
		delete(c.storage, key)
	}
	c.lruList = NewLRUList(int64(c.config.MaxSize))
	atomic.StoreInt64(&c.metrics.CurrentSize, 0)
}

// GetMetrics 获取缓存指标
func (c *L1Cache) GetMetrics() *L1CacheMetrics {
	metrics := &L1CacheMetrics{
		TotalRequests:   atomic.LoadInt64(&c.metrics.TotalRequests),
		HitCount:        atomic.LoadInt64(&c.metrics.HitCount),
		MissCount:       atomic.LoadInt64(&c.metrics.MissCount),
		EvictionCount:   atomic.LoadInt64(&c.metrics.EvictionCount),
		CurrentSize:     atomic.LoadInt64(&c.metrics.CurrentSize),
		MaxSize:         c.metrics.MaxSize,
		LastAccessTime:  c.metrics.LastAccessTime,
		LastEvictTime:   c.metrics.LastEvictTime,
		LastCleanupTime: c.metrics.LastCleanupTime,
	}

	// 计算命中率
	totalRequests := metrics.TotalRequests
	if totalRequests > 0 {
		metrics.HitRate = float64(metrics.HitCount) / float64(totalRequests)
	}

	// 计算内存使用
	metrics.MemoryUsageMB = float64(metrics.CurrentSize) / 1024 / 1024

	return metrics
}

// PreWarm 预热缓存
func (c *L1Cache) PreWarm(keys []string, loader func(string) (*PermissionResult, error)) error {
	if !atomic.CompareAndSwapInt32(&c.isWarming, 0, 1) {
		return nil // 已经在预热中
	}
	defer atomic.StoreInt32(&c.isWarming, 0)

	c.warmupMutex.Lock()
	defer c.warmupMutex.Unlock()

	maxWarmup := c.config.PreWarmSize
	if len(keys) < maxWarmup {
		maxWarmup = len(keys)
	}

	for i := 0; i < maxWarmup; i++ {
		key := keys[i]

		// 检查是否已经缓存
		if _, exists := c.Get(key); exists {
			continue
		}

		// 加载数据
		if value, err := loader(key); err == nil {
			c.Set(key, value, c.config.DefaultTTL)
		}
	}

	return nil
}

// backgroundCleanup 后台清理过期条目
func (c *L1Cache) backgroundCleanup(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCleanup:
			return
		case <-c.cleanupTicker.C:
			c.cleanup()
			c.metrics.LastCleanupTime = time.Now()
		}
	}
}

// cleanup 清理过期条目
func (c *L1Cache) cleanup() {
	now := time.Now()
	expiredKeys := make([]string, 0, 100)

	c.mu.RLock()
	for key, entry := range c.storage {
		if now.After(entry.ExpireTime) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	c.mu.RUnlock()

	if len(expiredKeys) > 0 {
		c.mu.Lock()
		for _, key := range expiredKeys {
			if entry, exists := c.storage[key]; exists {
				delete(c.storage, key)
				c.lruList.Remove(entry)
				atomic.AddInt64(&c.metrics.CurrentSize, -entry.Size)
			}
		}
		c.mu.Unlock()
	}
}

// evictLRU 淘汰LRU条目
func (c *L1Cache) evictLRU() error {
	tail := c.lruList.Tail()
	if tail == nil {
		return nil
	}

	delete(c.storage, tail.Key)
	c.lruList.Remove(tail)
	atomic.AddInt64(&c.metrics.CurrentSize, -tail.Size)
	atomic.AddInt64(&c.metrics.EvictionCount, 1)
	c.metrics.LastEvictTime = time.Now()

	return nil
}

// needEviction 检查是否需要淘汰
func (c *L1Cache) needEviction() bool {
	if c.config.MaxMemoryMB <= 0 {
		return false
	}

	currentMB := float64(atomic.LoadInt64(&c.metrics.CurrentSize)) / 1024 / 1024
	return currentMB > float64(c.config.MaxMemoryMB)
}

// calculateEntrySize 计算条目大小
func (c *L1Cache) calculateEntrySize(key string, value *PermissionResult) int64 {
	size := int64(len(key))
	if value != nil {
		size += int64(len(value.DataScope) + len(value.SubDept) +
			len(value.CustomDept) + len(value.Level) +
			len(value.Source) + len(value.ErrorMessage))
		size += 64 // 估算其他字段大小
	}
	return size
}

// copyPermissionResult 深拷贝权限结果
func (c *L1Cache) copyPermissionResult(original *PermissionResult) *PermissionResult {
	if original == nil {
		return nil
	}

	return &PermissionResult{
		DataScope:     original.DataScope,
		SubDept:       original.SubDept,
		CustomDept:    original.CustomDept,
		Level:         original.Level,
		Source:        original.Source,
		ExecutionTime: original.ExecutionTime,
		CacheHit:      original.CacheHit,
		FallbackUsed:  original.FallbackUsed,
		ErrorMessage:  original.ErrorMessage,
	}
}

// updateAccessTime 更新访问时间指标
func (c *L1Cache) updateAccessTime(startTime time.Time) {
	duration := time.Since(startTime)

	// 安全地更新平均访问时间（使用互斥锁）
	c.mu.Lock()
	currentAvg := c.metrics.AvgAccessTime
	newAvg := time.Duration((int64(currentAvg) + int64(duration)) / 2)
	c.metrics.AvgAccessTime = newAvg
	c.metrics.LastAccessTime = time.Now()
	c.mu.Unlock()
}

// NewLRUList 创建LRU链表
func NewLRUList(maxSize int64) *LRUList {
	head := &CacheEntry{}
	tail := &CacheEntry{}

	head.next = tail
	tail.prev = head

	return &LRUList{
		head:    head,
		tail:    tail,
		size:    0,
		maxSize: maxSize,
	}
}

// AddToFront 添加到链表头部
func (l *LRUList) AddToFront(entry *CacheEntry) {
	entry.prev = l.head
	entry.next = l.head.next
	l.head.next.prev = entry
	l.head.next = entry
	l.size++
}

// Remove 移除节点
func (l *LRUList) Remove(entry *CacheEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	}
	entry.prev = nil
	entry.next = nil
	l.size--
}

// MoveToFront 移动到头部
func (l *LRUList) MoveToFront(entry *CacheEntry) {
	l.Remove(entry)
	l.AddToFront(entry)
}

// Tail 获取尾部节点
func (l *LRUList) Tail() *CacheEntry {
	if l.tail.prev == l.head {
		return nil
	}
	return l.tail.prev
}

// Size 获取链表大小
func (l *LRUList) Size() int64 {
	return l.size
}

// MaxSize 获取最大大小
func (l *LRUList) MaxSize() int64 {
	return l.maxSize
}

// KeyTTLInfo TTL信息结构
type KeyTTLInfo struct {
	Key          string        `json:"key"`
	RemainingTTL time.Duration `json:"remaining_ttl"`
	OriginalTTL  time.Duration `json:"original_ttl"`
	ExpireTime   time.Time     `json:"expire_time"`
}

// GetKeyTTLInfo 获取键的TTL信息
func (c *L1Cache) GetKeyTTLInfo(key string) *KeyTTLInfo {
	c.mu.RLock()
	entry, exists := c.storage[key]
	c.mu.RUnlock()

	if !exists {
		return nil
	}

	now := time.Now()
	if now.After(entry.ExpireTime) {
		return nil // 已过期
	}

	remainingTTL := entry.ExpireTime.Sub(now)
	originalTTL := entry.ExpireTime.Sub(entry.CreateTime)

	return &KeyTTLInfo{
		Key:          key,
		RemainingTTL: remainingTTL,
		OriginalTTL:  originalTTL,
		ExpireTime:   entry.ExpireTime,
	}
}

// GetKeysForRefresh 获取需要刷新的键列表
func (c *L1Cache) GetKeysForRefresh(threshold float64) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var keysToRefresh []string
	now := time.Now()

	for key, entry := range c.storage {
		// 跳过已过期的条目
		if now.After(entry.ExpireTime) {
			continue
		}

		// 计算剩余TTL比例
		remainingTTL := entry.ExpireTime.Sub(now)
		originalTTL := entry.ExpireTime.Sub(entry.CreateTime)

		if originalTTL > 0 {
			remainingRatio := float64(remainingTTL) / float64(originalTTL)
			if remainingRatio < threshold {
				keysToRefresh = append(keysToRefresh, key)
			}
		}
	}

	return keysToRefresh
}
