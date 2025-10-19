// Copyright 2024 The NewBee Authors. All Rights Reserved.

package cache

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// ShardedCache 分片缓存 - 减少锁竞争，提升并发性能
type ShardedCache[K comparable, V any] struct {
	shards     []*CacheShard[K, V]
	shardCount uint32
	mask       uint32
}

// CacheShard 缓存分片
type CacheShard[K comparable, V any] struct {
	mutex sync.RWMutex
	data  map[K]*CacheEntry[V]
}

// CacheEntry 缓存条目
type CacheEntry[V any] struct {
	value     V
	expiresAt time.Time
	createdAt time.Time
	hitCount  int64 // 命中次数统计
}

// NewShardedCache 创建分片缓存
func NewShardedCache[K comparable, V any](shardCount int) *ShardedCache[K, V] {
	if shardCount <= 0 || shardCount&(shardCount-1) != 0 {
		// 确保分片数是2的幂，便于位运算优化
		shardCount = 16
	}
	
	shards := make([]*CacheShard[K, V], shardCount)
	for i := range shards {
		shards[i] = &CacheShard[K, V]{
			data: make(map[K]*CacheEntry[V]),
		}
	}
	
	return &ShardedCache[K, V]{
		shards:     shards,
		shardCount: uint32(shardCount),
		mask:       uint32(shardCount - 1),
	}
}

// getShard 获取对应的分片 - 使用位运算提升性能
func (c *ShardedCache[K, V]) getShard(key K) *CacheShard[K, V] {
	h := fnv.New32a()
	
	// 根据key类型选择hash策略
	switch v := any(key).(type) {
	case string:
		h.Write([]byte(v))
	case int:
		h.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	case int64:
		h.Write([]byte{
			byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
			byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
		})
	default:
		// 降级到默认hash
		h.Write([]byte{0})
	}
	
	return c.shards[h.Sum32()&c.mask]
}

// Set 设置缓存值
func (c *ShardedCache[K, V]) Set(key K, value V, ttl time.Duration) {
	shard := c.getShard(key)
	
	shard.mutex.Lock()
	defer shard.mutex.Unlock()
	
	entry := &CacheEntry[V]{
		value:     value,
		expiresAt: time.Now().Add(ttl),
		createdAt: time.Now(),
		hitCount:  0,
	}
	
	shard.data[key] = entry
}

// Get 获取缓存值
func (c *ShardedCache[K, V]) Get(key K) (V, bool) {
	shard := c.getShard(key)
	
	shard.mutex.RLock()
	defer shard.mutex.RUnlock()
	
	entry, exists := shard.data[key]
	if !exists {
		var zero V
		return zero, false
	}
	
	// 检查是否过期
	if time.Now().After(entry.expiresAt) {
		// 注意：这里不能直接删除，因为是读锁
		// 删除操作在后台清理中进行
		var zero V
		return zero, false
	}
	
	// 原子递增命中次数
	atomic.AddInt64(&entry.hitCount, 1)
	return entry.value, true
}

// GetAndExtend 获取缓存值并延长TTL
func (c *ShardedCache[K, V]) GetAndExtend(key K, ttl time.Duration) (V, bool) {
	shard := c.getShard(key)
	
	shard.mutex.Lock()
	defer shard.mutex.Unlock()
	
	entry, exists := shard.data[key]
	if !exists {
		var zero V
		return zero, false
	}
	
	// 检查是否过期
	if time.Now().After(entry.expiresAt) {
		delete(shard.data, key)
		var zero V
		return zero, false
	}
	
	// 延长TTL
	entry.expiresAt = time.Now().Add(ttl)
	atomic.AddInt64(&entry.hitCount, 1)
	
	return entry.value, true
}

// Delete 删除缓存项
func (c *ShardedCache[K, V]) Delete(key K) bool {
	shard := c.getShard(key)
	
	shard.mutex.Lock()
	defer shard.mutex.Unlock()
	
	_, exists := shard.data[key]
	if exists {
		delete(shard.data, key)
	}
	
	return exists
}

// Size 获取缓存大小
func (c *ShardedCache[K, V]) Size() int {
	total := 0
	for _, shard := range c.shards {
		shard.mutex.RLock()
		total += len(shard.data)
		shard.mutex.RUnlock()
	}
	return total
}

// Clear 清空缓存
func (c *ShardedCache[K, V]) Clear() {
	for _, shard := range c.shards {
		shard.mutex.Lock()
		for k := range shard.data {
			delete(shard.data, k)
		}
		shard.mutex.Unlock()
	}
}

// Cleanup 清理过期项
func (c *ShardedCache[K, V]) Cleanup() int {
	now := time.Now()
	cleaned := 0
	
	for _, shard := range c.shards {
		shard.mutex.Lock()
		for k, entry := range shard.data {
			if now.After(entry.expiresAt) {
				delete(shard.data, k)
				cleaned++
			}
		}
		shard.mutex.Unlock()
	}
	
	return cleaned
}

// Stats 获取缓存统计信息
func (c *ShardedCache[K, V]) Stats() CacheStats {
	stats := CacheStats{}
	now := time.Now()
	
	for _, shard := range c.shards {
		shard.mutex.RLock()
		for _, entry := range shard.data {
			stats.TotalEntries++
			stats.TotalHits += entry.hitCount
			
			if now.After(entry.expiresAt) {
				stats.ExpiredEntries++
			} else {
				stats.ActiveEntries++
			}
			
			age := now.Sub(entry.createdAt)
			if age > stats.MaxAge {
				stats.MaxAge = age
			}
		}
		shard.mutex.RUnlock()
	}
	
	if stats.TotalEntries > 0 {
		stats.AvgHitsPerEntry = float64(stats.TotalHits) / float64(stats.TotalEntries)
	}
	
	return stats
}

// CacheStats 缓存统计信息
type CacheStats struct {
	TotalEntries     int64
	ActiveEntries    int64
	ExpiredEntries   int64
	TotalHits        int64
	AvgHitsPerEntry  float64
	MaxAge           time.Duration
}

// StartCleanupWorker 启动后台清理协程
func (c *ShardedCache[K, V]) StartCleanupWorker(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cleaned := c.Cleanup()
			if cleaned > 0 {
				// 这里可以添加日志记录
			}
		case <-stopCh:
			return
		}
	}
}