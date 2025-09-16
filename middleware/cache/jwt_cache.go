// Copyright 2024 The NewBee Authors. All Rights Reserved.

package cache

import (
	"sync/atomic"
	"time"
)

// JWTCacheEntry JWT缓存条目
type JWTCacheEntry struct {
	Claims    map[string]interface{}
	ExpiresAt time.Time
	CreatedAt time.Time
}

// HighPerformanceJWTCache 高性能JWT缓存
type HighPerformanceJWTCache struct {
	cache       *ShardedCache[string, *JWTCacheEntry]
	maxSize     int64
	currentSize int64
	hitCount    int64
	missCount   int64
}

// NewHighPerformanceJWTCache 创建高性能JWT缓存
func NewHighPerformanceJWTCache(maxSize int64, shardCount int) *HighPerformanceJWTCache {
	if maxSize <= 0 {
		maxSize = 10000 // 默认1万个token缓存
	}
	
	return &HighPerformanceJWTCache{
		cache:       NewShardedCache[string, *JWTCacheEntry](shardCount),
		maxSize:     maxSize,
		currentSize: 0,
		hitCount:    0,
		missCount:   0,
	}
}

// Set 设置JWT缓存
func (c *HighPerformanceJWTCache) Set(token string, claims map[string]interface{}, expiresAt time.Time) bool {
	// 检查大小限制
	if atomic.LoadInt64(&c.currentSize) >= c.maxSize {
		// 触发紧急清理，但不阻塞主流程
		go c.emergencyCleanup()
		return false
	}
	
	entry := &JWTCacheEntry{
		Claims:    claims,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	
	// 计算TTL，提前5分钟过期以防止时钟偏差
	ttl := time.Until(expiresAt.Add(-5 * time.Minute))
	if ttl <= 0 {
		return false // token已过期
	}
	
	c.cache.Set(token, entry, ttl)
	atomic.AddInt64(&c.currentSize, 1)
	
	return true
}

// Get 获取JWT缓存
func (c *HighPerformanceJWTCache) Get(token string) (map[string]interface{}, bool) {
	entry, found := c.cache.Get(token)
	
	if found {
		atomic.AddInt64(&c.hitCount, 1)
		
		// 双重检查过期时间（提前5分钟）
		if time.Now().Before(entry.ExpiresAt.Add(-5 * time.Minute)) {
			return entry.Claims, true
		} else {
			// 已过期，异步删除
			go func() {
				c.cache.Delete(token)
				atomic.AddInt64(&c.currentSize, -1)
			}()
		}
	}
	
	atomic.AddInt64(&c.missCount, 1)
	return nil, false
}

// Delete 删除JWT缓存
func (c *HighPerformanceJWTCache) Delete(token string) bool {
	deleted := c.cache.Delete(token)
	if deleted {
		atomic.AddInt64(&c.currentSize, -1)
	}
	return deleted
}

// Size 获取当前缓存大小
func (c *HighPerformanceJWTCache) Size() int64 {
	return atomic.LoadInt64(&c.currentSize)
}

// HitRate 获取缓存命中率
func (c *HighPerformanceJWTCache) HitRate() float64 {
	hits := atomic.LoadInt64(&c.hitCount)
	misses := atomic.LoadInt64(&c.missCount)
	
	total := hits + misses
	if total == 0 {
		return 0
	}
	
	return float64(hits) / float64(total)
}

// Stats 获取详细统计信息
func (c *HighPerformanceJWTCache) Stats() JWTCacheStats {
	baseStats := c.cache.Stats()
	
	return JWTCacheStats{
		CacheStats:   baseStats,
		CurrentSize:  atomic.LoadInt64(&c.currentSize),
		MaxSize:      c.maxSize,
		HitCount:     atomic.LoadInt64(&c.hitCount),
		MissCount:    atomic.LoadInt64(&c.missCount),
		HitRate:      c.HitRate(),
		SizeUtilization: float64(c.currentSize) / float64(c.maxSize),
	}
}

// JWTCacheStats JWT缓存统计信息
type JWTCacheStats struct {
	CacheStats
	CurrentSize     int64
	MaxSize         int64
	HitCount        int64
	MissCount       int64
	HitRate         float64
	SizeUtilization float64 // 大小使用率
}

// Cleanup 清理过期条目
func (c *HighPerformanceJWTCache) Cleanup() int {
	cleaned := c.cache.Cleanup()
	if cleaned > 0 {
		atomic.AddInt64(&c.currentSize, -int64(cleaned))
	}
	return cleaned
}

// emergencyCleanup 紧急清理 - 当缓存满时触发
func (c *HighPerformanceJWTCache) emergencyCleanup() {
	c.Cleanup()
	
	// 如果清理后仍然满，则删除最老的25%条目
	if atomic.LoadInt64(&c.currentSize) >= c.maxSize {
		targetCleanup := c.maxSize / 4
		c.cleanupOldestEntries(int(targetCleanup))
	}
}

// cleanupOldestEntries 清理最老的条目
func (c *HighPerformanceJWTCache) cleanupOldestEntries(count int) int {
	// 这里需要遍历所有分片找到最老的条目
	// 简化实现：随机清理一些条目
	cleaned := 0
	maxCleanup := count
	
	for i := 0; i < len(c.cache.shards) && cleaned < maxCleanup; i++ {
		shard := c.cache.shards[i]
		shard.mutex.Lock()
		
		// 删除一些最老的条目
		deleteCount := 0
		maxDeletePerShard := maxCleanup / len(c.cache.shards)
		
		for k, entry := range shard.data {
			if deleteCount >= maxDeletePerShard {
				break
			}
			
			// 删除创建时间超过30分钟的条目
			if time.Since(entry.createdAt) > 30*time.Minute {
				delete(shard.data, k)
				cleaned++
				deleteCount++
			}
		}
		
		shard.mutex.Unlock()
	}
	
	atomic.AddInt64(&c.currentSize, -int64(cleaned))
	return cleaned
}

// StartCleanupWorker 启动清理工作协程
func (c *HighPerformanceJWTCache) StartCleanupWorker(interval time.Duration, stopCh <-chan struct{}) {
	c.cache.StartCleanupWorker(interval, stopCh)
}

// WarmUp 预热缓存 - 可以预加载一些常用token
func (c *HighPerformanceJWTCache) WarmUp(tokens []string, claimsFunc func(string) (map[string]interface{}, time.Time, error)) {
	for _, token := range tokens {
		if claims, expiresAt, err := claimsFunc(token); err == nil {
			c.Set(token, claims, expiresAt)
		}
	}
}