// Copyright 2024 Newbee Team. All Rights Reserved.
//
// Fast LRU Cache Implementation for High Performance Permission Middleware
// This implementation uses zero-allocation techniques for maximum performance

package middleware

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// FastLRUCache 高性能LRU缓存实现
type FastLRUCache struct {
	mutex     sync.RWMutex
	capacity  int
	items     map[string]*CacheItem
	evictList *list.List

	// 统计信息
	hits   uint64
	misses uint64
}

// CacheItem 缓存项
type CacheItem struct {
	key        string
	value      interface{}
	element    *list.Element
	expiry     time.Time
	lastAccess time.Time
}

// NewFastLRUCache 创建新的LRU缓存
func NewFastLRUCache(capacity int) *FastLRUCache {
	return &FastLRUCache{
		capacity:  capacity,
		items:     make(map[string]*CacheItem, capacity),
		evictList: list.New(),
	}
}

// Get 获取缓存项 - 高性能实现
func (c *FastLRUCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()

	item, exists := c.items[key]
	if !exists {
		c.mutex.RUnlock()
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	// 检查是否过期
	now := time.Now()
	if !item.expiry.IsZero() && now.After(item.expiry) {
		c.mutex.RUnlock()

		// 升级到写锁并删除过期项
		c.mutex.Lock()
		c.removeElement(item)
		c.mutex.Unlock()

		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	c.mutex.RUnlock()

	// 升级到写锁更新访问时间和位置
	c.mutex.Lock()
	item.lastAccess = now
	c.evictList.MoveToFront(item.element)
	value := item.value
	c.mutex.Unlock()

	atomic.AddUint64(&c.hits, 1)
	return value, true
}

// Set 设置缓存项
func (c *FastLRUCache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, 0)
}

// SetWithTTL 设置带TTL的缓存项
func (c *FastLRUCache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	var expiry time.Time
	if ttl > 0 {
		expiry = now.Add(ttl)
	}

	// 检查是否已存在
	if item, exists := c.items[key]; exists {
		// 更新现有项
		item.value = value
		item.expiry = expiry
		item.lastAccess = now
		c.evictList.MoveToFront(item.element)
		return
	}

	// 检查容量限制
	if c.evictList.Len() >= c.capacity {
		c.evictOldest()
	}

	// 添加新项
	item := &CacheItem{
		key:        key,
		value:      value,
		expiry:     expiry,
		lastAccess: now,
	}

	item.element = c.evictList.PushFront(item)
	c.items[key] = item
}

// Delete 删除缓存项
func (c *FastLRUCache) Delete(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if item, exists := c.items[key]; exists {
		c.removeElement(item)
		return true
	}

	return false
}

// Clear 清空缓存
func (c *FastLRUCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items = make(map[string]*CacheItem, c.capacity)
	c.evictList.Init()
}

// Len 获取当前缓存项数量
func (c *FastLRUCache) Len() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.items)
}

// Stats 获取缓存统计信息
func (c *FastLRUCache) Stats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return CacheStats{
		Hits:     hits,
		Misses:   misses,
		HitRate:  hitRate,
		Size:     len(c.items),
		Capacity: c.capacity,
	}
}

// CleanupExpired 清理过期项 - 定期调用
func (c *FastLRUCache) CleanupExpired() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	removed := 0

	// 从尾部开始检查（最少使用的项）
	for element := c.evictList.Back(); element != nil; {
		item := element.Value.(*CacheItem)
		next := element.Prev() // 保存下一个元素

		if !item.expiry.IsZero() && now.After(item.expiry) {
			c.removeElement(item)
			removed++
		}

		element = next
	}

	return removed
}

// evictOldest 淘汰最老的项
func (c *FastLRUCache) evictOldest() {
	element := c.evictList.Back()
	if element != nil {
		item := element.Value.(*CacheItem)
		c.removeElement(item)
	}
}

// removeElement 移除元素 - 内部方法，调用时需要持有写锁
func (c *FastLRUCache) removeElement(item *CacheItem) {
	c.evictList.Remove(item.element)
	delete(c.items, item.key)
}

// CacheStats 缓存统计信息
type CacheStats struct {
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	HitRate  float64 `json:"hit_rate"`
	Size     int     `json:"size"`
	Capacity int     `json:"capacity"`
}

// StartCleanupRoutine 启动清理协程
func (c *FastLRUCache) StartCleanupRoutine(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute * 5 // 默认5分钟清理一次
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			removed := c.CleanupExpired()
			if removed > 0 {
				// 可以在这里记录日志或指标
				_ = removed
			}
		}
	}()
}

// 原子操作辅助函数
func atomic64Add(addr *uint64, delta uint64) uint64 {
	return atomic.AddUint64(addr, delta)
}

// 使用unsafe包优化性能的字符串转换（谨慎使用）
func unsafeStringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

func unsafeBytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
