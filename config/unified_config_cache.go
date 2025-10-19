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

package config

import (
	"sync"
	"time"
)

// CacheItem 缓存项
type CacheItem struct {
	Value     interface{}
	ExpiresAt time.Time
}

// IsExpired 检查是否过期
func (item *CacheItem) IsExpired() bool {
	// Zero time means no expiration
	if item.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(item.ExpiresAt)
}

// MemoryUnifiedConfigCache 内存配置缓存实现
type MemoryUnifiedConfigCache struct {
	items map[string]*CacheItem
	mu    sync.RWMutex

	// 清理配置
	cleanupInterval time.Duration
	stopCleanup     chan bool
}

// NewMemoryUnifiedConfigCache 创建内存配置缓存
func NewMemoryUnifiedConfigCache(options ...UnifiedCacheOption) *MemoryUnifiedConfigCache {
	cache := &MemoryUnifiedConfigCache{
		items:           make(map[string]*CacheItem),
		cleanupInterval: 10 * time.Minute,
		stopCleanup:     make(chan bool),
	}

	for _, opt := range options {
		opt(cache)
	}

	// 启动清理协程
	cache.startCleanup()

	return cache
}

// UnifiedCacheOption 缓存选项
type UnifiedCacheOption func(*MemoryUnifiedConfigCache)

// WithCleanupInterval 设置清理间隔
func WithCleanupInterval(interval time.Duration) UnifiedCacheOption {
	return func(cache *MemoryUnifiedConfigCache) {
		cache.cleanupInterval = interval
	}
}

// Get 获取缓存值
func (mc *MemoryUnifiedConfigCache) Get(key string) (interface{}, bool) {
	mc.mu.RLock()
	item, exists := mc.items[key]
	if !exists {
		mc.mu.RUnlock()
		return nil, false
	}

	if item.IsExpired() {
		mc.mu.RUnlock()
		// 需要写锁来删除过期项
		mc.mu.Lock()
		// 重新检查，防止在锁切换期间被其他goroutine处理
		if item, exists := mc.items[key]; exists && item.IsExpired() {
			delete(mc.items, key)
		}
		mc.mu.Unlock()
		return nil, false
	}

	value := item.Value
	mc.mu.RUnlock()
	return value, true
}

// Set 设置缓存值
func (mc *MemoryUnifiedConfigCache) Set(key string, value interface{}, ttl time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	} else {
		// TTL of 0 means no expiration (permanent)
		expiresAt = time.Time{}
	}

	mc.items[key] = &CacheItem{
		Value:     value,
		ExpiresAt: expiresAt,
	}
}

// Delete 删除缓存值
func (mc *MemoryUnifiedConfigCache) Delete(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	delete(mc.items, key)
}

// Clear 清空缓存
func (mc *MemoryUnifiedConfigCache) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.items = make(map[string]*CacheItem)
}

// Size 获取缓存大小
func (mc *MemoryUnifiedConfigCache) Size() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return len(mc.items)
}

// startCleanup 启动清理协程
func (mc *MemoryUnifiedConfigCache) startCleanup() {
	go func() {
		ticker := time.NewTicker(mc.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				mc.cleanup()
			case <-mc.stopCleanup:
				return
			}
		}
	}()
}

// cleanup 清理过期缓存
func (mc *MemoryUnifiedConfigCache) cleanup() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	for key, item := range mc.items {
		if now.After(item.ExpiresAt) {
			delete(mc.items, key)
		}
	}
}

// Stop 停止清理协程
func (mc *MemoryUnifiedConfigCache) Stop() {
	close(mc.stopCleanup)
}

// LRUUnifiedConfigCache LRU 配置缓存实现
type LRUUnifiedConfigCache struct {
	maxSize int
	items   map[string]*LRUCacheItem
	head    *LRUCacheItem
	tail    *LRUCacheItem
	mu      sync.RWMutex
}

// LRUCacheItem LRU 缓存项
type LRUCacheItem struct {
	Key       string
	Value     interface{}
	ExpiresAt time.Time
	Prev      *LRUCacheItem
	Next      *LRUCacheItem
}

// IsExpired 检查是否过期
func (item *LRUCacheItem) IsExpired() bool {
	return time.Now().After(item.ExpiresAt)
}

// NewLRUUnifiedConfigCache 创建 LRU 配置缓存
func NewLRUUnifiedConfigCache(maxSize int) *LRUUnifiedConfigCache {
	cache := &LRUUnifiedConfigCache{
		maxSize: maxSize,
		items:   make(map[string]*LRUCacheItem),
	}

	// 创建哨兵节点
	cache.head = &LRUCacheItem{}
	cache.tail = &LRUCacheItem{}
	cache.head.Next = cache.tail
	cache.tail.Prev = cache.head

	return cache
}

// Get 获取缓存值
func (lru *LRUUnifiedConfigCache) Get(key string) (interface{}, bool) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	item, exists := lru.items[key]
	if !exists {
		return nil, false
	}

	if item.IsExpired() {
		lru.removeItem(item)
		delete(lru.items, key)
		return nil, false
	}

	// 移动到头部
	lru.moveToHead(item)

	return item.Value, true
}

// Set 设置缓存值
func (lru *LRUUnifiedConfigCache) Set(key string, value interface{}, ttl time.Duration) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	if item, exists := lru.items[key]; exists {
		// 更新现有项
		item.Value = value
		item.ExpiresAt = time.Now().Add(ttl)
		lru.moveToHead(item)
		return
	}

	// 创建新项
	newItem := &LRUCacheItem{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}

	lru.items[key] = newItem
	lru.addToHead(newItem)

	// 检查容量限制
	if len(lru.items) > lru.maxSize {
		// 移除尾部项
		tail := lru.removeTail()
		delete(lru.items, tail.Key)
	}
}

// Delete 删除缓存值
func (lru *LRUUnifiedConfigCache) Delete(key string) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	if item, exists := lru.items[key]; exists {
		lru.removeItem(item)
		delete(lru.items, key)
	}
}

// Clear 清空缓存
func (lru *LRUUnifiedConfigCache) Clear() {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	lru.items = make(map[string]*LRUCacheItem)
	lru.head.Next = lru.tail
	lru.tail.Prev = lru.head
}

// addToHead 添加到头部
func (lru *LRUUnifiedConfigCache) addToHead(item *LRUCacheItem) {
	item.Prev = lru.head
	item.Next = lru.head.Next

	lru.head.Next.Prev = item
	lru.head.Next = item
}

// removeItem 移除项
func (lru *LRUUnifiedConfigCache) removeItem(item *LRUCacheItem) {
	item.Prev.Next = item.Next
	item.Next.Prev = item.Prev
}

// moveToHead 移动到头部
func (lru *LRUUnifiedConfigCache) moveToHead(item *LRUCacheItem) {
	lru.removeItem(item)
	lru.addToHead(item)
}

// removeTail 移除尾部
func (lru *LRUUnifiedConfigCache) removeTail() *LRUCacheItem {
	last := lru.tail.Prev
	lru.removeItem(last)
	return last
}

// NoOpUnifiedConfigCache 无操作配置缓存（用于禁用缓存）
type NoOpUnifiedConfigCache struct{}

// NewNoOpUnifiedConfigCache 创建无操作配置缓存
func NewNoOpUnifiedConfigCache() *NoOpUnifiedConfigCache {
	return &NoOpUnifiedConfigCache{}
}

func (noc *NoOpUnifiedConfigCache) Get(key string) (interface{}, bool) {
	return nil, false
}

func (noc *NoOpUnifiedConfigCache) Set(key string, value interface{}, ttl time.Duration) {
	// 什么都不做
}

func (noc *NoOpUnifiedConfigCache) Delete(key string) {
	// 什么都不做
}

func (noc *NoOpUnifiedConfigCache) Clear() {
	// 什么都不做
}
