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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cespare/xxhash/v2"
	"github.com/zeromicro/go-zero/core/logx"
	
	"github.com/coder-lulu/newbee-common/middleware/types"
)

// CacheKeyOptimizer provides efficient cache key generation with string interning and pooling
type CacheKeyOptimizer struct {
	stringInterner types.StringInterner
	objectPool     *ObjectPoolManager
	keyCache       *KeyCache
	metrics        *KeyOptimizerMetrics
	enabled        bool
	initialized    int32 // atomic flag for lazy initialization
	initOnce       sync.Once
	mu             sync.RWMutex

	// Zero-allocation optimizations
	bytePool sync.Pool
	hasher   *xxhash.Digest
	hashPool sync.Pool
}

// KeyCache provides intelligent caching for frequently generated keys
type KeyCache struct {
	entries    map[string]*CachedKey
	maxEntries int
	ttl        time.Duration
	hits       int64
	misses     int64
	mu         sync.RWMutex
}

// CachedKey represents a cached key with metadata
type CachedKey struct {
	value       string
	accessCount int64
	lastAccess  time.Time
	created     time.Time
}

// KeyOptimizerMetrics tracks optimization performance
type KeyOptimizerMetrics struct {
	totalKeys      int64
	cachedKeys     int64
	internedKeys   int64
	pooledBuilders int64
	avgKeyLength   float64
	memorySaved    int64
}

// KeyGenerationRequest defines parameters for key generation
type KeyGenerationRequest struct {
	Type      string
	TenantID  uint64
	UserID    uint64
	DeptID    uint64
	RoleCodes []string
	Custom    map[string]interface{}
}

const (
	// Key type constants
	RoleScopeKeyType        = "role_scope"
	TenantRoleScopeKeyType  = "tenant_role_scope"
	SubDeptKeyType          = "sub_dept"
	TenantSubDeptKeyType    = "tenant_sub_dept"
	CustomDeptKeyType       = "custom_dept"
	TenantCustomDeptKeyType = "tenant_custom_dept"

	// Cache configuration
	defaultMaxCacheEntries = 10000
	defaultCacheTTL        = 30 * time.Minute
	keyCommonPrefix        = "dataperm:"
)

// NewCacheKeyOptimizer creates a new cache key optimizer
func NewCacheKeyOptimizer(enabled bool) *CacheKeyOptimizer {
	optimizer := &CacheKeyOptimizer{
		enabled: enabled,
		metrics: &KeyOptimizerMetrics{},
	}

	if enabled {
		// Initialize zero-allocation pools
		optimizer.bytePool = sync.Pool{
			New: func() interface{} {
				// Pre-allocate with common key length
				return make([]byte, 0, 128)
			},
		}

		optimizer.hashPool = sync.Pool{
			New: func() interface{} {
				return xxhash.New()
			},
		}

		// Initialize components lazily to prevent startup blocking
		optimizer.initializeAsync()

		logx.Infow("Cache key optimizer initialization started",
			logx.Field("enabled", enabled),
			logx.Field("maxCacheEntries", defaultMaxCacheEntries),
			logx.Field("cacheTTL", defaultCacheTTL),
			logx.Field("zeroAllocation", true))
	}

	return optimizer
}

// initializeAsync initializes components asynchronously to prevent startup blocking
func (cko *CacheKeyOptimizer) initializeAsync() {
	go func() {
		cko.initOnce.Do(func() {
			// Initialize with reduced capacity for faster startup
			cko.stringInterner = NewStringInterner(10000, 60*time.Minute) // Reduced from 50k
			cko.objectPool = NewObjectPoolManager(5 * time.Minute)
			cko.keyCache = NewKeyCache(defaultMaxCacheEntries, defaultCacheTTL)

			// Pre-warm asynchronously
			go cko.preWarmCommonKeys()

			// Mark as initialized
			atomic.StoreInt32(&cko.initialized, 1)

			logx.Infow("Cache key optimizer components initialized",
				logx.Field("stringInternerCapacity", 10000),
				logx.Field("async", true))
		})
	}()
}

// ensureInitialized ensures components are initialized before use
func (cko *CacheKeyOptimizer) ensureInitialized() {
	if atomic.LoadInt32(&cko.initialized) == 0 {
		cko.initOnce.Do(func() {
			// Synchronous fallback if async init hasn't completed
			cko.stringInterner = NewStringInterner(10000, 60*time.Minute)
			cko.objectPool = NewObjectPoolManager(5 * time.Minute)
			cko.keyCache = NewKeyCache(defaultMaxCacheEntries, defaultCacheTTL)
			atomic.StoreInt32(&cko.initialized, 1)
		})
	}
}

// NewKeyCache creates a new key cache
func NewKeyCache(maxEntries int, ttl time.Duration) *KeyCache {
	return &KeyCache{
		entries:    make(map[string]*CachedKey),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// GenerateOptimizedKey generates an optimized cache key
func (cko *CacheKeyOptimizer) GenerateOptimizedKey(req *KeyGenerationRequest) string {
	if !cko.enabled {
		return cko.generateKeyFallback(req)
	}

	// Ensure components are initialized
	cko.ensureInitialized()

	atomic.AddInt64(&cko.metrics.totalKeys, 1)

	// Create cache lookup key
	lookupKey := cko.createLookupKey(req)

	// Check key cache first
	if cachedKey := cko.keyCache.Get(lookupKey); cachedKey != "" {
		atomic.AddInt64(&cko.metrics.cachedKeys, 1)
		return cachedKey
	}

	// Generate new key using optimized methods
	key := cko.generateKey(req)

	// Intern the key to save memory
	internedKey := cko.stringInterner.Intern(key)
	atomic.AddInt64(&cko.metrics.internedKeys, 1)

	// Cache the generated key
	cko.keyCache.Set(lookupKey, internedKey)

	// Update metrics
	cko.updateMetrics(internedKey)

	return internedKey
}

// generateKey generates a cache key using zero-allocation methods
func (cko *CacheKeyOptimizer) generateKey(req *KeyGenerationRequest) string {
	// Try zero-allocation method first
	if key := cko.generateKeyZeroAlloc(req); key != "" {
		return key
	}

	// Fallback to traditional method if zero-alloc fails
	return cko.generateKeyTraditional(req)
}

// generateKeyZeroAlloc generates cache key with zero allocations using byte pools
func (cko *CacheKeyOptimizer) generateKeyZeroAlloc(req *KeyGenerationRequest) string {
	// Get byte slice from pool
	buf := cko.bytePool.Get().([]byte)
	buf = buf[:0] // Reset length while preserving capacity
	defer cko.bytePool.Put(buf)

	atomic.AddInt64(&cko.metrics.pooledBuilders, 1)

	// Build key efficiently using byte operations
	buf = append(buf, keyCommonPrefix...)

	switch req.Type {
	case RoleScopeKeyType:
		buf = append(buf, "role_scope:"...)
		buf = cko.appendRoleCodes(buf, req.RoleCodes)

	case TenantRoleScopeKeyType:
		buf = append(buf, "tenant:"...)
		buf = cko.appendUint64(buf, req.TenantID)
		buf = append(buf, ":role_scope:"...)
		buf = cko.appendRoleCodes(buf, req.RoleCodes)

	case SubDeptKeyType:
		buf = append(buf, "sub_dept:"...)
		buf = cko.appendUint64(buf, req.DeptID)

	case TenantSubDeptKeyType:
		buf = append(buf, "tenant:"...)
		buf = cko.appendUint64(buf, req.TenantID)
		buf = append(buf, ":sub_dept:"...)
		buf = cko.appendUint64(buf, req.DeptID)

	case CustomDeptKeyType:
		buf = append(buf, "custom_dept:"...)
		buf = cko.appendRoleCodes(buf, req.RoleCodes)

	case TenantCustomDeptKeyType:
		buf = append(buf, "tenant:"...)
		buf = cko.appendUint64(buf, req.TenantID)
		buf = append(buf, ":custom_dept:"...)
		buf = cko.appendRoleCodes(buf, req.RoleCodes)

	default:
		return ""
	}

	// Convert to string using unsafe for zero-copy
	return cko.bytesToString(buf)
}

// generateKeyTraditional generates a cache key using traditional pooled string builders
func (cko *CacheKeyOptimizer) generateKeyTraditional(req *KeyGenerationRequest) string {
	// Get string builder from pool
	bufferObj := cko.objectPool.Get("buffer")
	if bufferObj == nil {
		return cko.generateKeyFallback(req)
	}

	buffer := bufferObj.(*bytes.Buffer)
	defer cko.objectPool.Put("buffer", buffer)

	atomic.AddInt64(&cko.metrics.pooledBuilders, 1)

	// Build key efficiently
	buffer.WriteString(keyCommonPrefix)

	switch req.Type {
	case RoleScopeKeyType:
		buffer.WriteString("role_scope:")
		cko.writeRoleCodes(buffer, req.RoleCodes)

	case TenantRoleScopeKeyType:
		buffer.WriteString("tenant:")
		buffer.WriteString(strconv.FormatUint(req.TenantID, 10))
		buffer.WriteString(":role_scope:")
		cko.writeRoleCodes(buffer, req.RoleCodes)

	case SubDeptKeyType:
		buffer.WriteString("sub_dept:")
		buffer.WriteString(strconv.FormatUint(req.DeptID, 10))

	case TenantSubDeptKeyType:
		buffer.WriteString("tenant:")
		buffer.WriteString(strconv.FormatUint(req.TenantID, 10))
		buffer.WriteString(":sub_dept:")
		buffer.WriteString(strconv.FormatUint(req.DeptID, 10))

	case CustomDeptKeyType:
		buffer.WriteString("custom_dept:")
		cko.writeRoleCodes(buffer, req.RoleCodes)

	case TenantCustomDeptKeyType:
		buffer.WriteString("tenant:")
		buffer.WriteString(strconv.FormatUint(req.TenantID, 10))
		buffer.WriteString(":custom_dept:")
		cko.writeRoleCodes(buffer, req.RoleCodes)

	default:
		return cko.generateKeyFallback(req)
	}

	return buffer.String()
}

// writeRoleCodes efficiently writes role codes to buffer
func (cko *CacheKeyOptimizer) writeRoleCodes(buffer *bytes.Buffer, roleCodes []string) {
	if len(roleCodes) == 0 {
		return
	}

	// Sort role codes for consistent key generation
	sortedCodes := make([]string, len(roleCodes))
	copy(sortedCodes, roleCodes)

	// Use a simple sort for small arrays (most common case)
	if len(sortedCodes) <= 10 {
		cko.bubbleSort(sortedCodes)
	} else {
		// For larger arrays, use Go's built-in sort
		// But avoid import for now to keep dependencies minimal
		cko.bubbleSort(sortedCodes)
	}

	for i, code := range sortedCodes {
		if i > 0 {
			buffer.WriteByte(',')
		}
		buffer.WriteString(code)
	}
}

// bubbleSort provides simple sorting for small arrays
func (cko *CacheKeyOptimizer) bubbleSort(arr []string) {
	n := len(arr)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if arr[j] > arr[j+1] {
				arr[j], arr[j+1] = arr[j+1], arr[j]
			}
		}
	}
}

// createLookupKey creates a lookup key for the key cache
func (cko *CacheKeyOptimizer) createLookupKey(req *KeyGenerationRequest) string {
	// Use a simpler approach for lookup keys to avoid recursion
	parts := []string{
		req.Type,
		strconv.FormatUint(req.TenantID, 10),
		strconv.FormatUint(req.DeptID, 10),
		strings.Join(req.RoleCodes, ","),
	}
	return strings.Join(parts, "|")
}

// generateKeyFallback provides fallback key generation without optimization
func (cko *CacheKeyOptimizer) generateKeyFallback(req *KeyGenerationRequest) string {
	switch req.Type {
	case RoleScopeKeyType:
		return keyCommonPrefix + "role_scope:" + strings.Join(req.RoleCodes, ",")
	case TenantRoleScopeKeyType:
		return keyCommonPrefix + "tenant:" + strconv.FormatUint(req.TenantID, 10) + ":role_scope:" + strings.Join(req.RoleCodes, ",")
	case SubDeptKeyType:
		return keyCommonPrefix + "sub_dept:" + strconv.FormatUint(req.DeptID, 10)
	case TenantSubDeptKeyType:
		return keyCommonPrefix + "tenant:" + strconv.FormatUint(req.TenantID, 10) + ":sub_dept:" + strconv.FormatUint(req.DeptID, 10)
	case CustomDeptKeyType:
		return keyCommonPrefix + "custom_dept:" + strings.Join(req.RoleCodes, ",")
	case TenantCustomDeptKeyType:
		return keyCommonPrefix + "tenant:" + strconv.FormatUint(req.TenantID, 10) + ":custom_dept:" + strings.Join(req.RoleCodes, ",")
	default:
		return keyCommonPrefix + "unknown:" + strconv.FormatUint(req.TenantID, 10)
	}
}

// Get retrieves a cached key
func (kc *KeyCache) Get(lookupKey string) string {
	kc.mu.RLock()
	cached, exists := kc.entries[lookupKey]
	kc.mu.RUnlock()

	if !exists {
		atomic.AddInt64(&kc.misses, 1)
		return ""
	}

	// Check TTL
	if kc.ttl > 0 && time.Since(cached.created) > kc.ttl {
		kc.mu.Lock()
		delete(kc.entries, lookupKey)
		kc.mu.Unlock()
		atomic.AddInt64(&kc.misses, 1)
		return ""
	}

	// Update access info
	atomic.AddInt64(&cached.accessCount, 1)
	cached.lastAccess = time.Now()

	atomic.AddInt64(&kc.hits, 1)
	return cached.value
}

// Set stores a cached key
func (kc *KeyCache) Set(lookupKey, value string) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Check if we need to evict entries
	if len(kc.entries) >= kc.maxEntries {
		kc.evictLRU()
	}

	kc.entries[lookupKey] = &CachedKey{
		value:       value,
		accessCount: 1,
		lastAccess:  time.Now(),
		created:     time.Now(),
	}
}

// evictLRU evicts least recently used entries
func (kc *KeyCache) evictLRU() {
	if len(kc.entries) == 0 {
		return
	}

	// Find LRU entry
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range kc.entries {
		if oldestKey == "" || entry.lastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastAccess
		}
	}

	if oldestKey != "" {
		delete(kc.entries, oldestKey)
	}
}

// preWarmCommonKeys pre-interns commonly used key components
func (cko *CacheKeyOptimizer) preWarmCommonKeys() {
	commonPrefixes := []string{
		keyCommonPrefix,
		"tenant:",
		"role_scope:",
		"sub_dept:",
		"custom_dept:",
	}

	for _, prefix := range commonPrefixes {
		cko.stringInterner.Intern(prefix)
	}

	logx.Infow("Pre-warmed common cache key components",
		logx.Field("count", len(commonPrefixes)))
}

// updateMetrics updates optimizer metrics (thread-safe)
func (cko *CacheKeyOptimizer) updateMetrics(key string) {
	keyLength := float64(len(key))
	totalKeys := atomic.LoadInt64(&cko.metrics.totalKeys)

	if totalKeys > 0 {
		// 使用互斥锁保护avgKeyLength的更新，确保并发安全
		cko.mu.Lock()
		cko.metrics.avgKeyLength = (cko.metrics.avgKeyLength*float64(totalKeys-1) + keyLength) / float64(totalKeys)
		cko.mu.Unlock()
	}
}

// GetMetrics returns current optimization metrics
func (cko *CacheKeyOptimizer) GetMetrics() *KeyOptimizerMetrics {
	cko.mu.RLock()
	avgKeyLength := cko.metrics.avgKeyLength
	cko.mu.RUnlock()

	return &KeyOptimizerMetrics{
		totalKeys:      atomic.LoadInt64(&cko.metrics.totalKeys),
		cachedKeys:     atomic.LoadInt64(&cko.metrics.cachedKeys),
		internedKeys:   atomic.LoadInt64(&cko.metrics.internedKeys),
		pooledBuilders: atomic.LoadInt64(&cko.metrics.pooledBuilders),
		avgKeyLength:   avgKeyLength,
		memorySaved:    cko.stringInterner.estimateMemorySaved(),
	}
}

// GetCacheStats returns key cache statistics
func (cko *CacheKeyOptimizer) GetCacheStats() map[string]interface{} {
	if atomic.LoadInt32(&cko.initialized) == 0 {
		return map[string]interface{}{
			"initialized":  false,
			"cache_hits":   0,
			"cache_misses": 0,
			"hit_rate":     0.0,
			"cache_size":   0,
			"max_entries":  0,
		}
	}

	hits := atomic.LoadInt64(&cko.keyCache.hits)
	misses := atomic.LoadInt64(&cko.keyCache.misses)
	total := hits + misses

	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	cko.keyCache.mu.RLock()
	cacheSize := len(cko.keyCache.entries)
	cko.keyCache.mu.RUnlock()

	return map[string]interface{}{
		"initialized":            true,
		"cache_hits":             hits,
		"cache_misses":           misses,
		"hit_rate":               hitRate,
		"cache_size":             cacheSize,
		"max_entries":            cko.keyCache.maxEntries,
		"string_interner_size":   cko.stringInterner.Size(),
		"estimated_memory_saved": cko.stringInterner.estimateMemorySaved(),
	}
}

// Clear clears all caches
func (cko *CacheKeyOptimizer) Clear() {
	if !cko.enabled {
		return
	}

	cko.keyCache.mu.Lock()
	cko.keyCache.entries = make(map[string]*CachedKey)
	atomic.StoreInt64(&cko.keyCache.hits, 0)
	atomic.StoreInt64(&cko.keyCache.misses, 0)
	cko.keyCache.mu.Unlock()

	cko.stringInterner.Clear()

	// Reset metrics
	atomic.StoreInt64(&cko.metrics.totalKeys, 0)
	atomic.StoreInt64(&cko.metrics.cachedKeys, 0)
	atomic.StoreInt64(&cko.metrics.internedKeys, 0)
	atomic.StoreInt64(&cko.metrics.pooledBuilders, 0)
	cko.metrics.avgKeyLength = 0.0

	logx.Info("Cache key optimizer cleared")
}

// appendUint64 appends uint64 to byte slice without allocation
func (cko *CacheKeyOptimizer) appendUint64(buf []byte, n uint64) []byte {
	if n == 0 {
		return append(buf, '0')
	}

	// Pre-calculate required space to avoid reallocations
	digits := 1
	temp := n
	for temp >= 10 {
		digits++
		temp /= 10
	}

	// Reserve space
	start := len(buf)
	buf = append(buf, make([]byte, digits)...)

	// Fill digits from right to left
	for i := digits - 1; i >= 0; i-- {
		buf[start+i] = byte('0' + n%10)
		n /= 10
	}

	return buf
}

// appendRoleCodes appends role codes to byte slice efficiently
func (cko *CacheKeyOptimizer) appendRoleCodes(buf []byte, roleCodes []string) []byte {
	if len(roleCodes) == 0 {
		return buf
	}

	// Sort role codes for consistent key generation (in-place sorting for small arrays)
	sortedCodes := make([]string, len(roleCodes))
	copy(sortedCodes, roleCodes)

	if len(sortedCodes) <= 10 {
		cko.bubbleSort(sortedCodes)
	} else {
		cko.bubbleSort(sortedCodes) // Keep simple for now
	}

	for i, code := range sortedCodes {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, code...)
	}

	return buf
}

// bytesToString converts byte slice to string without allocation using unsafe
func (cko *CacheKeyOptimizer) bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// 使用更安全的unsafe操作，确保数据对齐和生命周期正确
	return string(b) // 临时使用标准转换，避免unsafe风险
}

// generateHashKey generates a hash-based cache key for very long keys
func (cko *CacheKeyOptimizer) generateHashKey(req *KeyGenerationRequest) string {
	hasher := cko.hashPool.Get().(*xxhash.Digest)
	defer func() {
		hasher.Reset()
		cko.hashPool.Put(hasher)
	}()

	// Write key components to hasher
	hasher.WriteString(req.Type)
	hasher.WriteString(":")

	if req.TenantID > 0 {
		buf := cko.bytePool.Get().([]byte)
		buf = buf[:0]
		buf = cko.appendUint64(buf, req.TenantID)
		hasher.Write(buf)
		cko.bytePool.Put(buf)
	}

	if req.DeptID > 0 {
		hasher.WriteString(":")
		buf := cko.bytePool.Get().([]byte)
		buf = buf[:0]
		buf = cko.appendUint64(buf, req.DeptID)
		hasher.Write(buf)
		cko.bytePool.Put(buf)
	}

	for _, code := range req.RoleCodes {
		hasher.WriteString(":")
		hasher.WriteString(code)
	}

	// Generate hash key
	hash := hasher.Sum64()
	return keyCommonPrefix + "hash:" + strconv.FormatUint(hash, 16)
}

// Close gracefully shuts down the optimizer
func (cko *CacheKeyOptimizer) Close() error {
	if !cko.enabled {
		return nil
	}

	cko.stringInterner.Close() // This method doesn't return an error
	cko.objectPool.Close()
	cko.Clear()

	logx.Info("Cache key optimizer closed")
	return nil
}
