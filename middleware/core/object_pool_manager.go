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
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// PermissionContext represents a pooled permission context object
type PermissionContext struct {
	UserID     uint64
	TenantID   uint64
	DeptID     uint64
	RoleCodes  []string
	DataScope  string
	SubDept    string
	CustomDept string
	Timestamp  time.Time
}

// Reset clears the permission context for reuse
func (pc *PermissionContext) Reset() {
	pc.UserID = 0
	pc.TenantID = 0
	pc.DeptID = 0
	pc.RoleCodes = pc.RoleCodes[:0] // Reset slice but keep capacity
	pc.DataScope = ""
	pc.SubDept = ""
	pc.CustomDept = ""
	pc.Timestamp = time.Time{}
}

// ObjectPoolManager manages multiple object pools to reduce memory allocations
type ObjectPoolManager struct {
	pools           map[string]*managedPool
	cleanupInterval time.Duration
	cleanupTicker   *time.Ticker
	done            chan struct{}
	mu              sync.RWMutex
}

// managedPool wraps sync.Pool with statistics and cleanup
type managedPool struct {
	pool        *sync.Pool
	newFunc     func() interface{}
	gets        int64
	puts        int64
	misses      int64
	lastCleanup time.Time
	maxIdleTime time.Duration
	poolType    string
}

// NewObjectPoolManager creates a new object pool manager
func NewObjectPoolManager(cleanupInterval time.Duration) *ObjectPoolManager {
	manager := &ObjectPoolManager{
		pools:           make(map[string]*managedPool),
		cleanupInterval: cleanupInterval,
		done:            make(chan struct{}),
	}

	// Start cleanup goroutine
	if cleanupInterval > 0 {
		manager.cleanupTicker = time.NewTicker(cleanupInterval)
		go manager.cleanupLoop()
	}

	// Register common object pools
	manager.registerCommonPools()

	logx.Infow("Object pool manager initialized",
		logx.Field("cleanupInterval", cleanupInterval))

	return manager
}

// registerCommonPools registers commonly used object pools
func (opm *ObjectPoolManager) registerCommonPools() {
	// Optimized byte slice pools for DataPerm operations
	opm.RegisterPool("bytes-128", func() interface{} {
		return make([]byte, 0, 128) // Common cache key length
	})

	opm.RegisterPool("bytes-256", func() interface{} {
		return make([]byte, 0, 256) // Larger cache keys
	})

	opm.RegisterPool("bytes-1k", func() interface{} {
		return make([]byte, 0, 1024)
	})

	opm.RegisterPool("bytes-4k", func() interface{} {
		return make([]byte, 0, 4096)
	})

	opm.RegisterPool("bytes-16k", func() interface{} {
		return make([]byte, 0, 16384)
	})

	// String slice pools with DataPerm-specific sizes
	opm.RegisterPool("string-slice-roles", func() interface{} {
		return make([]string, 0, 5) // Typical role count
	})

	opm.RegisterPool("string-slice-small", func() interface{} {
		return make([]string, 0, 10)
	})

	opm.RegisterPool("string-slice-large", func() interface{} {
		return make([]string, 0, 100)
	})

	// Map pools
	opm.RegisterPool("string-map-small", func() interface{} {
		return make(map[string]string, 10)
	})

	opm.RegisterPool("string-map-large", func() interface{} {
		return make(map[string]string, 100)
	})

	opm.RegisterPool("interface-map", func() interface{} {
		return make(map[string]interface{}, 20)
	})

	// Buffer pool (alternative to bytes.Buffer)
	opm.RegisterPool("buffer", func() interface{} {
		return &bytes.Buffer{}
	})

	// DataPerm-specific pools
	opm.RegisterPool("cache-key-request", func() interface{} {
		return &KeyGenerationRequest{}
	})

	opm.RegisterPool("permission-context", func() interface{} {
		return &PermissionContext{}
	})



	logx.Infow("Common object pools registered", logx.Field("poolCount", len(opm.pools)))
}

// RegisterPool registers a new object pool
func (opm *ObjectPoolManager) RegisterPool(poolType string, newFunc func() interface{}) {
	opm.mu.Lock()
	defer opm.mu.Unlock()

	pool := &managedPool{
		pool: &sync.Pool{
			New: func() interface{} {
				obj := newFunc()
				atomic.AddInt64(&opm.pools[poolType].misses, 1)
				return obj
			},
		},
		newFunc:     newFunc,
		lastCleanup: time.Now(),
		maxIdleTime: 10 * time.Minute, // Objects idle for 10+ minutes may be cleaned
		poolType:    poolType,
	}

	opm.pools[poolType] = pool

	logx.Infow("Object pool registered", logx.Field("type", poolType))
}

// GetPool returns the pool for the specified type
func (opm *ObjectPoolManager) GetPool(poolType string) *sync.Pool {
	opm.mu.RLock()
	defer opm.mu.RUnlock()

	if pool, exists := opm.pools[poolType]; exists {
		return pool.pool
	}
	return nil
}

// Get gets an object from the specified pool
func (opm *ObjectPoolManager) Get(poolType string) interface{} {
	opm.mu.RLock()
	pool, exists := opm.pools[poolType]
	opm.mu.RUnlock()

	if !exists {
		return nil
	}

	obj := pool.pool.Get()
	atomic.AddInt64(&pool.gets, 1)

	// Reset the object if it has a Reset method
	if resetter, ok := obj.(interface{ Reset() }); ok {
		resetter.Reset()
	}

	return obj
}

// Put returns an object to the specified pool
func (opm *ObjectPoolManager) Put(poolType string, obj interface{}) {
	opm.mu.RLock()
	pool, exists := opm.pools[poolType]
	opm.mu.RUnlock()

	if !exists {
		return
	}

	// Validate object type
	if !opm.validateObjectType(poolType, obj) {
		logx.Errorw("Invalid object type for pool",
			logx.Field("poolType", poolType),
			logx.Field("objectType", reflect.TypeOf(obj)))
		return
	}

	// Clean the object if it has a cleaning method
	opm.cleanObject(obj)

	pool.pool.Put(obj)
	atomic.AddInt64(&pool.puts, 1)
}

// validateObjectType validates that the object is of the expected type for the pool
func (opm *ObjectPoolManager) validateObjectType(poolType string, obj interface{}) bool {
	switch poolType {
	case "bytes-128", "bytes-256", "bytes-1k", "bytes-4k", "bytes-16k":
		_, ok := obj.([]byte)
		return ok
	case "string-slice-roles", "string-slice-small", "string-slice-large":
		_, ok := obj.([]string)
		return ok
	case "string-map-small", "string-map-large":
		_, ok := obj.(map[string]string)
		return ok
	case "interface-map":
		_, ok := obj.(map[string]interface{})
		return ok
	case "buffer":
		_, ok := obj.(*bytes.Buffer)
		return ok
	case "cache-key-request":
		_, ok := obj.(*KeyGenerationRequest)
		return ok
	case "permission-context":
		_, ok := obj.(*PermissionContext)
		return ok
	default:
		// For unknown types, accept anything
		return true
	}
}

// cleanObject cleans an object before returning it to the pool
func (opm *ObjectPoolManager) cleanObject(obj interface{}) {
	switch v := obj.(type) {
	case []byte:
		// Reset slice to zero length but keep capacity
		v = v[:0]
	case []string:
		// Reset slice to zero length but keep capacity
		v = v[:0]
	case map[string]string:
		// Clear map
		for k := range v {
			delete(v, k)
		}
	case map[string]interface{}:
		// Clear map
		for k := range v {
			delete(v, k)
		}
	case *bytes.Buffer:
		v.Reset()
	case *KeyGenerationRequest:
		// Clear key generation request fields
		v.Type = ""
		v.TenantID = 0
		v.UserID = 0
		v.DeptID = 0
		v.RoleCodes = v.RoleCodes[:0] // Reset slice but keep capacity
		if v.Custom != nil {
			for k := range v.Custom {
				delete(v.Custom, k)
			}
		}
	case *PermissionContext:
		v.Reset() // Use the Reset method we defined
	}
}

// GetStats returns statistics for all pools
func (opm *ObjectPoolManager) GetStats() map[string]*PoolStats {
	opm.mu.RLock()
	defer opm.mu.RUnlock()

	stats := make(map[string]*PoolStats, len(opm.pools))

	for poolType, pool := range opm.pools {
		gets := atomic.LoadInt64(&pool.gets)
		puts := atomic.LoadInt64(&pool.puts)
		misses := atomic.LoadInt64(&pool.misses)

		stats[poolType] = &PoolStats{
			Gets:        gets,
			Puts:        puts,
			Misses:      misses,
			CurrentSize: int(puts - gets), // Approximate current size
		}
	}

	return stats
}

// GetPoolStats returns statistics for a specific pool
func (opm *ObjectPoolManager) GetPoolStats(poolType string) *PoolStats {
	opm.mu.RLock()
	pool, exists := opm.pools[poolType]
	opm.mu.RUnlock()

	if !exists {
		return nil
	}

	gets := atomic.LoadInt64(&pool.gets)
	puts := atomic.LoadInt64(&pool.puts)
	misses := atomic.LoadInt64(&pool.misses)

	return &PoolStats{
		Gets:        gets,
		Puts:        puts,
		Misses:      misses,
		CurrentSize: int(puts - gets), // Approximate current size
	}
}

// cleanupLoop periodically cleans up idle objects from pools
func (opm *ObjectPoolManager) cleanupLoop() {
	defer opm.cleanupTicker.Stop()

	for {
		select {
		case <-opm.cleanupTicker.C:
			opm.cleanup()
		case <-opm.done:
			return
		}
	}
}

// cleanup removes idle objects from pools
func (opm *ObjectPoolManager) cleanup() {
	opm.mu.Lock()
	defer opm.mu.Unlock()

	now := time.Now()
	cleanedPools := 0

	for poolType, pool := range opm.pools {
		if now.Sub(pool.lastCleanup) > pool.maxIdleTime {
			// Create a new sync.Pool to effectively clear the old one
			oldNewFunc := pool.newFunc
			pool.pool = &sync.Pool{
				New: func() interface{} {
					obj := oldNewFunc()
					atomic.AddInt64(&opm.pools[poolType].misses, 1)
					return obj
				},
			}
			pool.lastCleanup = now
			cleanedPools++
		}
	}

	if cleanedPools > 0 {
		logx.Infow("Object pools cleanup completed",
			logx.Field("cleanedPools", cleanedPools),
			logx.Field("totalPools", len(opm.pools)))
	}
}

// PrewarmPools pre-allocates objects in pools to avoid initial allocation overhead
func (opm *ObjectPoolManager) PrewarmPools() {
	opm.mu.RLock()
	defer opm.mu.RUnlock()

	prewarmCounts := map[string]int{
		"bytes-128":             25, // High usage for cache keys
		"bytes-256":             15,
		"bytes-1k":              10,
		"bytes-4k":              10,
		"bytes-16k":             5,
		"string-slice-roles":    30, // High usage for role operations
		"string-slice-small":    20,
		"string-slice-large":    5,
		"string-map-small":      15,
		"string-map-large":      5,
		"interface-map":         10,
		"buffer":                15,
		"cache-key-request":     20, // High usage for DataPerm operations
		"permission-context":    15,
		"audit-event":           10,
		"audit-response-writer": 5,
	}

	totalPrewarmed := 0

	for poolType, count := range prewarmCounts {
		if pool, exists := opm.pools[poolType]; exists {
			// Pre-allocate objects
			objects := make([]interface{}, count)
			for i := 0; i < count; i++ {
				objects[i] = pool.newFunc()
			}

			// Put them back in the pool
			for _, obj := range objects {
				pool.pool.Put(obj)
				atomic.AddInt64(&pool.puts, 1)
			}

			totalPrewarmed += count
		}
	}

	logx.Infow("Object pools prewarmed",
		logx.Field("totalObjects", totalPrewarmed))
}

// Close shuts down the object pool manager
func (opm *ObjectPoolManager) Close() {
	close(opm.done)

	if opm.cleanupTicker != nil {
		opm.cleanupTicker.Stop()
	}

	opm.mu.Lock()
	defer opm.mu.Unlock()

	// Clear all pools
	for poolType := range opm.pools {
		delete(opm.pools, poolType)
	}

	logx.Info("Object pool manager closed")
}

// GetBytesFromPool gets a byte slice from the appropriate pool based on size
func (opm *ObjectPoolManager) GetBytesFromPool(size int) []byte {
	var poolType string

	switch {
	case size <= 128:
		poolType = "bytes-128" // Optimal for cache keys
	case size <= 256:
		poolType = "bytes-256" // For larger cache keys
	case size <= 1024:
		poolType = "bytes-1k"
	case size <= 4096:
		poolType = "bytes-4k"
	case size <= 16384:
		poolType = "bytes-16k"
	default:
		// For very large sizes, don't use pooling
		return make([]byte, 0, size)
	}

	obj := opm.Get(poolType)
	if obj != nil {
		return obj.([]byte)
	}

	// Fallback if pool doesn't exist
	return make([]byte, 0, size)
}

// PutBytesToPool returns a byte slice to the appropriate pool
func (opm *ObjectPoolManager) PutBytesToPool(b []byte) {
	capacity := cap(b)
	var poolType string

	switch {
	case capacity <= 128:
		poolType = "bytes-128"
	case capacity <= 256:
		poolType = "bytes-256"
	case capacity <= 1024:
		poolType = "bytes-1k"
	case capacity <= 4096:
		poolType = "bytes-4k"
	case capacity <= 16384:
		poolType = "bytes-16k"
	default:
		// Don't pool very large slices
		return
	}

	// Reset length to 0 but keep capacity
	b = b[:0]
	opm.Put(poolType, b)
}
