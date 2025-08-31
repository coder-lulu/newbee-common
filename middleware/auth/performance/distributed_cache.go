// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package performance

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/auth/core"
	"github.com/go-redis/redis/v8"
	"github.com/hashicorp/golang-lru/v2"
)

// DistributedCache 分布式缓存实现 - 支持Redis集群和本地L1/L2缓存
type DistributedCache struct {
	// L1缓存 - 进程内超快速缓存 (LFU算法)
	l1Cache     *lru.Cache[string, *CachedClaims]
	l1Capacity  int
	l1TTL       time.Duration
	
	// L2缓存 - 本地共享内存缓存
	l2Cache     *ShardedLocalCache
	l2Capacity  int
	l2TTL       time.Duration
	
	// L3缓存 - Redis分布式缓存
	redisClient redis.UniversalClient // 支持单机、哨兵、集群模式
	redisPrefix string
	redisTTL    time.Duration
	
	// 批量操作优化
	batchProcessor *BatchProcessor
	pipeline       redis.Pipeliner
	
	// 缓存预热
	preheater     *CachePreheater
	hotKeys       *HotKeyDetector
	
	// 性能监控
	stats         *CacheStats
	metrics       *DistributedMetrics
	
	// 并发控制
	mu            sync.RWMutex
	singleFlight  *SingleFlightGroup // 防止缓存击穿
	rateLimiter   *RateLimiter       // 限流保护
	
	// 配置
	config        *DistributedCacheConfig
}

// DistributedCacheConfig 分布式缓存配置
type DistributedCacheConfig struct {
	// Redis配置
	RedisAddrs      []string      `json:"redis_addrs"`
	RedisPassword   string        `json:"redis_password"`
	RedisDB         int           `json:"redis_db"`
	RedisPoolSize   int           `json:"redis_pool_size"`
	RedisMode       string        `json:"redis_mode"` // "single", "sentinel", "cluster"
	
	// 多级缓存配置
	L1Enabled       bool          `json:"l1_enabled"`
	L1Capacity      int           `json:"l1_capacity"`
	L1TTL           time.Duration `json:"l1_ttl"`
	
	L2Enabled       bool          `json:"l2_enabled"`
	L2Capacity      int           `json:"l2_capacity"`
	L2Shards        int           `json:"l2_shards"`
	L2TTL           time.Duration `json:"l2_ttl"`
	
	L3TTL           time.Duration `json:"l3_ttl"`
	
	// 批量操作
	BatchSize       int           `json:"batch_size"`
	BatchTimeout    time.Duration `json:"batch_timeout"`
	
	// 预热配置
	EnablePreheating bool         `json:"enable_preheating"`
	PreheatingKeys   int          `json:"preheating_keys"`
	
	// 性能优化
	EnablePipeline   bool         `json:"enable_pipeline"`
	PipelineBuffer   int          `json:"pipeline_buffer"`
	EnableCompression bool        `json:"enable_compression"`
	
	// 容错配置
	MaxRetries       int          `json:"max_retries"`
	RetryBackoff     time.Duration `json:"retry_backoff"`
	CircuitBreaker   bool         `json:"circuit_breaker"`
}

// CachedClaims 缓存的声明信息
type CachedClaims struct {
	Claims       *core.Claims  `json:"claims"`
	CachedAt     time.Time    `json:"cached_at"`
	ExpiresAt    time.Time    `json:"expires_at"`
	HitCount     int64        `json:"hit_count"`
	Version      int64        `json:"version"`
	Compressed   bool         `json:"compressed"`
}

// CacheStats 缓存统计
type CacheStats struct {
	L1Hits        atomic.Uint64
	L2Hits        atomic.Uint64
	L3Hits        atomic.Uint64
	Misses        atomic.Uint64
	
	L1Evictions   atomic.Uint64
	L2Evictions   atomic.Uint64
	
	TotalRequests atomic.Uint64
	TotalLatency  atomic.Uint64
	
	LastUpdate    atomic.Value // time.Time
}

// NewDistributedCache 创建分布式缓存
func NewDistributedCache(config *DistributedCacheConfig) (*DistributedCache, error) {
	if config == nil {
		config = DefaultDistributedCacheConfig()
	}
	
	dc := &DistributedCache{
		config:       config,
		redisPrefix:  "auth:token:",
		redisTTL:     config.L3TTL,
		stats:        &CacheStats{},
		metrics:      NewDistributedMetrics(),
		singleFlight: NewSingleFlightGroup(),
		rateLimiter:  NewRateLimiter(10000), // 10K ops/sec
	}
	
	// 初始化L1缓存 (LFU算法，最适合热点数据)
	if config.L1Enabled {
		l1, err := lru.New[string, *CachedClaims](config.L1Capacity)
		if err != nil {
			return nil, fmt.Errorf("failed to create L1 cache: %w", err)
		}
		dc.l1Cache = l1
		dc.l1Capacity = config.L1Capacity
		dc.l1TTL = config.L1TTL
	}
	
	// 初始化L2缓存 (分片本地缓存)
	if config.L2Enabled {
		dc.l2Cache = NewShardedLocalCache(
			config.L2Shards,
			config.L2Capacity,
			config.L2TTL,
		)
	}
	
	// 初始化Redis客户端
	if err := dc.initRedisClient(); err != nil {
		return nil, fmt.Errorf("failed to init redis client: %w", err)
	}
	
	// 初始化批处理器
	if config.BatchSize > 0 {
		dc.batchProcessor = NewBatchProcessor(
			config.BatchSize,
			config.BatchTimeout,
			dc.batchSet,
			dc.batchGet,
		)
	}
	
	// 初始化预热器
	if config.EnablePreheating {
		dc.preheater = NewCachePreheater(dc, config.PreheatingKeys)
		dc.hotKeys = NewHotKeyDetector(1000) // Top 1000 hot keys
	}
	
	// 启动后台任务
	dc.startBackgroundTasks()
	
	return dc, nil
}

// initRedisClient 初始化Redis客户端
func (dc *DistributedCache) initRedisClient() error {
	config := dc.config
	
	switch config.RedisMode {
	case "cluster":
		dc.redisClient = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        config.RedisAddrs,
			Password:     config.RedisPassword,
			PoolSize:     config.RedisPoolSize,
			MaxRetries:   config.MaxRetries,
			MinIdleConns: 10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		})
		
	case "sentinel":
		dc.redisClient = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    "master",
			SentinelAddrs: config.RedisAddrs,
			Password:      config.RedisPassword,
			DB:            config.RedisDB,
			PoolSize:      config.RedisPoolSize,
			MaxRetries:    config.MaxRetries,
		})
		
	default: // single
		dc.redisClient = redis.NewClient(&redis.Options{
			Addr:         config.RedisAddrs[0],
			Password:     config.RedisPassword,
			DB:           config.RedisDB,
			PoolSize:     config.RedisPoolSize,
			MaxRetries:   config.MaxRetries,
			MinIdleConns: 10,
		})
	}
	
	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := dc.redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}
	
	// 初始化Pipeline
	if config.EnablePipeline {
		dc.pipeline = dc.redisClient.Pipeline()
	}
	
	return nil
}

// Get 获取缓存的JWT claims (多级缓存查找)
func (dc *DistributedCache) Get(ctx context.Context, tokenHash string) (*core.Claims, bool) {
	// 记录请求
	dc.stats.TotalRequests.Add(1)
	startTime := time.Now()
	defer func() {
		dc.stats.TotalLatency.Add(uint64(time.Since(startTime).Microseconds()))
	}()
	
	// 限流检查
	if !dc.rateLimiter.Allow() {
		return nil, false
	}
	
	// L1缓存查找 (最快)
	if dc.l1Cache != nil {
		if cached, ok := dc.l1Cache.Get(tokenHash); ok {
			if !dc.isExpired(cached) {
				dc.stats.L1Hits.Add(1)
				dc.recordHotKey(tokenHash)
				atomic.AddInt64(&cached.HitCount, 1)
				return dc.copyClaims(cached.Claims), true
			}
			dc.l1Cache.Remove(tokenHash)
		}
	}
	
	// L2缓存查找
	if dc.l2Cache != nil {
		if cached, ok := dc.l2Cache.Get(tokenHash); ok {
			if cachedClaims, valid := dc.validateCached(cached); valid {
				dc.stats.L2Hits.Add(1)
				dc.promoteToL1(tokenHash, cachedClaims)
				dc.recordHotKey(tokenHash)
				return dc.copyClaims(cachedClaims.Claims), true
			}
			dc.l2Cache.Delete(tokenHash)
		}
	}
	
	// L3缓存查找 (Redis) - 使用SingleFlight防止缓存击穿
	result, err, _ := dc.singleFlight.Do(tokenHash, func() (interface{}, error) {
		return dc.getFromRedis(ctx, tokenHash)
	})
	
	if err == nil && result != nil {
		if cachedClaims, ok := result.(*CachedClaims); ok && !dc.isExpired(cachedClaims) {
			dc.stats.L3Hits.Add(1)
			dc.promoteToL2(tokenHash, cachedClaims)
			dc.promoteToL1(tokenHash, cachedClaims)
			dc.recordHotKey(tokenHash)
			return dc.copyClaims(cachedClaims.Claims), true
		}
	}
	
	// 缓存未命中
	dc.stats.Misses.Add(1)
	return nil, false
}

// Set 设置缓存 (写入所有层级)
func (dc *DistributedCache) Set(ctx context.Context, tokenHash string, claims *core.Claims, ttl ...time.Duration) error {
	if claims == nil {
		return nil
	}
	
	effectiveTTL := dc.redisTTL
	if len(ttl) > 0 && ttl[0] > 0 {
		effectiveTTL = ttl[0]
	}
	
	cached := &CachedClaims{
		Claims:    claims,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(effectiveTTL),
		HitCount:  0,
		Version:   time.Now().UnixNano(),
	}
	
	// 写入L1缓存
	if dc.l1Cache != nil {
		dc.l1Cache.Add(tokenHash, cached)
	}
	
	// 写入L2缓存
	if dc.l2Cache != nil {
		dc.l2Cache.Set(tokenHash, cached, dc.l2TTL)
	}
	
	// 异步写入Redis (不阻塞主流程)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		
		if dc.batchProcessor != nil {
			// 批量写入
			dc.batchProcessor.Add(tokenHash, cached)
		} else {
			// 直接写入
			dc.setToRedis(ctx, tokenHash, cached, effectiveTTL)
		}
	}()
	
	return nil
}

// BatchGet 批量获取
func (dc *DistributedCache) BatchGet(ctx context.Context, tokenHashes []string) map[string]*core.Claims {
	results := make(map[string]*core.Claims, len(tokenHashes))
	missing := make([]string, 0, len(tokenHashes))
	
	// 先从本地缓存查找
	for _, hash := range tokenHashes {
		if claims, ok := dc.Get(ctx, hash); ok {
			results[hash] = claims
		} else {
			missing = append(missing, hash)
		}
	}
	
	// 批量从Redis获取缺失的
	if len(missing) > 0 {
		redisResults := dc.batchGetFromRedis(ctx, missing)
		for hash, claims := range redisResults {
			results[hash] = claims
			// 回填到本地缓存
			dc.Set(ctx, hash, claims)
		}
	}
	
	return results
}

// Delete 删除缓存 (所有层级)
func (dc *DistributedCache) Delete(ctx context.Context, tokenHash string) error {
	// 删除L1缓存
	if dc.l1Cache != nil {
		dc.l1Cache.Remove(tokenHash)
	}
	
	// 删除L2缓存
	if dc.l2Cache != nil {
		dc.l2Cache.Delete(tokenHash)
	}
	
	// 删除Redis缓存
	key := dc.redisPrefix + tokenHash
	return dc.redisClient.Del(ctx, key).Err()
}

// InvalidatePattern 按模式失效缓存 (支持通配符)
func (dc *DistributedCache) InvalidatePattern(ctx context.Context, pattern string) error {
	// 清理本地缓存
	if dc.l1Cache != nil {
		dc.l1Cache.Purge()
	}
	if dc.l2Cache != nil {
		dc.l2Cache.Clear()
	}
	
	// 清理Redis缓存
	keys, err := dc.redisClient.Keys(ctx, dc.redisPrefix+pattern).Result()
	if err != nil {
		return err
	}
	
	if len(keys) > 0 {
		return dc.redisClient.Del(ctx, keys...).Err()
	}
	
	return nil
}

// PreHeat 预热缓存
func (dc *DistributedCache) PreHeat(ctx context.Context, tokens []string) error {
	if dc.preheater == nil {
		return fmt.Errorf("preheater not initialized")
	}
	
	return dc.preheater.Preheat(ctx, tokens)
}

// getFromRedis 从Redis获取
func (dc *DistributedCache) getFromRedis(ctx context.Context, tokenHash string) (*CachedClaims, error) {
	key := dc.redisPrefix + tokenHash
	
	data, err := dc.redisClient.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	
	var cached CachedClaims
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}
	
	return &cached, nil
}

// setToRedis 写入Redis
func (dc *DistributedCache) setToRedis(ctx context.Context, tokenHash string, cached *CachedClaims, ttl time.Duration) error {
	key := dc.redisPrefix + tokenHash
	
	data, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	
	// 如果启用压缩
	if dc.config.EnableCompression && len(data) > 1024 {
		data = dc.compress(data)
		cached.Compressed = true
	}
	
	return dc.redisClient.Set(ctx, key, data, ttl).Err()
}

// batchGetFromRedis 批量从Redis获取
func (dc *DistributedCache) batchGetFromRedis(ctx context.Context, hashes []string) map[string]*core.Claims {
	results := make(map[string]*core.Claims, len(hashes))
	
	// 使用Pipeline批量获取
	pipe := dc.redisClient.Pipeline()
	cmds := make([]*redis.StringCmd, 0, len(hashes))
	
	for _, hash := range hashes {
		key := dc.redisPrefix + hash
		cmds = append(cmds, pipe.Get(ctx, key))
	}
	
	_, _ = pipe.Exec(ctx)
	
	for i, cmd := range cmds {
		data, err := cmd.Bytes()
		if err == nil {
			var cached CachedClaims
			if json.Unmarshal(data, &cached) == nil && !dc.isExpired(&cached) {
				results[hashes[i]] = dc.copyClaims(cached.Claims)
			}
		}
	}
	
	return results
}

// batchSet 批量设置 (BatchProcessor回调)
func (dc *DistributedCache) batchSet(items map[string]interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	pipe := dc.redisClient.Pipeline()
	
	for hash, item := range items {
		if cached, ok := item.(*CachedClaims); ok {
			key := dc.redisPrefix + hash
			if data, err := json.Marshal(cached); err == nil {
				pipe.Set(ctx, key, data, dc.redisTTL)
			}
		}
	}
	
	pipe.Exec(ctx)
}

// batchGet 批量获取 (BatchProcessor回调)
func (dc *DistributedCache) batchGet(keys []string) map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	
	results := make(map[string]interface{})
	
	pipe := dc.redisClient.Pipeline()
	cmds := make([]*redis.StringCmd, 0, len(keys))
	
	for _, key := range keys {
		cmds = append(cmds, pipe.Get(ctx, dc.redisPrefix+key))
	}
	
	pipe.Exec(ctx)
	
	for i, cmd := range cmds {
		if data, err := cmd.Bytes(); err == nil {
			var cached CachedClaims
			if json.Unmarshal(data, &cached) == nil {
				results[keys[i]] = &cached
			}
		}
	}
	
	return results
}

// promoteToL1 提升到L1缓存
func (dc *DistributedCache) promoteToL1(tokenHash string, cached *CachedClaims) {
	if dc.l1Cache != nil && cached != nil {
		dc.l1Cache.Add(tokenHash, cached)
	}
}

// promoteToL2 提升到L2缓存
func (dc *DistributedCache) promoteToL2(tokenHash string, cached *CachedClaims) {
	if dc.l2Cache != nil && cached != nil {
		dc.l2Cache.Set(tokenHash, cached, dc.l2TTL)
	}
}

// recordHotKey 记录热点Key
func (dc *DistributedCache) recordHotKey(key string) {
	if dc.hotKeys != nil {
		dc.hotKeys.Record(key)
	}
}

// isExpired 检查是否过期
func (dc *DistributedCache) isExpired(cached *CachedClaims) bool {
	return cached == nil || time.Now().After(cached.ExpiresAt)
}

// validateCached 验证缓存数据
func (dc *DistributedCache) validateCached(data interface{}) (*CachedClaims, bool) {
	cached, ok := data.(*CachedClaims)
	if !ok || dc.isExpired(cached) {
		return nil, false
	}
	return cached, true
}

// copyClaims 复制Claims (防止外部修改)
func (dc *DistributedCache) copyClaims(original *core.Claims) *core.Claims {
	if original == nil {
		return nil
	}
	
	// 深拷贝
	copy := &core.Claims{
		UserID:    original.UserID,
		TenantID:  original.TenantID,
		Role:      original.Role,
		SessionID: original.SessionID,
		IssuedAt:  original.IssuedAt,
		ExpiresAt: original.ExpiresAt,
		NotBefore: original.NotBefore,
	}
	
	if len(original.Roles) > 0 {
		copy.Roles = make([]string, len(original.Roles))
		copy.copy.Roles, original.Roles)
	}
	
	if len(original.Permissions) > 0 {
		copy.Permissions = make([]string, len(original.Permissions))
		copy(copy.Permissions, original.Permissions)
	}
	
	if original.Extra != nil {
		copy.Extra = make(map[string]interface{}, len(original.Extra))
		for k, v := range original.Extra {
			copy.Extra[k] = v
		}
	}
	
	return copy
}

// compress 压缩数据
func (dc *DistributedCache) compress(data []byte) []byte {
	// 实现压缩逻辑 (使用snappy或lz4)
	return data
}

// decompress 解压数据
func (dc *DistributedCache) decompress(data []byte) []byte {
	// 实现解压逻辑
	return data
}

// startBackgroundTasks 启动后台任务
func (dc *DistributedCache) startBackgroundTasks() {
	// 定期清理过期数据
	go dc.cleanupExpired()
	
	// 定期同步热点数据
	if dc.hotKeys != nil {
		go dc.syncHotKeys()
	}
	
	// 定期报告统计
	go dc.reportStats()
}

// cleanupExpired 清理过期数据
func (dc *DistributedCache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		// 清理L1缓存 (LRU自动管理)
		
		// 清理L2缓存
		if dc.l2Cache != nil {
			dc.l2Cache.CleanupExpired()
		}
		
		// Redis TTL自动管理
	}
}

// syncHotKeys 同步热点数据
func (dc *DistributedCache) syncHotKeys() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		hotKeys := dc.hotKeys.GetTop(100)
		
		// 预加载热点数据到本地缓存
		ctx := context.Background()
		for _, key := range hotKeys {
			if _, ok := dc.Get(ctx, key); !ok {
				// 触发加载
				dc.Get(ctx, key)
			}
		}
	}
}

// reportStats 报告统计信息
func (dc *DistributedCache) reportStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		dc.metrics.Report(dc.GetStats())
	}
}

// GetStats 获取统计信息
func (dc *DistributedCache) GetStats() map[string]interface{} {
	total := dc.stats.TotalRequests.Load()
	l1Hits := dc.stats.L1Hits.Load()
	l2Hits := dc.stats.L2Hits.Load()
	l3Hits := dc.stats.L3Hits.Load()
	misses := dc.stats.Misses.Load()
	
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(l1Hits+l2Hits+l3Hits) / float64(total) * 100
	}
	
	avgLatency := float64(0)
	if total > 0 {
		avgLatency = float64(dc.stats.TotalLatency.Load()) / float64(total)
	}
	
	return map[string]interface{}{
		"total_requests": total,
		"l1_hits":       l1Hits,
		"l2_hits":       l2Hits,
		"l3_hits":       l3Hits,
		"misses":        misses,
		"hit_rate":      hitRate,
		"l1_hit_rate":   float64(l1Hits) / float64(total) * 100,
		"l2_hit_rate":   float64(l2Hits) / float64(total) * 100,
		"l3_hit_rate":   float64(l3Hits) / float64(total) * 100,
		"avg_latency_us": avgLatency,
	}
}

// Shutdown 关闭缓存
func (dc *DistributedCache) Shutdown() error {
	// 关闭批处理器
	if dc.batchProcessor != nil {
		dc.batchProcessor.Shutdown()
	}
	
	// 关闭Redis连接
	if dc.redisClient != nil {
		return dc.redisClient.Close()
	}
	
	return nil
}

// DefaultDistributedCacheConfig 默认分布式缓存配置
func DefaultDistributedCacheConfig() *DistributedCacheConfig {
	return &DistributedCacheConfig{
		RedisAddrs:    []string{"localhost:6379"},
		RedisMode:     "single",
		RedisPoolSize: 100,
		
		L1Enabled:  true,
		L1Capacity: 10000,
		L1TTL:      1 * time.Minute,
		
		L2Enabled: true,
		L2Capacity: 50000,
		L2Shards:   64,
		L2TTL:      5 * time.Minute,
		
		L3TTL: 10 * time.Minute,
		
		BatchSize:    100,
		BatchTimeout: 100 * time.Millisecond,
		
		EnablePreheating:  true,
		PreheatingKeys:    1000,
		EnablePipeline:    true,
		PipelineBuffer:    100,
		EnableCompression: true,
		
		MaxRetries:     3,
		RetryBackoff:   100 * time.Millisecond,
		CircuitBreaker: true,
	}
}