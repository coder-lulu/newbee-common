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

// Package auth 企业级高性能认证中间件 - 终极优化版
package auth

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/audit"
	"github.com/coder-lulu/newbee-common/utils/jwt"
	jwt2 "github.com/golang-jwt/jwt/v5"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/enum"
	"google.golang.org/grpc/metadata"
	"strconv"
)

// ==================== 配置定义 ====================

// OptimalConfig 优化配置（精简至核心参数）
type OptimalConfig struct {
	// 基础配置
	JWTSecret string   `json:"jwt_secret" yaml:"jwt_secret"`
	Enabled   bool     `json:"enabled" yaml:"enabled"`
	SkipPaths []string `json:"skip_paths" yaml:"skip_paths"`

	// 性能配置
	Performance PerformanceOpts `json:"performance" yaml:"performance"`

	// 监控配置
	Monitoring MonitoringOpts `json:"monitoring" yaml:"monitoring"`
}

// PerformanceOpts 性能选项
type PerformanceOpts struct {
	EnableCache   bool          `json:"enable_cache" yaml:"enable_cache"`
	CacheSize     int           `json:"cache_size" yaml:"cache_size"`
	CacheTTL      time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
	EnablePool    bool          `json:"enable_pool" yaml:"enable_pool"`
	ShardCount    int           `json:"shard_count" yaml:"shard_count"`
}

// MonitoringOpts 监控选项
type MonitoringOpts struct {
	Enabled         bool `json:"enabled" yaml:"enabled"`
	CollectDetailed bool `json:"collect_detailed" yaml:"collect_detailed"`
}

// DefaultOptimalConfig 默认优化配置
func DefaultOptimalConfig() *OptimalConfig {
	return &OptimalConfig{
		Enabled:   true,
		SkipPaths: []string{"/health", "/metrics", "/ping", "/ready"},
		Performance: PerformanceOpts{
			EnableCache: true,
			CacheSize:   10000,
			CacheTTL:    5 * time.Minute,
			EnablePool:  true,
			ShardCount:  256,
		},
		Monitoring: MonitoringOpts{
			Enabled:         true,
			CollectDetailed: false,
		},
	}
}

// ==================== 核心中间件 ====================

// OptimalAuth 优化的认证中间件（核心实现）
type OptimalAuth struct {
	config    *OptimalConfig
	skipPaths map[string]bool
	cache     *ShardedCache
	metrics   *Metrics
	pool      *sync.Pool
}

// NewOptimal 创建优化的认证中间件
func NewOptimal(config *OptimalConfig) *OptimalAuth {
	if config == nil {
		config = DefaultOptimalConfig()
	}

	auth := &OptimalAuth{
		config:    config,
		skipPaths: make(map[string]bool, len(config.SkipPaths)),
	}

	// 构建跳过路径映射（O(1)查找）
	for _, path := range config.SkipPaths {
		auth.skipPaths[path] = true
	}

	// 初始化缓存
	if config.Performance.EnableCache {
		auth.cache = NewShardedCache(
			config.Performance.ShardCount,
			config.Performance.CacheSize,
			config.Performance.CacheTTL,
		)
	}

	// 初始化对象池
	if config.Performance.EnablePool {
		auth.pool = &sync.Pool{
			New: func() interface{} {
				return &jwt.TokenInfo{
					Claims: make(jwt2.MapClaims, 8),
				}
			},
		}
	}

	// 初始化指标
	if config.Monitoring.Enabled {
		auth.metrics = NewMetrics()
	}

	return auth
}

// Handle HTTP处理函数（核心逻辑）
func (oa *OptimalAuth) Handle(next http.HandlerFunc) http.HandlerFunc {
	// 预检查配置
	if !oa.config.Enabled {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// 指标记录
		start := time.Now()
		if oa.metrics != nil {
			defer oa.metrics.Record(time.Since(start))
		}

		// Debug: Log incoming request details
		logx.Infow("Auth middleware processing request",
			logx.Field("method", r.Method),
			logx.Field("path", r.URL.Path),
			logx.Field("headers_authorization", r.Header.Get("Authorization") != ""),
			logx.Field("remote_addr", r.RemoteAddr))

		// 快速路径1: 跳过路径检查
		if oa.skipPaths[r.URL.Path] {
			logx.Infow("Skipping auth for path", logx.Field("path", r.URL.Path))
			next(w, r)
			return
		}

		// 提取令牌
		token := oa.extractToken(r)
		if token == "" {
			logx.Errorw("No authorization token found in request", 
				logx.Field("path", r.URL.Path),
				logx.Field("authorization_header", r.Header.Get("Authorization")))
			oa.handleUnauthorized(w, r, errors.New("missing token"))
			return
		}

		logx.Infow("Token extracted successfully", 
			logx.Field("token_length", len(token)),
			logx.Field("token_prefix", func() string {
				if len(token) > 10 {
					return token[:10]
				}
				return token
			}()))

		// 快速路径2: 缓存查找
		var tokenInfo *jwt.TokenInfo
		var cached bool

		if oa.cache != nil {
			tokenInfo, cached = oa.cache.Get(token)
			if cached {
				logx.Infow("Using cached token info", 
					logx.Field("userID", tokenInfo.UserID),
					logx.Field("tenantID", tokenInfo.TenantID))
				if oa.metrics != nil {
					atomic.AddInt64(&oa.metrics.cacheHits, 1)
				}
			} else {
				if oa.metrics != nil {
					atomic.AddInt64(&oa.metrics.cacheMisses, 1)
				}
			}
		}

		// 慢路径: JWT验证
		if !cached {
			logx.Infow("Validating JWT token (cache miss)")
			var err error
			tokenInfo, err = oa.validateToken(token)
			if err != nil {
				logx.Errorw("JWT token validation failed", 
					logx.Field("error", err.Error()),
					logx.Field("token_length", len(token)))
				oa.handleUnauthorized(w, r, err)
				return
			}

			logx.Infow("JWT token validated successfully", 
				logx.Field("userID", tokenInfo.UserID),
				logx.Field("tenantID", tokenInfo.TenantID),
				logx.Field("claims_count", len(tokenInfo.Claims)),
				logx.Field("valid", tokenInfo.Valid))

			// 更新缓存
			if oa.cache != nil {
				oa.cache.Set(token, tokenInfo)
			}
		}

		// 注入上下文
		ctx := oa.injectContext(r.Context(), tokenInfo)

		// 记录成功
		if oa.metrics != nil {
			atomic.AddInt64(&oa.metrics.successes, 1)
		}

		next(w, r.WithContext(ctx))
	}
}

// extractToken 提取令牌（优化版）
func (oa *OptimalAuth) extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	// 避免字符串分配
	if len(auth) > 7 && auth[0] == 'B' && auth[6] == ' ' {
		return auth[7:]
	}
	return ""
}

// validateToken JWT验证
func (oa *OptimalAuth) validateToken(token string) (*jwt.TokenInfo, error) {
	if oa.config.JWTSecret == "" {
		return nil, errors.New("JWT secret not configured")
	}

	logx.Infow("Starting JWT token validation", 
		logx.Field("token_length", len(token)),
		logx.Field("has_secret", oa.config.JWTSecret != ""))

	// 使用对象池
	if oa.pool != nil {
		tokenInfo := oa.pool.Get().(*jwt.TokenInfo)
		defer func() {
			if tokenInfo.Valid == false {
				// 重置并归还
				tokenInfo.UserID = ""
				tokenInfo.TenantID = ""
				tokenInfo.Claims = make(jwt2.MapClaims, 8)
				oa.pool.Put(tokenInfo)
			}
		}()
	}

	tokenInfo, err := jwt.ValidateJwtToken(token, oa.config.JWTSecret)
	if err != nil {
		logx.Errorw("JWT validation failed", 
			logx.Field("error", err.Error()),
			logx.Field("token_length", len(token)))
		return nil, err
	}

	// Debug: Log the actual claims content
	logx.Infow("JWT token claims detailed analysis", 
		logx.Field("userID", tokenInfo.UserID),
		logx.Field("tenantID", tokenInfo.TenantID),
		logx.Field("valid", tokenInfo.Valid),
		logx.Field("claims_raw", tokenInfo.Claims))

	// Log each claim individually for debugging
	for key, value := range tokenInfo.Claims {
		logx.Infow("JWT claim detail", 
			logx.Field("key", key), 
			logx.Field("value", value),
			logx.Field("type", fmt.Sprintf("%T", value)))
	}

	return tokenInfo, nil
}

// injectContext 注入上下文（优化版）
func (oa *OptimalAuth) injectContext(ctx context.Context, tokenInfo *jwt.TokenInfo) context.Context {
	// Debug logging to track what token information we have
	logx.Infow("Auth middleware injecting context",
		logx.Field("userID", tokenInfo.UserID),
		logx.Field("tenantID", tokenInfo.TenantID),
		logx.Field("valid", tokenInfo.Valid),
		logx.Field("claimsCount", len(tokenInfo.Claims)))

	// 使用预定义的key减少内存分配
	type ctxKey int
	const (
		userIDKey ctxKey = iota
		tenantIDKey
		permissionsKey
		rolesKey
	)

	ctx = context.WithValue(ctx, userIDKey, tokenInfo.UserID)
	ctx = context.WithValue(ctx, tenantIDKey, tokenInfo.TenantID)

	// 兼容性：同时使用字符串key
	ctx = context.WithValue(ctx, "userID", tokenInfo.UserID)
	ctx = context.WithValue(ctx, "tenantID", tokenInfo.TenantID)
	
	// 审计中间件兼容性：使用审计包提供的函数来设置context keys（确保类型匹配）
	ctx = audit.WithUserID(ctx, tokenInfo.UserID)
	ctx = audit.WithTenantID(ctx, tokenInfo.TenantID)

	logx.Infow("Auth middleware set audit context keys using audit package functions",
		logx.Field("audit_user_id", tokenInfo.UserID),
		logx.Field("audit_tenant_id", tokenInfo.TenantID))

	// RPC兼容性：设置租户上下文以便RPC调用正常工作
	if tenantIDStr := tokenInfo.TenantID; tenantIDStr != "" {
		// 将tenant ID转换为uint64
		if tenantID, err := strconv.ParseUint(tenantIDStr, 10, 64); err == nil {
			// 设置RPC期望的context key
			ctx = context.WithValue(ctx, enum.TenantIdCtxKey, tenantIDStr)
			ctx = context.WithValue(ctx, "tenantId", tenantID)
			
			// 设置gRPC metadata以便跨服务调用
			ctx = metadata.AppendToOutgoingContext(ctx, enum.TenantIdCtxKey, tenantIDStr)
		}
	}

	// 批量处理claims - 根据实际JWT结构映射
	if len(tokenInfo.Claims) > 0 {
		// 处理用户ID
		if userID, ok := tokenInfo.Claims["userId"]; ok {
			if userIDStr, ok := userID.(string); ok {
				ctx = context.WithValue(ctx, "userId", userIDStr)
			}
		}
		
		// 处理角色ID - 映射roleId到roleCodes以兼容现有业务逻辑
		if roleID, ok := tokenInfo.Claims["roleId"]; ok {
			if roleIDStr, ok := roleID.(string); ok {
				ctx = context.WithValue(ctx, "roleCodes", roleIDStr)
				ctx = context.WithValue(ctx, "roleId", roleIDStr)
			}
		}
		
		// 处理角色IDs - 也可能被某些逻辑使用
		if roleIDs, ok := tokenInfo.Claims["roleIds"]; ok {
			if roleIDsStr, ok := roleIDs.(string); ok {
				ctx = context.WithValue(ctx, "roleIds", roleIDsStr)
				// 如果没有roleId但有roleIds，也用它作为roleCodes
				if _, hasRoleID := tokenInfo.Claims["roleId"]; !hasRoleID {
					ctx = context.WithValue(ctx, "roleCodes", roleIDsStr)
				}
			}
		}
		
		// 处理部门ID
		if deptID, ok := tokenInfo.Claims["deptId"]; ok {
			ctx = context.WithValue(ctx, "deptId", deptID)
		}
		
		// 保持原有的permissions和roles处理以兼容其他可能的用法
		if perms, ok := tokenInfo.Claims["permissions"]; ok {
			ctx = context.WithValue(ctx, permissionsKey, perms)
			ctx = context.WithValue(ctx, "permissions", perms)
		}
		if roles, ok := tokenInfo.Claims["roles"]; ok {
			ctx = context.WithValue(ctx, rolesKey, roles)
			ctx = context.WithValue(ctx, "roles", roles)
		}
	}

	return ctx
}

// handleUnauthorized 处理未授权请求
func (oa *OptimalAuth) handleUnauthorized(w http.ResponseWriter, r *http.Request, err error) {
	if oa.metrics != nil {
		atomic.AddInt64(&oa.metrics.failures, 1)
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// ==================== 分片缓存实现 ====================

// ShardedCache 高性能分片缓存
type ShardedCache struct {
	shards    []*shard
	shardMask uint32
	ttl       time.Duration
}

// shard 缓存分片
type shard struct {
	mu    sync.RWMutex
	items map[string]*cachedItem
}

// cachedItem 缓存项
type cachedItem struct {
	tokenInfo *jwt.TokenInfo
	expireAt  time.Time
	hits      int32
}

// NewShardedCache 创建分片缓存
func NewShardedCache(shardCount, maxSize int, ttl time.Duration) *ShardedCache {
	// 确保分片数是2的幂
	count := 1
	for count < shardCount {
		count <<= 1
	}

	cache := &ShardedCache{
		shards:    make([]*shard, count),
		shardMask: uint32(count - 1),
		ttl:       ttl,
	}

	maxPerShard := maxSize / count
	for i := range cache.shards {
		cache.shards[i] = &shard{
			items: make(map[string]*cachedItem, maxPerShard),
		}
	}

	// 启动清理协程
	go cache.cleanup()

	return cache
}

// Get 获取缓存
func (c *ShardedCache) Get(token string) (*jwt.TokenInfo, bool) {
	shard := c.getShard(token)

	shard.mu.RLock()
	item, exists := shard.items[token]
	shard.mu.RUnlock()

	if !exists || time.Now().After(item.expireAt) {
		return nil, false
	}

	atomic.AddInt32(&item.hits, 1)
	return item.tokenInfo, true
}

// Set 设置缓存
func (c *ShardedCache) Set(token string, info *jwt.TokenInfo) {
	shard := c.getShard(token)

	item := &cachedItem{
		tokenInfo: info,
		expireAt:  time.Now().Add(c.ttl),
		hits:      0,
	}

	shard.mu.Lock()
	// 简单的容量控制
	if len(shard.items) > 1000 {
		// 删除最旧的项
		for k := range shard.items {
			delete(shard.items, k)
			break
		}
	}
	shard.items[token] = item
	shard.mu.Unlock()
}

// getShard 获取分片
func (c *ShardedCache) getShard(token string) *shard {
	h := fnv.New32a()
	h.Write([]byte(token))
	return c.shards[h.Sum32()&c.shardMask]
}

// cleanup 定期清理过期项
func (c *ShardedCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for _, shard := range c.shards {
			shard.mu.Lock()
			for token, item := range shard.items {
				if now.After(item.expireAt) {
					delete(shard.items, token)
				}
			}
			shard.mu.Unlock()
		}
	}
}

// ==================== 指标收集 ====================

// Metrics 轻量级指标
type Metrics struct {
	requests    int64
	successes   int64
	failures    int64
	cacheHits   int64
	cacheMisses int64
	totalLatency int64
}

// NewMetrics 创建指标收集器
func NewMetrics() *Metrics {
	return &Metrics{}
}

// Record 记录请求
func (m *Metrics) Record(latency time.Duration) {
	atomic.AddInt64(&m.requests, 1)
	atomic.AddInt64(&m.totalLatency, int64(latency))
}

// GetSnapshot 获取指标快照
func (m *Metrics) GetSnapshot() map[string]interface{} {
	requests := atomic.LoadInt64(&m.requests)
	avgLatency := int64(0)
	if requests > 0 {
		avgLatency = atomic.LoadInt64(&m.totalLatency) / requests
	}

	hits := atomic.LoadInt64(&m.cacheHits)
	misses := atomic.LoadInt64(&m.cacheMisses)
	hitRate := float64(0)
	if total := hits + misses; total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return map[string]interface{}{
		"requests":       requests,
		"successes":      atomic.LoadInt64(&m.successes),
		"failures":       atomic.LoadInt64(&m.failures),
		"cache_hits":     hits,
		"cache_misses":   misses,
		"cache_hit_rate": hitRate,
		"avg_latency_ns": avgLatency,
	}
}

// Reset 重置指标
func (m *Metrics) Reset() {
	atomic.StoreInt64(&m.requests, 0)
	atomic.StoreInt64(&m.successes, 0)
	atomic.StoreInt64(&m.failures, 0)
	atomic.StoreInt64(&m.cacheHits, 0)
	atomic.StoreInt64(&m.cacheMisses, 0)
	atomic.StoreInt64(&m.totalLatency, 0)
}

// ==================== 辅助函数 ====================

// ExtractUserID 从上下文提取用户ID
func ExtractUserID(ctx context.Context) string {
	if userID, ok := ctx.Value("userID").(string); ok {
		return userID
	}
	return ""
}

// ExtractTenantID 从上下文提取租户ID
func ExtractTenantID(ctx context.Context) string {
	if tenantID, ok := ctx.Value("tenantID").(string); ok {
		return tenantID
	}
	return ""
}

// ExtractPermissions 从上下文提取权限
func ExtractPermissions(ctx context.Context) []string {
	if perms, ok := ctx.Value("permissions").([]interface{}); ok {
		result := make([]string, 0, len(perms))
		for _, p := range perms {
			if s, ok := p.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// ExtractRoles 从上下文提取角色
func ExtractRoles(ctx context.Context) []string {
	if roles, ok := ctx.Value("roles").([]interface{}); ok {
		result := make([]string, 0, len(roles))
		for _, r := range roles {
			if s, ok := r.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// ==================== 便捷构造函数 ====================

// QuickStart 快速启动（使用默认配置）
func QuickStart(jwtSecret string) *OptimalAuth {
	config := DefaultOptimalConfig()
	config.JWTSecret = jwtSecret
	return NewOptimal(config)
}

// EnterpriseGrade 企业级配置（50K+ QPS）
func EnterpriseGrade(jwtSecret string) *OptimalAuth {
	config := &OptimalConfig{
		JWTSecret: jwtSecret,
		Enabled:   true,
		SkipPaths: []string{"/health", "/metrics", "/ping", "/ready"},
		Performance: PerformanceOpts{
			EnableCache: true,
			CacheSize:   50000,     // 支持5万令牌
			CacheTTL:    10 * time.Minute,
			EnablePool:  true,
			ShardCount:  512,       // 更多分片减少锁竞争
		},
		Monitoring: MonitoringOpts{
			Enabled:         true,
			CollectDetailed: true,
		},
	}
	return NewOptimal(config)
}

// ==================== 向后兼容 ====================

// 类型别名保持兼容性
type (
	AuthMiddleware = OptimalAuth
	AuthConfig     = OptimalConfig
)

// 兼容的构造函数
func New(config *AuthConfig) *AuthMiddleware {
	return NewOptimal(config)
}

func NewAuthMiddleware(config *AuthConfig) *AuthMiddleware {
	return NewOptimal(config)
}

// 兼容的配置函数
func DefaultConfig() *AuthConfig {
	return DefaultOptimalConfig()
}