// Copyright 2024 The NewBee Authors. All Rights Reserved.

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/cache"
	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/coder-lulu/newbee-common/utils/jwt"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/metadata"
)

// metadataPool provides reusable metadata maps to reduce allocations
var metadataPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]string)
	},
}

// AuthPlugin implements the framework.MiddlewarePlugin for authentication.
type AuthPlugin struct {
	core        *framework.CoreServices
	config      *framework.AuthConfig
	jwtCache    *cache.HighPerformanceJWTCache // 高性能JWT缓存
	stopCleanup chan struct{}                  // Signal to stop cache cleanup goroutine
	logger      *logging.MiddlewareLogger
}

// NewAuthPlugin creates a new instance of the authentication plugin.
func NewAuthPlugin() framework.MiddlewarePlugin {
	return &AuthPlugin{}
}

func (p *AuthPlugin) Name() string {
	return "Authentication"
}

func (p *AuthPlugin) Priority() int {
	// Auth should run early in the chain.
	return 10
}

func (p *AuthPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.config = core.Config.Auth
	p.logger = logging.AuthLogger()
	p.stopCleanup = make(chan struct{})

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("auth config is missing or disabled").
			Build()
		p.logger.WithError(err).Error("auth plugin initialization failed")
		return err
	}
	if p.config.AccessSecret == "" {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("AccessSecret is not configured for auth plugin").
			Build()
		p.logger.WithError(err).Error("auth plugin initialization failed")
		return err
	}

	// 初始化高性能JWT缓存
	maxCacheSize := int64(10000) // 默认缓存1万个token
	shardCount := 16             // 16个分片，减少锁竞争
	p.jwtCache = cache.NewHighPerformanceJWTCache(maxCacheSize, shardCount)

	// Start cache cleanup goroutine
	go p.jwtCache.StartCleanupWorker(10*time.Minute, p.stopCleanup)

	p.logger.WithField("max_cache_size", maxCacheSize).
		WithField("shard_count", shardCount).
		Info("auth plugin initialized successfully with high-performance JWT cache")

	return nil
}

// Shutdown gracefully stops the cache cleanup goroutine
func (p *AuthPlugin) Shutdown() error {
	if p.stopCleanup != nil {
		close(p.stopCleanup)
	}
	return nil
}

func (p *AuthPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		logger := p.logger.WithContext(r.Context()).WithRequest(r)

		// Check if the path should be skipped
		if p.shouldSkip(r.URL.Path) {
			logger.WithField("skipped", true).Debug("auth check skipped for path")
			next(w, r)
			return
		}

		// Extract token from header or query params
		token := p.extractToken(r)
		if token == "" {
			err := errors.NewAuthError(errors.CodeAuthTokenMissing, nil)
			logger.WithError(err).WithDuration(startTime).Error("authentication token missing")
			err.WriteHTTPResponse(w)
			return
		}

		// Parse and validate the JWT token with cache
		claims, err := p.parseJWTWithCache(token)
		if err != nil {
			authErr := errors.NewAuthError(errors.CodeAuthTokenInvalid, err)
			logger.WithError(authErr).WithDuration(startTime).Error("token validation failed")
			authErr.WriteHTTPResponse(w)
			return
		}

		// Build authentication context from claims
		ctx, err := p.core.ContextManager.SetFullAuthContext(r.Context(), claims)
		if err != nil {
			authErr := errors.NewAuthError(errors.CodeAuthUserNotFound, err)
			logger.WithError(authErr).WithDuration(startTime).Error("failed to build auth context")
			authErr.WriteHTTPResponse(w)
			return
		}

		// update logger context to include auth claims in structured fields
		logger = logger.WithContext(ctx)

		// Apply dynamic tenant override for super admin context switch
		if newCtx, applied := p.applyDynamicTenantOverride(ctx, logger); applied {
			ctx = newCtx
			logger = logger.WithContext(ctx)
		}

		// 🔍 调试：验证 context 中的值
		logger.WithField("tenant_id", p.core.ContextManager.GetTenantID(ctx)).
			WithField("user_id", p.core.ContextManager.GetUserID(ctx)).
			WithField("dept_id", p.core.ContextManager.GetDeptID(ctx)).
			WithField("role_codes", p.core.ContextManager.GetRoleCodes(ctx)).
			Info("Auth context built successfully")

		// Set gRPC metadata for downstream services (optimized)
		ctx = p.setGRPCMetadataOptimized(ctx, p.core.ContextManager)

		// Log successful authentication
		userID := p.core.ContextManager.GetUserID(ctx)
		tenantID := p.core.ContextManager.GetTenantID(ctx)
		logger.WithField("user_id", userID).
			WithField("tenant_id", tenantID).
			WithDuration(startTime).
			Info("authentication successful")

		// Authentication successful, proceed to the next handler
		next(w, r.WithContext(ctx))
	}
}

func (p *AuthPlugin) shouldSkip(path string) bool {
	for _, skipPath := range p.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (p *AuthPlugin) extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// writeUnauthorized方法已废弃，现在使用统一的错误处理
// 保留此方法仅为向后兼容，实际使用MiddlewareError.WriteHTTPResponse

// parseJWTWithCache parses JWT token with high-performance caching
func (p *AuthPlugin) parseJWTWithCache(token string) (map[string]interface{}, error) {
	// 1. 快速缓存查找 - 无锁竞争
	if claims, found := p.jwtCache.Get(token); found {
		return claims, nil
	}

	// 2. 缓存未命中，解析Token
	claims, err := jwt.ParseJwtToken(token, p.config.AccessSecret)
	if err != nil {
		return nil, err
	}

	// 3. 缓存解析结果
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt := time.Unix(int64(exp), 0)

		// 尝试缓存，如果缓存满了会自动处理
		if cached := p.jwtCache.Set(token, claims, expiresAt); !cached {
			// 缓存失败（通常是因为缓存满），记录但不影响功能
			p.logger.WithField("cache_size", p.jwtCache.Size()).
				Warn("JWT cache is full, token not cached")
		}
	}

	return claims, nil
}

// applyDynamicTenantOverride checks whether the current user has a temporary tenant override
// (set via the admin tenant switch API) and, if so, overwrites the tenant ID in the context.
func (p *AuthPlugin) applyDynamicTenantOverride(ctx context.Context, logger *logging.MiddlewareLogger) (context.Context, bool) {
	if p.core.Redis == nil {
		return ctx, false
	}

	cm := p.core.ContextManager
	userID := strings.TrimSpace(cm.GetUserID(ctx))
	if userID == "" {
		return ctx, false
	}

	currentTenant := strings.TrimSpace(cm.GetTenantID(ctx))
	originalTenant := strings.TrimSpace(cm.GetOriginalTenantID(ctx))
	overrideKey := fmt.Sprintf("admin:tenant:%s", userID)
	tenantFromRedis, err := p.core.Redis.Get(ctx, overrideKey).Result()
	if err != nil {
		if err != redis.Nil {
			logger.WithError(err).
				WithField("override_key", overrideKey).
				Warn("failed to load tenant override from Redis")
		}
		return ctx, false
	}

	overrideTenant := strings.TrimSpace(tenantFromRedis)
	if overrideTenant == "" || overrideTenant == currentTenant {
		return ctx, false
	}

	newCtx := ctx
	if originalTenant == "" && currentTenant != "" && currentTenant != "0" {
		newCtx = cm.SetOriginalTenantID(newCtx, currentTenant)
		originalTenant = currentTenant
	}

	newCtx = cm.SetTenantID(newCtx, overrideTenant)
	logger.WithField("override_key", overrideKey).
		WithField("previous_tenant_id", currentTenant).
		WithField("original_tenant_id", originalTenant).
		WithField("override_tenant_id", overrideTenant).
		Info("dynamic tenant override applied")

	return newCtx, true
}

// setGRPCMetadataOptimized sets gRPC metadata with memory optimization
func (p *AuthPlugin) setGRPCMetadataOptimized(ctx context.Context, cm *keys.ContextManager) context.Context {
	// Get reusable map from pool
	md := metadataPool.Get().(map[string]string)
	defer metadataPool.Put(md)

	// Clear map for reuse (ensure clean state)
	for k := range md {
		delete(md, k)
	}

	// Set metadata using common package standard keys for consistency
	md[string(keys.TenantIDKey)] = cm.GetTenantID(ctx)
	if originalTenant := cm.GetOriginalTenantID(ctx); originalTenant != "" {
		md[string(keys.OriginalTenantIDKey)] = originalTenant
	}
	md[string(keys.UserIDKey)] = cm.GetUserID(ctx)
	md[string(keys.DeptIDKey)] = cm.GetDeptID(ctx)
	md[string(keys.DataScopeKey)] = cm.GetDataScope(ctx)

	// 添加角色代码传递
	roleCodes := cm.GetRoleCodes(ctx)
	if roleCodes != "" {
		md[string(keys.RoleCodesKey)] = roleCodes
	}

	// 调试：记录所有metadata值
	p.logger.WithField("tenant_id", md[string(keys.TenantIDKey)]).
		WithField("original_tenant_id", md[string(keys.OriginalTenantIDKey)]).
		WithField("user_id", md[string(keys.UserIDKey)]).
		WithField("dept_id", md[string(keys.DeptIDKey)]).
		WithField("role_codes", roleCodes).
		WithField("data_scope", md[string(keys.DataScopeKey)]).
		Info("🚀 Auth Plugin setting gRPC metadata")

	// Create new outgoing context with all metadata at once
	newCtx := metadata.NewOutgoingContext(ctx, metadata.New(md))

	// 验证 metadata 是否设置成功
	if testMD, ok := metadata.FromOutgoingContext(newCtx); ok {
		p.logger.WithField("metadata_keys", len(testMD)).
			WithField("has_rolecodes", len(testMD.Get(string(keys.RoleCodesKey))) > 0).
			Info("✅ gRPC metadata created successfully")
	}

	return newCtx
}
