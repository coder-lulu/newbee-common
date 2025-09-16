// Copyright 2024 The NewBee Authors. All Rights Reserved.

package auth

import (
	"context"
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
	core         *framework.CoreServices
	config       *framework.AuthConfig
	jwtCache     *cache.HighPerformanceJWTCache // 高性能JWT缓存
	stopCleanup  chan struct{}                  // Signal to stop cache cleanup goroutine
	logger       *logging.MiddlewareLogger
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
	shardCount := 16            // 16个分片，减少锁竞争
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
	md[string(keys.UserIDKey)] = cm.GetUserID(ctx)
	md[string(keys.DeptIDKey)] = cm.GetDeptID(ctx)
	md[string(keys.DataScopeKey)] = cm.GetDataScope(ctx)
	
	// Create new outgoing context with all metadata at once
	return metadata.NewOutgoingContext(ctx, metadata.New(md))
}
