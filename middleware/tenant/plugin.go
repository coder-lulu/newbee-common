// Copyright 2024 The NewBee Authors. All Rights Reserved.

package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/cache"
	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/redis/go-redis/v9"
)

// TenantCheckPlugin enforces that a valid tenant ID exists in the request context.
// It relies on the AuthPlugin to have already populated the context with tenant info.
type TenantCheckPlugin struct {
	core           *framework.CoreServices
	config         *framework.TenantCheckConfig
	logger         *logging.MiddlewareLogger
	highPerfRedis  *cache.HighPerformanceRedisClient // 高性能Redis客户端
	tenantProvider framework.TenantInfoProvider
}

// NewTenantCheckPlugin creates a new instance of the tenant check plugin.
func NewTenantCheckPlugin() framework.MiddlewarePlugin {
	return &TenantCheckPlugin{}
}

func (p *TenantCheckPlugin) Name() string {
	return "TenantCheck"
}

func (p *TenantCheckPlugin) Priority() int {
	// Run after Auth (10) but before DataPerm (20).
	return 15
}

func (p *TenantCheckPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.config = core.Config.TenantCheck
	p.logger = logging.TenantLogger()
	p.tenantProvider = core.TenantProvider

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("tenantcheck config is missing or disabled").
			Build()
		p.logger.WithError(err).Error("tenant plugin initialization failed")
		return err
	}

	if p.config.ValidateStatus && p.tenantProvider == nil {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("tenant status validation enabled but tenant provider not configured").
			Build()
		p.logger.WithError(err).Error("tenant plugin initialization failed")
		return err
	}

	// 初始化高性能Redis客户端
	if core.Redis != nil {
		// 类型断言将redis.Cmdable转换为redis.UniversalClient
		if universalClient, ok := core.Redis.(redis.UniversalClient); ok {
			p.highPerfRedis = cache.NewHighPerformanceRedisClient(universalClient)
			p.logger.Info("high-performance Redis client initialized")
		} else {
			p.logger.Warn("Redis client is not UniversalClient, high-performance features disabled")
		}
	}

	p.logger.Info("tenant plugin initialized successfully")
	return nil
}

func (p *TenantCheckPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		logger := p.logger.WithContext(r.Context()).WithRequest(r)

		// Check if the path should be skipped
		if p.shouldSkip(r.URL.Path) {
			logger.WithField("skipped", true).Debug("tenant check skipped for path")
			next(w, r)
			return
		}

		ctx := r.Context()
		cm := p.core.ContextManager

		// Retrieve and normalize tenant ID from the context set by AuthPlugin.
		tenantID := strings.TrimSpace(cm.GetTenantID(ctx))

		if tenantID == "" || tenantID == "0" {
			// This is a critical security failure. A request to a protected endpoint
			// has passed authentication but lacks tenant information.
			err := errors.NewTenantError(errors.CodeTenantMissing, "")
			logger.WithError(err).
				WithField("tenant_id", tenantID).
				WithDuration(startTime).
				Error("invalid tenant ID in context after authentication")
			err.WriteHTTPResponse(w)
			return
		}

		// Enhanced tenant validation
		if p.config.ValidateStatus {
			if err := p.validateTenantStatus(ctx, tenantID); err != nil {
				tenantErr := errors.NewTenantError(errors.CodeTenantInactive, tenantID)
				logger.WithError(tenantErr).WithField("tenant_id", tenantID).WithDuration(startTime).Error("tenant status validation failed")
				tenantErr.WriteHTTPResponse(w)
				return
			}
		}

		// Rate limiting check
		if p.config.RateLimitEnabled && p.core.Redis != nil {
			if !p.checkRateLimit(ctx, tenantID) {
				rateLimitErr := errors.NewRateLimitError(errors.CodeRateLimitExceeded, p.config.MaxRequestsPerMin, "1 minute")
				logger.WithError(rateLimitErr).WithField("tenant_id", tenantID).WithDuration(startTime).Error("rate limit exceeded for tenant")
				w.Header().Set("Retry-After", "60")
				rateLimitErr.WriteHTTPResponse(w)
				return
			}
		}

		logger.WithField("tenant_id", tenantID).WithDuration(startTime).Debug("tenant check passed")

		// Tenant check passed, proceed to the next handler.
		next(w, r.WithContext(ctx))
	}
}

func (p *TenantCheckPlugin) shouldSkip(path string) bool {
	for _, skipPath := range p.config.SkipPaths {
		normalized := strings.TrimSpace(skipPath)
		if normalized == "" {
			continue
		}

		if strings.HasSuffix(normalized, "*") {
			prefix := strings.TrimSuffix(normalized, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}

		if path == normalized {
			return true
		}
	}
	return false
}

// validateTenantStatus checks if the tenant is active using Redis cache
func (p *TenantCheckPlugin) validateTenantStatus(ctx context.Context, tenantID string) error {
	tenantInfo, err := p.getTenantInfo(ctx, tenantID)
	if err != nil {
		// If we cannot get tenant info, we log the error but don't fail the request
		// This provides graceful degradation when Redis is unavailable
		p.logger.WithContext(ctx).WithField("tenant_id", tenantID).WithError(err).Warn("failed to get tenant info, allowing request")
		return nil
	}

	if tenantInfo.Status != framework.TenantStatusActive {
		return fmt.Errorf("tenant %s status is %s", tenantID, tenantInfo.Status)
	}

	return nil
}

// getTenantInfo retrieves tenant information with Redis caching
func (p *TenantCheckPlugin) getTenantInfo(ctx context.Context, tenantID string) (*framework.TenantInfo, error) {
	if !p.config.CacheEnabled || p.core.Redis == nil {
		return p.fetchTenantInfoFromProvider(ctx, tenantID)
	}

	// Try to get from Redis cache first
	cacheKey := fmt.Sprintf("tenant_info:%s", tenantID)
	result, err := p.core.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var tenantInfo framework.TenantInfo
		if err = json.Unmarshal([]byte(result), &tenantInfo); err == nil {
			// Check if cache entry is not too old (5 minutes TTL)
			if time.Since(tenantInfo.UpdatedAt) < 5*time.Minute {
				return &tenantInfo, nil
			}
		}
	}

	// Cache miss or expired, fetch from database
	tenantInfo, err := p.fetchTenantInfoFromProvider(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Update cache
	tenantInfo.UpdatedAt = time.Now()
	if data, err := json.Marshal(tenantInfo); err == nil {
		// Cache for 5 minutes, ignore error as cache is not critical
		p.core.Redis.Set(ctx, cacheKey, data, 5*time.Minute).Result()
	}

	return tenantInfo, nil
}

// fetchTenantInfoFromProvider fetches tenant info using the configured provider
func (p *TenantCheckPlugin) fetchTenantInfoFromProvider(ctx context.Context, tenantID string) (*framework.TenantInfo, error) {
	if p.tenantProvider == nil {
		return nil, fmt.Errorf("tenant provider not configured")
	}

	info, err := p.tenantProvider.GetTenantInfo(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if info == nil {
		return nil, fmt.Errorf("tenant provider returned nil info for %s", tenantID)
	}

	if info.ID == "" {
		info.ID = tenantID
	}

	return info, nil
}

// checkRateLimit implements a high-performance sliding window rate limiter using Lua scripts
func (p *TenantCheckPlugin) checkRateLimit(ctx context.Context, tenantID string) bool {
	if p.highPerfRedis == nil {
		// 默认允许（如果Redis不可用）
		p.logger.WithContext(ctx).WithField("tenant_id", tenantID).Warn("high-performance Redis not available, allowing request")
		return true
	}

	// Create a rate limit key for this tenant
	rateLimitKey := fmt.Sprintf("rate_limit:%s", tenantID)

	// 使用高性能Lua脚本进行限流检查
	result, err := p.highPerfRedis.SlidingWindowRateLimit(ctx, rateLimitKey, p.config.MaxRequestsPerMin, time.Minute)
	if err != nil {
		// If Redis fails, we allow the request (graceful degradation)
		p.logger.WithContext(ctx).WithField("tenant_id", tenantID).WithError(err).Warn("rate limit check failed, allowing request")
		return true
	}

	// 记录限流统计信息
	if !result.Allowed {
		p.logger.WithContext(ctx).
			WithField("tenant_id", tenantID).
			WithField("remaining", result.Remaining).
			WithField("reset_time", result.ResetTime).
			Warn("rate limit exceeded")
	} else {
		p.logger.WithContext(ctx).
			WithField("tenant_id", tenantID).
			WithField("remaining", result.Remaining).
			Debug("rate limit check passed")
	}

	return result.Allowed
}

// Shutdown implements the ShutdownablePlugin interface for graceful shutdown
func (p *TenantCheckPlugin) Shutdown() error {
	if p.highPerfRedis != nil {
		// 关闭高性能Redis客户端连接
		p.logger.Info("shutting down high-performance Redis client")
		if err := p.highPerfRedis.Close(); err != nil {
			p.logger.WithError(err).Error("failed to close high-performance Redis client")
			return err
		}
	}

	p.logger.Info("tenant plugin shutdown completed")
	return nil
}
