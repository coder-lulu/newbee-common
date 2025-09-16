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

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
)

// TenantInfo represents basic tenant information for validation
type TenantInfo struct {
	ID        string       `json:"id"`
	Status    TenantStatus `json:"status"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// TenantCheckPlugin enforces that a valid tenant ID exists in the request context.
// It relies on the AuthPlugin to have already populated the context with tenant info.
type TenantCheckPlugin struct {
	core          *framework.CoreServices
	config        *framework.TenantCheckConfig
	logger        *logging.MiddlewareLogger
	highPerfRedis *cache.HighPerformanceRedisClient // 高性能Redis客户端
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

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("tenantcheck config is missing or disabled").
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

		// Retrieve tenant ID from the context set by AuthPlugin.
		tenantID := cm.GetTenantID(ctx)

		if tenantID == "" {
			// This is a critical security failure. A request to a protected endpoint
			// has passed authentication but lacks tenant information.
			err := errors.NewTenantError(errors.CodeTenantMissing, "")
			logger.WithError(err).WithDuration(startTime).Error("missing tenant ID in context after authentication")
			err.WriteHTTPResponse(w)
			return
		}

		// Enhanced tenant validation
		if p.config.ValidateStatus && p.core.Redis != nil {
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

		logger.WithField("tenant_id", tenantID).WithDuration(startTime).Info("tenant check passed")

		// Tenant check passed, proceed to the next handler.
		next(w, r.WithContext(ctx))
	}
}

func (p *TenantCheckPlugin) shouldSkip(path string) bool {
	for _, skipPath := range p.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
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

	if tenantInfo.Status != TenantStatusActive {
		return fmt.Errorf("tenant %s status is %s", tenantID, tenantInfo.Status)
	}

	return nil
}

// getTenantInfo retrieves tenant information with Redis caching
func (p *TenantCheckPlugin) getTenantInfo(ctx context.Context, tenantID string) (*TenantInfo, error) {
	if !p.config.CacheEnabled {
		return p.fetchTenantInfoFromDatabase(ctx, tenantID)
	}

	// Try to get from Redis cache first
	cacheKey := fmt.Sprintf("tenant_info:%s", tenantID)
	result, err := p.core.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var tenantInfo TenantInfo
		if err := json.Unmarshal([]byte(result), &tenantInfo); err == nil {
			// Check if cache entry is not too old (5 minutes TTL)
			if time.Since(tenantInfo.UpdatedAt) < 5*time.Minute {
				return &tenantInfo, nil
			}
		}
	}

	// Cache miss or expired, fetch from database
	tenantInfo, err := p.fetchTenantInfoFromDatabase(ctx, tenantID)
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

// fetchTenantInfoFromDatabase fetches tenant info from database (placeholder implementation)
// In a real implementation, this would query the tenant table
func (p *TenantCheckPlugin) fetchTenantInfoFromDatabase(ctx context.Context, tenantID string) (*TenantInfo, error) {
	// TODO: Replace this with actual database query
	// For now, we assume all tenants are active if we reach this point
	// This provides backward compatibility
	return &TenantInfo{
		ID:        tenantID,
		Status:    TenantStatusActive,
		UpdatedAt: time.Now(),
	}, nil
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
