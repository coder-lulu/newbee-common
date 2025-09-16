// Copyright 2024 The NewBee Authors. All Rights Reserved.

package integration

import (
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/zeromicro/go-zero/rest"
)

// OneClickResult 一键集成结果
type OneClickResult struct {
	ContextManager *keys.ContextManager   // 上下文管理器
	Middlewares    []rest.Middleware      // 中间件链
	Manager        *framework.MiddlewareManager // 底层管理器（高级使用）
}

// 旧的OneClickSetup函数已被弃用
// 请使用统一的 integration.Setup() 函数
// 
// 迁移示例:
// 旧的: OneClickSetupWithSecret(rds, "secret")
// 新的: Setup(&Config{Redis: rds, JWTSecret: "secret", Mode: Production})
//
// 旧的: OneClickSetupMinimal(rds, "secret") 
// 新的: Setup(&Config{Redis: rds, JWTSecret: "secret", SkipPlugins: []string{"dataperm", "audit"}})
//
// 旧的: OneClickSetupForDevelopment(rds)
// 新的: Setup(&Config{Redis: rds, JWTSecret: "dev-secret", Mode: Development})

// DefaultProductionConfig 生产环境推荐配置
func DefaultProductionConfig(jwtSecret string) *framework.UnifiedConfig {
	return &framework.UnifiedConfig{
		Auth: &framework.AuthConfig{
			Enabled:      true,
			AccessSecret: jwtSecret,
			AccessExpire: 7200, // 2 hours
			SkipPaths: []string{
				"/health",
				"/metrics", 
				"/api/v1/auth/login",
				"/api/v1/auth/register",
			},
		},
		TenantCheck: &framework.TenantCheckConfig{
			Enabled:           true,
			ValidateStatus:    true,  // 生产环境验证租户状态
			CacheEnabled:      true,  // 启用缓存以提高性能
			RateLimitEnabled:  true,  // 启用租户级限流
			MaxRequestsPerMin: 1000,  // 每个租户每分钟1000请求
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/v1/auth/login", 
				"/api/v1/auth/register",
			},
		},
		DataPerm: &framework.DataPermConfig{
			Enabled:         true,
			CasbinEnabled:   true,
			CoreRpcEndpoint: "127.0.0.1:8080", // 需要根据实际情况调整
			SkipPaths: []string{
				"/health",
				"/metrics",
			},
		},
		Audit: &framework.AuditConfig{
			Enabled: true,
			SkipPaths: []string{
				"/health",
				"/metrics",
			},
		},
	}
}

// DefaultDevelopmentConfig 开发环境配置
func DefaultDevelopmentConfig() *framework.UnifiedConfig {
	return &framework.UnifiedConfig{
		Auth: &framework.AuthConfig{
			Enabled:      true,
			AccessSecret: "dev-secret-change-in-production", 
			AccessExpire: 86400, // 24 hours for development convenience
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/v1/auth/login",
				"/api/v1/auth/register",
				"/swagger/",
				"/debug/",
			},
		},
		TenantCheck: &framework.TenantCheckConfig{
			Enabled:           true,
			ValidateStatus:    false, // 开发环境不验证状态
			CacheEnabled:      false, // 开发环境不使用缓存
			RateLimitEnabled:  false, // 开发环境不限流
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/v1/auth/login",
				"/api/v1/auth/register", 
				"/swagger/",
				"/debug/",
			},
		},
		DataPerm: &framework.DataPermConfig{
			Enabled:         false, // 开发环境可选择跳过数据权限
			CasbinEnabled:   false,
			CoreRpcEndpoint: "127.0.0.1:8080",
		},
		Audit: &framework.AuditConfig{
			Enabled: false, // 开发环境通常跳过审计
		},
	}
}

// ApplyOneClickToServer 已弃用，请使用 integration.ApplyToServer()
// 
// 迁移示例:
// 旧的: ApplyOneClickToServer(server, result)  
// 新的: ApplyToServer(server, result)

// MustOneClickSetup 已弃用，请使用 integration.MustSetup()
//
// 迁移示例:
// 旧的: MustOneClickSetup(rds, "secret")
// 新的: MustSetup(&Config{Redis: rds, JWTSecret: "secret"})