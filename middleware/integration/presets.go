// Copyright 2024 The NewBee Authors. All Rights Reserved.

package integration

import "github.com/coder-lulu/newbee-common/middleware/framework"

// ProductionPreset 生产环境预设配置
func ProductionPreset(jwtSecret string) *framework.UnifiedConfig {
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
			Enabled:          true,
			WriterType:       "custom", // 默认使用custom，当有RPC提供者时会自动切换为rpc
			MaxBodySize:      1048576, // 1MB
			AsyncEnabled:     true,
			AsyncWorkers:     5,        // 生产环境更多worker
			AsyncBufferSize:  2000,     // 生产环境更大缓冲区
			SkipPaths: []string{
				"/health",
				"/metrics",
			},
		},
		Encryption: &framework.EncryptionConfig{
			Enabled:      false, // 默认关闭，可通过配置启用
			SkipPaths:    []string{"/health", "/metrics"},
			ForceEncrypt: false,
		},
	}
}

// DevelopmentPreset 开发环境预设配置
func DevelopmentPreset(jwtSecret string) *framework.UnifiedConfig {
	return &framework.UnifiedConfig{
		Auth: &framework.AuthConfig{
			Enabled:      true,
			AccessSecret: jwtSecret,
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
			Enabled:         false, // 开发环境通常跳过审计
			WriterType:      "custom",
			MaxBodySize:     1048576, // 1MB
			AsyncEnabled:    false,   // 开发环境同步写入便于调试
			AsyncWorkers:    1,
			AsyncBufferSize: 100,
		},
		Encryption: &framework.EncryptionConfig{
			Enabled:      false, // 开发环境默认关闭加密
			SkipPaths:    []string{"/health", "/metrics", "/swagger/", "/debug/"},
			ForceEncrypt: false,
		},
	}
}

// TestingPreset 测试环境预设配置
func TestingPreset(jwtSecret string) *framework.UnifiedConfig {
	return &framework.UnifiedConfig{
		Auth: &framework.AuthConfig{
			Enabled:      true,
			AccessSecret: jwtSecret,
			AccessExpire: 3600, // 1 hour
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/test/",
			},
		},
		TenantCheck: &framework.TenantCheckConfig{
			Enabled:          true,
			ValidateStatus:   false, // 测试环境不验证状态
			CacheEnabled:     false, // 测试环境不使用缓存
			RateLimitEnabled: false, // 测试环境不限流
			SkipPaths: []string{
				"/health",
				"/metrics", 
				"/test/",
			},
		},
		DataPerm: &framework.DataPermConfig{
			Enabled:         false, // 测试环境通常跳过数据权限
			CasbinEnabled:   false,
			CoreRpcEndpoint: "127.0.0.1:8080",
		},
		Audit: &framework.AuditConfig{
			Enabled:         false, // 测试环境通常跳过审计
			WriterType:      "custom",
			MaxBodySize:     1048576, // 1MB
			AsyncEnabled:    false,   // 测试环境同步写入便于验证
			AsyncWorkers:    1,
			AsyncBufferSize: 10,
		},
		Encryption: &framework.EncryptionConfig{
			Enabled:      false, // 测试环境默认关闭加密
			SkipPaths:    []string{"/health", "/metrics", "/test/"},
			ForceEncrypt: false,
		},
	}
}

// MinimalPreset 最小化配置，只包含认证和租户检查
func MinimalPreset(jwtSecret string) *framework.UnifiedConfig {
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
			Enabled:          true,
			ValidateStatus:   false, // 最小化配置，不验证状态
			CacheEnabled:     false, // 最小化配置，不使用缓存
			RateLimitEnabled: false,
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/v1/auth/login",
				"/api/v1/auth/register",
			},
		},
		// DataPerm 和 Audit 不包含，通过 SkipPlugins 控制
	}
}