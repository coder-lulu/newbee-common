// Copyright 2024 The NewBee Authors. All Rights Reserved.

package integration

import (
	"context"
	"fmt"

	"github.com/coder-lulu/newbee-common/i18n"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/rest"
)

// StandardServiceContext 标准服务上下文接口
// 所有服务的ServiceContext都应该实现此接口
type StandardServiceContext interface {
	GetContextManager() *keys.ContextManager
	GetManagedMiddlewareChain() []rest.Middleware
	GetTranslator() *i18n.Translator
}

// QuickSetupConfig 快速集成配置
type QuickSetupConfig struct {
	// 基本配置
	MiddlewareConfig *framework.UnifiedConfig
	RedisClient      redis.UniversalClient
	I18nConfig       *i18n.Conf
	I18nFS           interface{} // embed.FS

	// 可选配置
	AuditWriter         framework.AuditWriter         // 可选：自定义审计写入器
	ApiResourceProvider framework.ApiResourceProvider // 可选：自定义API资源提供器
	
	// 高级配置
	SkipPlugins         []string // 跳过的插件列表：["auth", "tenant", "dataperm", "audit"]
	CustomPlugins       []framework.MiddlewarePlugin // 自定义插件
}

// QuickSetupResult 快速集成结果
type QuickSetupResult struct {
	ContextManager         *keys.ContextManager
	ManagedMiddlewareChain []rest.Middleware
	Translator             *i18n.Translator
	Manager                *framework.MiddlewareManager
}

// QuickSetup 已弃用，请使用统一的 integration.Setup() 函数
// 
// 迁移示例:
// 旧的: QuickSetup(&QuickSetupConfig{MiddlewareConfig: config, RedisClient: rds})
// 新的: Setup(&Config{Redis: rds, JWTSecret: "secret", Middleware: config})

// SimpleApiResourceProvider 简单API资源提供器实现
type SimpleApiResourceProvider struct{}

func (p *SimpleApiResourceProvider) GetApiResourceName(ctx context.Context, method, path string) (string, error) {
	return fmt.Sprintf("%s:%s", method, path), nil
}

// contains 检查字符串切片是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ApplyToServer 已移动到 unified_setup.go，请使用 integration.ApplyToServer()

// CreateStandardServiceContext 已弃用，请直接使用 integration.Setup() 
// 
// 迁移示例:
// 旧的: CreateStandardServiceContext(config, quickSetupConfig, fields)
// 新的: Setup(&Config{Redis: rds, JWTSecret: "secret", ...})

// StandardContextWrapper 标准上下文包装器
type StandardContextWrapper struct {
	contextManager         *keys.ContextManager
	managedMiddlewareChain []rest.Middleware
	translator             *i18n.Translator
	additionalFields       map[string]interface{}
}

func (s *StandardContextWrapper) GetContextManager() *keys.ContextManager {
	return s.contextManager
}

func (s *StandardContextWrapper) GetManagedMiddlewareChain() []rest.Middleware {
	return s.managedMiddlewareChain
}

func (s *StandardContextWrapper) GetTranslator() *i18n.Translator {
	return s.translator
}

func (s *StandardContextWrapper) GetAdditionalField(key string) interface{} {
	return s.additionalFields[key]
}