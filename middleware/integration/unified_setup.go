// Copyright 2024 The NewBee Authors. All Rights Reserved.

package integration

import (
	"context"
	"fmt"

	"github.com/coder-lulu/newbee-common/middleware/audit"
	"github.com/coder-lulu/newbee-common/middleware/auth"
	"github.com/coder-lulu/newbee-common/middleware/dataperm"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/tenant"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest"
)

// Mode 环境模式枚举
type Mode string

const (
	Production  Mode = "production"  // 生产环境
	Development Mode = "development" // 开发环境
	Testing     Mode = "testing"     // 测试环境
)

// Config 统一的中间件集成配置
type Config struct {
	// 必需参数
	Redis     redis.UniversalClient `json:"-"` // Redis客户端 (运行时注入)
	JWTSecret string                 `json:"jwt_secret"`

	// 环境模式 (可选，默认为Production)
	Mode Mode `json:"mode,optional,default=production"`

	// 服务类型标识 (可选，用于智能选择审计写入器)
	IsCore bool `json:"is_core,optional,default=false"` // 是否为Core服务

	// 插件控制 (可选)
	Plugins     []string `json:"plugins,optional"`      // 启用的插件列表，为空则启用所有
	SkipPlugins []string `json:"skip_plugins,optional"` // 跳过的插件列表

	// 高级配置 (可选，优先级高于Mode预设)
	Middleware *framework.UnifiedConfig `json:"middleware,optional"` // 详细的中间件配置

	// 其他可选配置
	ApiResourceProvider framework.ApiResourceProvider `json:"-"` // API资源提供者 (运行时注入)
	AuditWriter         framework.AuditWriter         `json:"-"` // 自定义审计写入器 (运行时注入)
}

// Result 统一的集成结果
type Result struct {
	ContextManager *keys.ContextManager      // 上下文管理器
	Middlewares    []rest.Middleware         // 中间件链
	Manager        *framework.MiddlewareManager // 底层管理器（高级使用）
}

// Setup 统一的中间件集成函数
// 这是NewBee中间件框架的唯一标准集成入口
func Setup(config *Config) (*Result, error) {
	// 参数验证
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if config.Redis == nil {
		return nil, fmt.Errorf("Redis client cannot be nil")
	}
	if config.JWTSecret == "" {
		return nil, fmt.Errorf("JWT secret cannot be empty")
	}

	// 获取中间件配置
	var middlewareConfig *framework.UnifiedConfig
	if config.Middleware != nil {
		// 使用用户提供的详细配置
		middlewareConfig = config.Middleware
	} else {
		// 根据模式生成预设配置
		var err error
		middlewareConfig, err = generatePresetConfig(config.Mode, config.JWTSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to generate preset config: %w", err)
		}
	}

	// 创建API资源提供器
	apiResourceProvider := config.ApiResourceProvider
	if apiResourceProvider == nil {
		apiResourceProvider = &DefaultApiResourceProvider{}
	}

	// 使用智能工厂创建审计写入器
	factory := &SmartAuditWriterFactory{}
	auditWriter := factory.CreateWriter(config, config.IsCore)

	// 创建中间件管理器
	manager, err := framework.NewManager(middlewareConfig, context.Background(), config.Redis, auditWriter, apiResourceProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create middleware manager: %w", err)
	}

	// 注册插件
	if err := registerPlugins(manager, middlewareConfig, config); err != nil {
		return nil, fmt.Errorf("failed to register plugins: %w", err)
	}

	return &Result{
		ContextManager: manager.GetCoreServices().ContextManager,
		Middlewares:    manager.BuildChain(),
		Manager:        manager,
	}, nil
}

// MustSetup Setup的必须成功版本，失败时panic
func MustSetup(config *Config) *Result {
	result, err := Setup(config)
	if err != nil {
		panic(fmt.Sprintf("middleware setup failed: %v", err))
	}
	return result
}

// ApplyToServer 将中间件链应用到go-zero服务器
func ApplyToServer(server *rest.Server, result *Result) {
	for _, middleware := range result.Middlewares {
		server.Use(middleware)
	}
}

// DefaultApiResourceProvider 默认的API资源提供器
type DefaultApiResourceProvider struct{}

func (p *DefaultApiResourceProvider) GetApiResourceName(ctx context.Context, method, path string) (string, error) {
	return fmt.Sprintf("%s:%s", method, path), nil
}

// NoOpAuditWriter 无操作审计写入器，用于测试和开发环境
type NoOpAuditWriter struct{}

func (n *NoOpAuditWriter) WriteAuditLog(ctx context.Context, auditData framework.AuditLogData) error {
	// 只记录日志，不实际写入任何存储
	logx.WithContext(ctx).Infow("Audit log (NoOp mode)",
		logx.Field("tenant_id", auditData.TenantID),
		logx.Field("user_id", auditData.UserID),
		logx.Field("method", auditData.Method),
		logx.Field("path", auditData.Path),
		logx.Field("status_code", auditData.StatusCode),
		logx.Field("duration_ms", auditData.DurationMs))
	return nil
}

// SmartAuditWriterFactory 智能审计写入器工厂
// 根据服务类型和配置自动选择最佳的审计写入器
type SmartAuditWriterFactory struct{}

// CreateWriter 创建合适的审计写入器
func (f *SmartAuditWriterFactory) CreateWriter(config *Config, isCore bool) framework.AuditWriter {
	// 1. 优先使用用户提供的自定义写入器
	if config.AuditWriter != nil {
		logx.Info("Using provided custom audit writer")
		return config.AuditWriter
	}
	
	// 2. 根据服务类型选择
	if isCore {
		// Core服务使用NoOp写入器避免循环调用
		logx.Info("Core service detected, using NoOp audit writer to prevent circular calls")
		return &NoOpAuditWriter{}
	}
	
	// 3. 检查模式配置
	switch config.Mode {
	case Development, Testing:
		logx.Info("Development/Testing mode detected, using NoOp audit writer")
		return &NoOpAuditWriter{}
	default:
		// 生产环境，让审计插件自己处理写入器选择
		logx.Info("Production mode, audit writer will be auto-detected by plugin")
		return nil
	}
}

// DetectServiceType 检测服务类型
func DetectServiceType() bool {
	// 通过环境变量或其他方式检测是否为Core服务
	// 可以根据实际需要扩展检测逻辑
	return false // 默认不是Core服务
}

// generatePresetConfig 根据模式生成预设配置
func generatePresetConfig(mode Mode, jwtSecret string) (*framework.UnifiedConfig, error) {
	switch mode {
	case Production:
		return ProductionPreset(jwtSecret), nil
	case Development:
		return DevelopmentPreset(jwtSecret), nil
	case Testing:
		return TestingPreset(jwtSecret), nil
	default:
		return nil, fmt.Errorf("unknown mode: %s", mode)
	}
}

// registerPlugins 根据配置注册插件
func registerPlugins(manager *framework.MiddlewareManager, middlewareConfig *framework.UnifiedConfig, config *Config) error {
	// 获取应该启用的插件列表
	enabledPlugins := getEnabledPlugins(config.Plugins, config.SkipPlugins)
	
	// 根据具体配置进一步过滤插件
	actualEnabledPlugins := filterByPluginConfig(enabledPlugins, middlewareConfig)
	
	// 创建插件实例
	var plugins []framework.MiddlewarePlugin
	
	for _, pluginName := range actualEnabledPlugins {
		switch pluginName {
		case "auth":
			plugins = append(plugins, auth.NewAuthPlugin())
		case "tenant":
			plugins = append(plugins, tenant.NewTenantCheckPlugin())
		case "dataperm":
			plugins = append(plugins, dataperm.NewDataPermPlugin())
		case "audit":
			// 使用简化的构造函数，依赖通过Init方法注入
			if config.AuditWriter != nil {
				// 使用注入的自定义审计写入器
				plugins = append(plugins, audit.NewAuditPluginWithWriter(config.AuditWriter))
			} else {
				// 使用默认配置，具体写入器通过配置决定
				plugins = append(plugins, audit.NewAuditPlugin())
			}
		default:
			return fmt.Errorf("unknown plugin: %s", pluginName)
		}
	}
	
	return manager.Register(plugins...)
}

// filterByPluginConfig 根据具体插件配置过滤启用的插件
func filterByPluginConfig(plugins []string, config *framework.UnifiedConfig) []string {
	var filtered []string
	
	for _, plugin := range plugins {
		switch plugin {
		case "auth":
			if config.Auth != nil && config.Auth.Enabled {
				filtered = append(filtered, plugin)
			}
		case "tenant":
			if config.TenantCheck != nil && config.TenantCheck.Enabled {
				filtered = append(filtered, plugin)
			}
		case "dataperm":
			if config.DataPerm != nil && config.DataPerm.Enabled {
				filtered = append(filtered, plugin)
			}
		case "audit":
			if config.Audit != nil && config.Audit.Enabled {
				filtered = append(filtered, plugin)
			}
		}
	}
	
	return filtered
}

// getEnabledPlugins 根据配置决定启用哪些插件
func getEnabledPlugins(plugins, skipPlugins []string) []string {
	allPlugins := []string{"auth", "tenant", "dataperm", "audit"}
	
	// 如果指定了具体的插件列表，使用该列表
	if len(plugins) > 0 {
		return filterSkippedPlugins(plugins, skipPlugins)
	}
	
	// 否则使用所有插件，但排除跳过的插件
	return filterSkippedPlugins(allPlugins, skipPlugins)
}

// filterSkippedPlugins 过滤掉跳过的插件
func filterSkippedPlugins(plugins, skipPlugins []string) []string {
	if len(skipPlugins) == 0 {
		return plugins
	}
	
	var result []string
	for _, plugin := range plugins {
		skip := false
		for _, skipPlugin := range skipPlugins {
			if plugin == skipPlugin {
				skip = true
				break
			}
		}
		if !skip {
			result = append(result, plugin)
		}
	}
	return result
}

