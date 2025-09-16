package tenant

import (
	"context"
	"time"
)

// TenantInitPlugin 租户初始化插件接口
// 所有参与租户初始化的插件都必须实现此接口
type TenantInitPlugin interface {
	// GetMetadata 获取插件元数据
	GetMetadata() PluginMetadata
	
	// Initialize 执行租户初始化
	Initialize(ctx context.Context, req *InitRequest) error
	
	// IsInitialized 检查指定租户是否已经被此插件初始化
	IsInitialized(ctx context.Context, tenantID uint64) (bool, error)
	
	// Rollback 回滚租户初始化（清理此插件创建的数据）
	Rollback(ctx context.Context, tenantID uint64) error
	
	// HealthCheck 健康检查，确保插件可以正常工作
	HealthCheck(ctx context.Context) error
}

// PluginMetadata 插件元数据
type PluginMetadata struct {
	// 插件名称（唯一标识符）
	Name string `json:"name"`
	
	// 插件版本
	Version string `json:"version"`
	
	// 依赖的其他插件列表
	Dependencies []string `json:"dependencies"`
	
	// 执行优先级（数值越小越优先执行）
	Priority int `json:"priority"`
	
	// 插件描述
	Description string `json:"description"`
	
	// 插件类型（core, microservice, custom等）
	Type PluginType `json:"type"`
	
	// 预估执行时间（用于超时控制）
	EstimatedDuration time.Duration `json:"estimated_duration"`
	
	// 是否支持回滚
	SupportRollback bool `json:"support_rollback"`
	
	// 是否可以并行执行
	Concurrent bool `json:"concurrent"`
}

// PluginType 插件类型
type PluginType string

const (
	PluginTypeCore         PluginType = "core"         // 核心插件
	PluginTypeMicroservice PluginType = "microservice" // 微服务插件
	PluginTypeCustom       PluginType = "custom"       // 自定义插件
	PluginTypeExternal     PluginType = "external"     // 外部系统插件
)

// InitRequest 租户初始化请求
type InitRequest struct {
	// 租户ID
	TenantID uint64 `json:"tenant_id"`
	
	// 管理员用户名
	AdminUsername *string `json:"admin_username,omitempty"`
	
	// 管理员密码
	AdminPassword *string `json:"admin_password,omitempty"`
	
	// 管理员邮箱
	AdminEmail *string `json:"admin_email,omitempty"`
	
	// 租户配置参数
	Config map[string]any `json:"config,omitempty"`
	
	// 请求上下文信息
	RequestID string `json:"request_id"`
	
	// 初始化模式（full, partial, repair等）
	Mode InitMode `json:"mode"`
	
	// 是否为测试模式
	DryRun bool `json:"dry_run"`
	
	// 超时设置
	Timeout time.Duration `json:"timeout,omitempty"`
}

// InitMode 初始化模式
type InitMode string

const (
	InitModeFull    InitMode = "full"    // 完整初始化
	InitModePartial InitMode = "partial" // 部分初始化
	InitModeRepair  InitMode = "repair"  // 修复模式
	InitModeUpgrade InitMode = "upgrade" // 升级模式
)

// InitResponse 初始化响应
type InitResponse struct {
	// 插件名称
	PluginName string `json:"plugin_name"`
	
	// 执行状态
	Status InitStatus `json:"status"`
	
	// 执行结果消息
	Message string `json:"message"`
	
	// 执行时间
	Duration time.Duration `json:"duration"`
	
	// 错误信息
	Error string `json:"error,omitempty"`
	
	// 创建的资源信息
	CreatedResources []string `json:"created_resources,omitempty"`
	
	// 元数据
	Metadata map[string]any `json:"metadata,omitempty"`
}

// InitStatus 初始化状态
type InitStatus string

const (
	StatusPending    InitStatus = "pending"     // 等待执行
	StatusRunning    InitStatus = "running"     // 正在执行
	StatusSuccess    InitStatus = "success"     // 执行成功
	StatusFailed     InitStatus = "failed"      // 执行失败
	StatusSkipped    InitStatus = "skipped"     // 跳过执行
	StatusTimeout    InitStatus = "timeout"     // 执行超时
	StatusRolledback InitStatus = "rolledback"  // 已回滚
)

// PluginFactory 插件工厂接口
type PluginFactory interface {
	// CreatePlugin 创建插件实例
	CreatePlugin(config map[string]any) (TenantInitPlugin, error)
	
	// GetPluginType 获取插件类型
	GetPluginType() PluginType
	
	// ValidateConfig 验证插件配置
	ValidateConfig(config map[string]any) error
}

// PluginRegistry 插件注册表接口
type PluginRegistry interface {
	// RegisterPlugin 注册插件
	RegisterPlugin(name string, factory PluginFactory) error
	
	// UnregisterPlugin 注销插件
	UnregisterPlugin(name string) error
	
	// GetPlugin 获取插件
	GetPlugin(name string) (TenantInitPlugin, error)
	
	// ListPlugins 列出所有已注册的插件
	ListPlugins() map[string]PluginMetadata
	
	// ValidatePlugins 验证插件配置和依赖关系
	ValidatePlugins() error
}