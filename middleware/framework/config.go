// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

type UnifiedConfig struct {
	Auth        *AuthConfig        `json:"auth,optional"`
	Audit       *AuditConfig       `json:"audit,optional"`
	TenantCheck *TenantCheckConfig `json:"tenantCheck,optional"`
	DataPerm    *DataPermConfig    `json:"dataPerm,optional"`
	Permission  *PermissionConfig  `json:"permission,optional"`
	Encryption  *EncryptionConfig  `json:"encryption,optional"`
}

// AuthConfig defines the configuration for the Authentication plugin.
type AuthConfig struct {
	Enabled      bool     `json:"enabled,optional"`
	AccessSecret string   `json:"accessSecret,optional"`
	AccessExpire int64    `json:"accessExpire,optional"`
	SkipPaths    []string `json:"skipPaths,optional"`
}

// AuditConfig defines the unified configuration for the Audit plugin.
type AuditConfig struct {
	// 基础配置
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skipPaths,optional"`

	// 写入器配置 - 支持RPC/DB/Custom写入方式
	WriterType string `json:"writerType,optional,options=rpc|db|custom,default=rpc"` // rpc, db, custom

	// 高级选项
	MaxBodySize         int64  `json:"maxBodySize,optional,default=1048576"`  // 1MB 请求体最大大小
	AsyncEnabled        bool   `json:"asyncEnabled,optional,default=true"`    // 启用异步写入
	AsyncWorkers        int    `json:"asyncWorkers,optional,default=3"`       // 异步工作者数量
	AsyncBufferSize     int    `json:"asyncBufferSize,optional,default=1000"` // 异步缓冲区大小
	CaptureResponseBody bool   `json:"captureResponseBody,optional,default=true"`
	RealIPHeader        string `json:"realIpHeader,optional"`
}

// AuditRuntimeConfig holds runtime-injected dependencies for audit plugin
type AuditRuntimeConfig struct {
	RpcProvider  interface{} // RPC客户端提供者 (运行时注入)
	CustomWriter interface{} // 自定义写入器 (运行时注入)
}

// TenantCheckConfig defines the configuration for the TenantCheck plugin.
type TenantCheckConfig struct {
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skipPaths,optional"`

	// Enhanced validation options - backward compatible
	ValidateStatus bool `json:"validateStatus,optional,default=true"` // Check tenant active/suspended status
	CacheEnabled   bool `json:"cacheEnabled,optional,default=true"`   // Enable Redis caching for tenant info

	// Rate limiting options - disabled by default for backward compatibility
	RateLimitEnabled  bool `json:"rateLimitEnabled,optional,default=false"` // Enable rate limiting per tenant
	MaxRequestsPerMin int  `json:"maxRequestsPerMin,optional,default=1000"` // Max requests per minute per tenant
}

// DataPermConfig defines the configuration for the Data Permission plugin.
type DataPermConfig struct {
	// 基础配置
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skipPaths,optional"`

	// 🔥 核心Casbin集成配置
	CasbinEnabled   bool   `json:"casbinEnabled,default=true"`
	CoreRpcEndpoint string `json:"coreRpcEndpoint,default=127.0.0.1:8080"`

	// 统一数据权限增强配置
	Unified *UnifiedDataPermConfig `json:"unified,optional"`
}

// UnifiedDataPermConfig 统一数据权限配置
type UnifiedDataPermConfig struct {
	// 权限引擎配置
	Engine *PermissionEngineConfig `json:"engine,optional"`

	// 字段掩码配置
	FieldMask *FieldMaskConfig `json:"fieldMask,optional"`

	// 拦截器配置
	Interceptor *InterceptorConfig `json:"interceptor,optional"`

	// 性能和缓存配置
	Performance *PerformanceConfig `json:"performance,optional"`

	// 调试和监控配置
	Debug *DebugConfig `json:"debug,optional"`
}

// PermissionEngineConfig 权限引擎配置
type PermissionEngineConfig struct {
	// 规则模板配置
	TemplatesEnabled bool     `json:"templatesEnabled,default=true"`
	CustomTemplates  []string `json:"customTemplates,optional"` // 自定义模板文件路径

	// 动态规则生成
	DynamicRules bool `json:"dynamicRules,default=true"`

	// 规则优先级策略
	PriorityStrategy string `json:"priorityStrategy,default=highest,options=highest|lowest|merge"`
}

// FieldMaskConfig 字段掩码配置
type FieldMaskConfig struct {
	// 启用字段级权限控制
	Enabled bool `json:"enabled,default=true"`

	// 默认掩码策略
	DefaultStrategy string `json:"defaultStrategy,default=partial,options=none|partial|full|hash|encrypt"`

	// 敏感字段自动检测
	AutoDetection bool `json:"autoDetection,default=true"`

	// 自定义敏感字段配置
	CustomSensitive map[string]string `json:"customSensitive,optional"`

	// 字段访问策略
	AccessStrategy string `json:"accessStrategy,default=role_based,options=role_based|rule_based|hybrid"`
}

// InterceptorConfig 拦截器配置
type InterceptorConfig struct {
	// 启用SQL过滤
	SqlFiltering bool `json:"sqlFiltering,default=true"`

	// 跳过拦截的表
	SkipTables []string `json:"skipTables,optional"`

	// 严格模式（无权限上下文时拒绝访问）
	StrictMode bool `json:"strictMode,default=true"`

	// 系统表保护
	ProtectSystemTables bool `json:"protectSystemTables,default=true"`
}

// PerformanceConfig 性能配置
type PerformanceConfig struct {
	// 启用缓存
	CacheEnabled bool `json:"cacheEnabled,default=true"`

	// 缓存过期时间（分钟）
	CacheExpiry int `json:"cacheExpiry,default=15"`

	// 批量检查并发数
	BatchConcurrency int `json:"batchConcurrency,default=10"`

	// 权限检查超时（毫秒）
	CheckTimeout int `json:"checkTimeout,default=5000"`

	// 启用性能指标收集
	MetricsEnabled bool `json:"metricsEnabled,default=true"`
}

// DebugConfig 调试配置
type DebugConfig struct {
	// 启用调试日志
	VerboseLogging bool `json:"verboseLogging,default=false"`

	// 权限检查详细日志
	LogPermissionChecks bool `json:"logPermissionChecks,default=false"`

	// SQL过滤详细日志
	LogSqlFilters bool `json:"logSqlFilters,default=false"`

	// 字段掩码详细日志
	LogFieldMasks bool `json:"logFieldMasks,default=false"`

	// 性能分析
	ProfileEnabled bool `json:"profileEnabled,default=false"`
}

// PermissionConfig defines the configuration for the RBAC permission plugin (Casbin based).
type PermissionConfig struct {
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skipPaths,optional"`
}

// EncryptionConfig defines the configuration for the Encryption plugin.
type EncryptionConfig struct {
	Enabled      bool     `json:"enabled,optional"`
	Key          string   `json:"key,optional"` // Base64-encoded AES key
	SkipPaths    []string `json:"skipPaths,optional"`
	ForceEncrypt bool     `json:"forceEncrypt,optional,default=false"` // Force encryption even without header
}

// DefaultUnifiedConfig creates a default configuration for the framework.
func DefaultUnifiedConfig() *UnifiedConfig {
	return &UnifiedConfig{
		Auth: &AuthConfig{
			Enabled: true,
		},
		Audit: &AuditConfig{
			Enabled:             true,
			CaptureResponseBody: true,
		},
		TenantCheck: &TenantCheckConfig{
			Enabled:           true,
			ValidateStatus:    true,
			CacheEnabled:      true,
			RateLimitEnabled:  false, // Disabled by default for backward compatibility
			MaxRequestsPerMin: 1000,
		},
		DataPerm: &DataPermConfig{
			Enabled:         true,
			CasbinEnabled:   true,
			CoreRpcEndpoint: "127.0.0.1:9100",
			Unified: &UnifiedDataPermConfig{
				Engine: &PermissionEngineConfig{
					TemplatesEnabled: true,
					DynamicRules:     true,
					PriorityStrategy: "highest",
				},
				FieldMask: &FieldMaskConfig{
					Enabled:         true,
					DefaultStrategy: "partial",
					AutoDetection:   true,
					AccessStrategy:  "role_based",
				},
				Interceptor: &InterceptorConfig{
					SqlFiltering:        true,
					StrictMode:          true,
					ProtectSystemTables: true,
				},
				Performance: &PerformanceConfig{
					CacheEnabled:     true,
					CacheExpiry:      15,
					BatchConcurrency: 10,
					CheckTimeout:     5000,
					MetricsEnabled:   true,
				},
				Debug: &DebugConfig{
					VerboseLogging:      false,
					LogPermissionChecks: false,
					LogSqlFilters:       false,
					LogFieldMasks:       false,
					ProfileEnabled:      false,
				},
			},
		},
		Permission: &PermissionConfig{
			Enabled:   false, // Disabled by default to avoid behavior changes
			SkipPaths: []string{"/health", "/metrics"},
		},
		Encryption: &EncryptionConfig{
			Enabled:      false, // Disabled by default
			SkipPaths:    []string{"/health", "/metrics"},
			ForceEncrypt: false,
		},
	}
}
