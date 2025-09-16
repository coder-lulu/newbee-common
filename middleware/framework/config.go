// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

type UnifiedConfig struct {
	Auth        *AuthConfig        `json:"auth,optional"`
	Audit       *AuditConfig       `json:"audit,optional"`
	TenantCheck *TenantCheckConfig `json:"tenant_check,optional"`
	DataPerm    *DataPermConfig    `json:"data_perm,optional"`
}

// AuthConfig defines the configuration for the Authentication plugin.
type AuthConfig struct {
	Enabled      bool     `json:"enabled,optional"`
	AccessSecret string   `json:"access_secret,optional"`
	AccessExpire int64    `json:"access_expire,optional"`
	SkipPaths    []string `json:"skip_paths,optional"`
}

// AuditConfig defines the unified configuration for the Audit plugin.
type AuditConfig struct {
	// 基础配置
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skip_paths,optional"`
	
	// 写入器配置 - 支持RPC/DB/Custom写入方式
	WriterType string `json:"writer_type,optional,options=rpc|db|custom,default=rpc"` // rpc, db, custom
	
	// 高级选项
	MaxBodySize     int64 `json:"max_body_size,optional,default=1048576"`  // 1MB 请求体最大大小
	AsyncEnabled    bool  `json:"async_enabled,optional,default=true"`     // 启用异步写入
	AsyncWorkers    int   `json:"async_workers,optional,default=3"`        // 异步工作者数量
	AsyncBufferSize int   `json:"async_buffer_size,optional,default=1000"` // 异步缓冲区大小
}

// AuditRuntimeConfig holds runtime-injected dependencies for audit plugin
type AuditRuntimeConfig struct {
	RpcProvider  interface{} // RPC客户端提供者 (运行时注入)
	CustomWriter interface{} // 自定义写入器 (运行时注入)
}

// TenantCheckConfig defines the configuration for the TenantCheck plugin.
type TenantCheckConfig struct {
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skip_paths,optional"`
	
	// Enhanced validation options - backward compatible
	ValidateStatus bool `json:"validate_status,optional,default=true"` // Check tenant active/suspended status
	CacheEnabled   bool `json:"cache_enabled,optional,default=true"`   // Enable Redis caching for tenant info
	
	// Rate limiting options - disabled by default for backward compatibility
	RateLimitEnabled   bool `json:"rate_limit_enabled,optional,default=false"` // Enable rate limiting per tenant
	MaxRequestsPerMin  int  `json:"max_requests_per_min,optional,default=1000"` // Max requests per minute per tenant
}

// DataPermConfig defines the configuration for the Data Permission plugin.
type DataPermConfig struct {
	// 基础配置
	Enabled   bool     `json:"enabled,optional"`
	SkipPaths []string `json:"skip_paths,optional"`
	
	// 🔥 核心Casbin集成配置
	CasbinEnabled   bool   `json:"casbin_enabled,default=true"`
	CoreRpcEndpoint string `json:"core_rpc_endpoint,default=127.0.0.1:8080"`
}

// DefaultUnifiedConfig creates a default configuration for the framework.
func DefaultUnifiedConfig() *UnifiedConfig {
	return &UnifiedConfig{
		Auth: &AuthConfig{
			Enabled: true,
		},
		Audit: &AuditConfig{
			Enabled: true,
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
			CoreRpcEndpoint: "127.0.0.1:8080",
		},
	}
}

