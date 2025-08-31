// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package config

import (
	"errors"
	"fmt"
	"time"
)

// UnifiedConfig represents the complete configuration for the auth middleware system
type UnifiedConfig struct {
	// Core authentication settings
	Core CoreConfig `yaml:"core" json:"core"`
	
	// Plugin configurations (optional, loaded only if enabled)
	Plugins PluginConfigs `yaml:"plugins" json:"plugins"`
	
	// Environment-specific settings
	Environment string `yaml:"environment" json:"environment"` // dev, staging, prod
}

// CoreConfig contains the essential authentication configuration
type CoreConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Algorithm     string        `yaml:"algorithm" json:"algorithm"` 
	SecretSource  string        `yaml:"secret_source" json:"secret_source"`
	TokenExpiry   time.Duration `yaml:"token_expiry" json:"token_expiry"`
	RefreshExpiry time.Duration `yaml:"refresh_expiry" json:"refresh_expiry"`
	ClockSkew     time.Duration `yaml:"clock_skew" json:"clock_skew"`
	SkipPaths     []string      `yaml:"skip_paths" json:"skip_paths"`
	RequiredClaims []string     `yaml:"required_claims" json:"required_claims"`
}

// PluginConfigs contains configuration for all optional plugins
type PluginConfigs struct {
	Cache      *CacheConfig      `yaml:"cache,omitempty" json:"cache,omitempty"`
	Security   *SecurityConfig   `yaml:"security,omitempty" json:"security,omitempty"`
	MultiTenant *MultiTenantConfig `yaml:"multi_tenant,omitempty" json:"multi_tenant,omitempty"`
	RBAC       *RBACConfig       `yaml:"rbac,omitempty" json:"rbac,omitempty"`
	Monitoring *MonitoringConfig `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`
}

// CacheConfig configures token validation caching
type CacheConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	Type        string        `yaml:"type" json:"type"` // "memory" or "redis"
	Size        int           `yaml:"size" json:"size"`
	TTL         time.Duration `yaml:"ttl" json:"ttl"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
	
	// Redis-specific settings (when type = "redis")
	Redis *RedisConfig `yaml:"redis,omitempty" json:"redis,omitempty"`
}

// RedisConfig configures Redis cache backend
type RedisConfig struct {
	Address     string        `yaml:"address" json:"address"`
	Password    string        `yaml:"password" json:"password"`
	Database    int           `yaml:"database" json:"database"`
	MaxRetries  int           `yaml:"max_retries" json:"max_retries"`
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`
	ReadTimeout time.Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout"`
}

// SecurityConfig configures security features
type SecurityConfig struct {
	TokenRevocation *RevocationConfig `yaml:"token_revocation,omitempty" json:"token_revocation,omitempty"`
	RateLimit      *RateLimitConfig  `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	TokenBinding   *TokenBindingConfig `yaml:"token_binding,omitempty" json:"token_binding,omitempty"`
	KeyManagement  *KeyManagementConfig `yaml:"key_management,omitempty" json:"key_management,omitempty"`
	AuditLog       *AuditLogConfig   `yaml:"audit_log,omitempty" json:"audit_log,omitempty"`
}

// RevocationConfig configures token revocation/blacklisting
type RevocationConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
	MaxStoredTokens int           `yaml:"max_stored_tokens" json:"max_stored_tokens"`
	DefaultTTL      time.Duration `yaml:"default_ttl" json:"default_ttl"`
}

// RateLimitConfig configures rate limiting
type RateLimitConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	RequestsPerSecond int        `yaml:"requests_per_second" json:"requests_per_second"`
	BurstSize      int           `yaml:"burst_size" json:"burst_size"`
	WindowSize     time.Duration `yaml:"window_size" json:"window_size"`
}

// TokenBindingConfig configures token binding to client attributes
type TokenBindingConfig struct {
	Enabled       bool `yaml:"enabled" json:"enabled"`
	BindToIP      bool `yaml:"bind_to_ip" json:"bind_to_ip"`
	BindToUserAgent bool `yaml:"bind_to_user_agent" json:"bind_to_user_agent"`
	StrictMode    bool `yaml:"strict_mode" json:"strict_mode"`
}

// KeyManagementConfig configures cryptographic key management
type KeyManagementConfig struct {
	RotationEnabled  bool          `yaml:"rotation_enabled" json:"rotation_enabled"`
	RotationInterval time.Duration `yaml:"rotation_interval" json:"rotation_interval"`
	MaxKeyAge        time.Duration `yaml:"max_key_age" json:"max_key_age"`
	KeySources       []KeySource   `yaml:"key_sources" json:"key_sources"`
}

// KeySource represents a source for loading cryptographic keys
type KeySource struct {
	KeyID     string `yaml:"key_id" json:"key_id"`
	Source    string `yaml:"source" json:"source"`
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	TenantID  string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
}

// AuditLogConfig configures security audit logging
type AuditLogConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Level       string `yaml:"level" json:"level"` // "basic", "detailed", "full"
	Format      string `yaml:"format" json:"format"` // "json", "text"
	Destination string `yaml:"destination" json:"destination"` // "stdout", "file", "syslog"
	FilePath    string `yaml:"file_path,omitempty" json:"file_path,omitempty"`
}

// MultiTenantConfig configures multi-tenant support
type MultiTenantConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	StrictIsolation  bool     `yaml:"strict_isolation" json:"strict_isolation"`
	DefaultTenant    string   `yaml:"default_tenant" json:"default_tenant"`
	AllowedTenants   []string `yaml:"allowed_tenants" json:"allowed_tenants"`
	TenantSources    []string `yaml:"tenant_sources" json:"tenant_sources"` // "header", "subdomain", "path"
}

// RBACConfig configures role-based access control
type RBACConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	Provider     string `yaml:"provider" json:"provider"` // "casbin", "simple"
	ModelFile    string `yaml:"model_file" json:"model_file"`
	PolicySource string `yaml:"policy_source" json:"policy_source"` // "file", "database"
	PolicyFile   string `yaml:"policy_file,omitempty" json:"policy_file,omitempty"`
}

// MonitoringConfig configures monitoring and metrics
type MonitoringConfig struct {
	Metrics   *MetricsConfig `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	Tracing   *TracingConfig `yaml:"tracing,omitempty" json:"tracing,omitempty"`
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty" json:"health_check,omitempty"`
}

// MetricsConfig configures metrics collection
type MetricsConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Provider    string `yaml:"provider" json:"provider"` // "prometheus", "statsd"
	Endpoint    string `yaml:"endpoint" json:"endpoint"`
	Namespace   string `yaml:"namespace" json:"namespace"`
	Detailed    bool   `yaml:"detailed" json:"detailed"`
}

// TracingConfig configures distributed tracing
type TracingConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Provider    string `yaml:"provider" json:"provider"` // "jaeger", "zipkin", "otel"
	Endpoint    string `yaml:"endpoint" json:"endpoint"`
	ServiceName string `yaml:"service_name" json:"service_name"`
	SampleRate  float64 `yaml:"sample_rate" json:"sample_rate"`
}

// HealthCheckConfig configures health check endpoints
type HealthCheckConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
}

// DefaultConfig returns a secure default configuration
func DefaultConfig() *UnifiedConfig {
	return &UnifiedConfig{
		Core: CoreConfig{
			Enabled:        true,
			Algorithm:      "HS256", // Secure default
			SecretSource:   "env:JWT_SECRET", // Load from environment
			TokenExpiry:    15 * time.Minute,
			RefreshExpiry:  24 * time.Hour,
			ClockSkew:      1 * time.Minute,
			SkipPaths:      []string{"/health", "/metrics", "/ready"},
			RequiredClaims: []string{"user_id"},
		},
		Plugins: PluginConfigs{
			Cache: &CacheConfig{
				Enabled:         true,
				Type:           "memory",
				Size:           1000,
				TTL:            5 * time.Minute,
				CleanupInterval: 1 * time.Minute,
			},
			Security: &SecurityConfig{
				TokenRevocation: &RevocationConfig{
					Enabled:         true,
					CleanupInterval: 5 * time.Minute,
					MaxStoredTokens: 10000,
					DefaultTTL:      24 * time.Hour,
				},
				KeyManagement: &KeyManagementConfig{
					RotationEnabled:  false, // Disabled by default for simplicity
					RotationInterval: 24 * time.Hour,
					MaxKeyAge:        7 * 24 * time.Hour,
				},
				AuditLog: &AuditLogConfig{
					Enabled:     false, // Disabled by default
					Level:       "basic",
					Format:      "json",
					Destination: "stdout",
				},
			},
			Monitoring: &MonitoringConfig{
				Metrics: &MetricsConfig{
					Enabled:   false, // Disabled by default
					Provider:  "prometheus",
					Namespace: "auth_middleware",
					Detailed:  false,
				},
				HealthCheck: &HealthCheckConfig{
					Enabled:  true,
					Endpoint: "/auth/health",
					Timeout:  5 * time.Second,
				},
			},
		},
		Environment: "dev",
	}
}

// ProductionConfig returns a production-ready configuration
func ProductionConfig() *UnifiedConfig {
	config := DefaultConfig()
	
	// Production-specific overrides
	config.Environment = "prod"
	config.Core.ClockSkew = 30 * time.Second // Tighter clock skew
	
	// Enable security features
	config.Plugins.Security.TokenRevocation.Enabled = true
	config.Plugins.Security.AuditLog.Enabled = true
	config.Plugins.Security.AuditLog.Level = "detailed"
	
	// Enable monitoring
	config.Plugins.Monitoring.Metrics.Enabled = true
	config.Plugins.Monitoring.Metrics.Detailed = true
	
	// Use Redis for distributed caching in production
	config.Plugins.Cache.Type = "redis"
	config.Plugins.Cache.Redis = &RedisConfig{
		Address:      "localhost:6379",
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	
	return config
}

// Validate validates the configuration and returns any errors
func (c *UnifiedConfig) Validate() error {
	// Validate core configuration
	if err := c.validateCore(); err != nil {
		return fmt.Errorf("core config validation failed: %w", err)
	}
	
	// Validate plugin configurations
	if err := c.validatePlugins(); err != nil {
		return fmt.Errorf("plugin config validation failed: %w", err)
	}
	
	return nil
}

// validateCore validates the core configuration
func (c *UnifiedConfig) validateCore() error {
	if !c.Core.Enabled {
		return nil // Skip validation if disabled
	}
	
	// Validate algorithm
	supportedAlgorithms := []string{"HS256", "HS384", "HS512"}
	algorithmValid := false
	for _, alg := range supportedAlgorithms {
		if c.Core.Algorithm == alg {
			algorithmValid = true
			break
		}
	}
	if !algorithmValid {
		return fmt.Errorf("unsupported algorithm: %s", c.Core.Algorithm)
	}
	
	// Validate secret source
	if c.Core.SecretSource == "" {
		return errors.New("secret_source cannot be empty")
	}
	
	// Validate token expiry
	if c.Core.TokenExpiry <= 0 {
		return errors.New("token_expiry must be positive")
	}
	if c.Core.TokenExpiry > 24*time.Hour {
		return errors.New("token_expiry should not exceed 24 hours for security")
	}
	
	// Validate refresh expiry
	if c.Core.RefreshExpiry <= c.Core.TokenExpiry {
		return errors.New("refresh_expiry must be greater than token_expiry")
	}
	
	return nil
}

// validatePlugins validates plugin configurations
func (c *UnifiedConfig) validatePlugins() error {
	// Validate cache config
	if c.Plugins.Cache != nil && c.Plugins.Cache.Enabled {
		if c.Plugins.Cache.Size <= 0 {
			return errors.New("cache size must be positive")
		}
		if c.Plugins.Cache.TTL <= 0 {
			return errors.New("cache TTL must be positive")
		}
		if c.Plugins.Cache.Type == "redis" && c.Plugins.Cache.Redis == nil {
			return errors.New("redis configuration required when cache type is redis")
		}
	}
	
	// Validate security config
	if c.Plugins.Security != nil {
		if rev := c.Plugins.Security.TokenRevocation; rev != nil && rev.Enabled {
			if rev.MaxStoredTokens <= 0 {
				return errors.New("max_stored_tokens must be positive")
			}
		}
	}
	
	return nil
}

// IsProductionEnvironment returns true if running in production
func (c *UnifiedConfig) IsProductionEnvironment() bool {
	return c.Environment == "prod" || c.Environment == "production"
}

// GetEffectiveTTL returns the effective TTL for token caching
func (c *UnifiedConfig) GetEffectiveTTL() time.Duration {
	if c.Plugins.Cache != nil && c.Plugins.Cache.Enabled {
		return c.Plugins.Cache.TTL
	}
	// Default to half of token expiry
	return c.Core.TokenExpiry / 2
}