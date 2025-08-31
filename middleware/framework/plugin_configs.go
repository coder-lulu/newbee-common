// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package framework

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)


// DataPermPluginConfig defines strongly typed configuration for data permission plugin
type DataPermPluginConfig struct {
	CacheSize         int           `json:"cache_size" yaml:"cache_size"`
	CacheTTL          time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
	MaxRetries        int           `json:"max_retries" yaml:"max_retries"`
	RetryInterval     time.Duration `json:"retry_interval" yaml:"retry_interval"`
	CircuitBreaker    bool          `json:"circuit_breaker" yaml:"circuit_breaker"`
	FailureThreshold  int           `json:"failure_threshold" yaml:"failure_threshold"`
	RecoveryTimeout   time.Duration `json:"recovery_timeout" yaml:"recovery_timeout"`
	DefaultPermission string        `json:"default_permission" yaml:"default_permission"`
	StrictMode        bool          `json:"strict_mode" yaml:"strict_mode"`
}

// TenantPluginConfig defines strongly typed configuration for tenant plugin
type TenantPluginConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	TenantHeader string `json:"tenant_header" yaml:"tenant_header"`
}

// RateLimitPluginConfig defines strongly typed configuration for rate limit plugin
type RateLimitPluginConfig struct {
	RequestsPerSecond int           `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size"`
	KeyGenerator      string        `json:"key_generator" yaml:"key_generator"`
	StorageType       string        `json:"storage_type" yaml:"storage_type"`
	RedisURL          string        `json:"redis_url" yaml:"redis_url"`
	CleanupInterval   time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	MemoryLimit       int64         `json:"memory_limit" yaml:"memory_limit"`
}


// CreateDataPermPluginConfig creates a strongly typed data permission plugin configuration
func CreateDataPermPluginConfig() *TypedPluginConfig {
	config := NewTypedPluginConfig("dataperm")

	schema := map[string]*ConfigValue{
		"cache_size": {
			Type:        reflect.TypeOf(0),
			Required:    false,
			Default:     10000,
			Validator:   ValidateRange(100, 1000000),
			Description: "Size of the permission cache",
		},
		"cache_ttl": {
			Type:        reflect.TypeOf(time.Duration(0)),
			Required:    false,
			Default:     5 * time.Minute,
			Description: "Time-to-live for cached permissions",
		},
		"max_retries": {
			Type:        reflect.TypeOf(0),
			Required:    false,
			Default:     3,
			Validator:   ValidateRange(1, 10),
			Description: "Maximum number of retry attempts",
		},
		"retry_interval": {
			Type:        reflect.TypeOf(time.Duration(0)),
			Required:    false,
			Default:     time.Second,
			Description: "Interval between retry attempts",
		},
		"circuit_breaker": {
			Type:        reflect.TypeOf(true),
			Required:    false,
			Default:     true,
			Description: "Enable circuit breaker protection",
		},
		"failure_threshold": {
			Type:        reflect.TypeOf(0),
			Required:    false,
			Default:     5,
			Validator:   ValidateRange(1, 100),
			Description: "Number of failures before opening circuit",
		},
		"recovery_timeout": {
			Type:        reflect.TypeOf(time.Duration(0)),
			Required:    false,
			Default:     30 * time.Second,
			Description: "Time to wait before attempting recovery",
		},
		"default_permission": {
			Type:        reflect.TypeOf(""),
			Required:    false,
			Default:     "deny",
			Validator:   ValidateEnum("allow", "deny"),
			Description: "Default permission when unable to determine",
		},
		"strict_mode": {
			Type:        reflect.TypeOf(true),
			Required:    false,
			Default:     true,
			Description: "Enable strict permission checking",
		},
	}

	config.DefineSchema(schema)
	return config
}

// CreateTenantPluginConfig creates a strongly typed tenant plugin configuration
func CreateTenantPluginConfig() *TypedPluginConfig {
	config := NewTypedPluginConfig("tenant")

	schema := map[string]*ConfigValue{
		"enabled": {
			Type:        reflect.TypeOf(true),
			Required:    false,
			Default:     true,
			Description: "Enable tenant middleware",
		},
		"tenant_header": {
			Type:        reflect.TypeOf(""),
			Required:    false,
			Default:     "X-Tenant-ID",
			Description: "HTTP header for tenant identification",
		},
	}

	config.DefineSchema(schema)
	return config
}

// CreateRateLimitPluginConfig creates a strongly typed rate limit plugin configuration
func CreateRateLimitPluginConfig() *TypedPluginConfig {
	config := NewTypedPluginConfig("ratelimit")

	schema := map[string]*ConfigValue{
		"requests_per_second": {
			Type:        reflect.TypeOf(0),
			Required:    false,
			Default:     1000,
			Validator:   ValidateRange(1, 1000000),
			Description: "Maximum requests per second",
		},
		"burst_size": {
			Type:        reflect.TypeOf(0),
			Required:    false,
			Default:     1000,
			Validator:   ValidateRange(1, 10000),
			Description: "Maximum burst size",
		},
		"window_size": {
			Type:        reflect.TypeOf(time.Duration(0)),
			Required:    false,
			Default:     time.Minute,
			Description: "Rate limiting window size",
		},
		"key_generator": {
			Type:        reflect.TypeOf(""),
			Required:    false,
			Default:     "ip",
			Validator:   ValidateEnum("ip", "user", "tenant", "custom"),
			Description: "Key generation strategy",
		},
		"storage_type": {
			Type:        reflect.TypeOf(""),
			Required:    false,
			Default:     "memory",
			Validator:   ValidateEnum("memory", "redis"),
			Description: "Storage backend for rate limiting",
		},
		"redis_url": {
			Type:        reflect.TypeOf(""),
			Required:    false,
			Default:     "",
			Description: "Redis URL for distributed rate limiting",
		},
		"cleanup_interval": {
			Type:        reflect.TypeOf(time.Duration(0)),
			Required:    false,
			Default:     5 * time.Minute,
			Description: "Cleanup interval for expired entries",
		},
		"memory_limit": {
			Type:        reflect.TypeOf(int64(0)),
			Required:    false,
			Default:     int64(100 * 1024 * 1024),                 // 100MB
			Validator:   ValidateRange(1024*1024, 1024*1024*1024), // 1MB to 1GB
			Description: "Memory limit for in-memory storage",
		},
	}

	config.DefineSchema(schema)
	return config
}

// PluginConfigFactory creates typed configurations for known plugin types
type PluginConfigFactory struct{}

// NewPluginConfigFactory creates a new plugin configuration factory
func NewPluginConfigFactory() *PluginConfigFactory {
	return &PluginConfigFactory{}
}

// CreateTypedConfig creates a typed configuration for the specified plugin type
func (pcf *PluginConfigFactory) CreateTypedConfig(pluginType string) *TypedPluginConfig {
	switch pluginType {
	case "audit":
		return nil // Removed: Use simplified audit.AuditConfig instead
	case "dataperm":
		return CreateDataPermPluginConfig()
	case "tenant":
		return CreateTenantPluginConfig()
	case "ratelimit":
		return CreateRateLimitPluginConfig()
	default:
		// Return generic typed config for unknown plugin types
		return NewTypedPluginConfig(pluginType)
	}
}

// GetConfigStruct returns a struct instance for the plugin configuration
func (pcf *PluginConfigFactory) GetConfigStruct(pluginType string) interface{} {
	switch pluginType {
	case "audit":
		return &AuditPluginConfig{}
	case "dataperm":
		return &DataPermPluginConfig{}
	case "tenant":
		return &TenantPluginConfig{}
	case "ratelimit":
		return &RateLimitPluginConfig{}
	default:
		return &map[string]interface{}{}
	}
}

// LoadFromStruct loads configuration from a struct into TypedPluginConfig
func (pcf *PluginConfigFactory) LoadFromStruct(pluginType string, configStruct interface{}) (*TypedPluginConfig, error) {
	config := pcf.CreateTypedConfig(pluginType)

	v := reflect.ValueOf(configStruct)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		// Get field name from JSON tag or field name
		fieldName := field.Tag.Get("json")
		if fieldName == "" {
			fieldName = field.Tag.Get("yaml")
		}
		if fieldName == "" {
			fieldName = field.Name
		}

		// Remove options from tag (e.g., "omitempty")
		if idx := strings.Index(fieldName, ","); idx != -1 {
			fieldName = fieldName[:idx]
		}

		if err := config.Set(fieldName, value.Interface()); err != nil {
			return nil, fmt.Errorf("failed to set field %s: %w", fieldName, err)
		}
	}

	return config, nil
}

// Example usage functions

// ExampleAuditConfig creates an example audit configuration
func ExampleAuditConfig() *TypedPluginConfig {
	// Removed: Use simplified audit.DefaultConfig() instead
	return nil
}

// ExampleDataPermConfig creates an example data permission configuration
func ExampleDataPermConfig() *TypedPluginConfig {
	config := CreateDataPermPluginConfig()

	// Set some example values
	config.Set("cache_size", 50000)
	config.Set("cache_ttl", 10*time.Minute)
	config.Set("max_retries", 3)
	config.Set("circuit_breaker", true)
	config.Set("default_permission", "deny")
	config.Set("strict_mode", true)

	return config
}

// ExampleTenantConfig creates an example tenant configuration
func ExampleTenantConfig() *TypedPluginConfig {
	config := CreateTenantPluginConfig()

	// Set some example values
	config.Set("enabled", true)
	config.Set("tenant_header", "X-Tenant-ID")

	return config
}
