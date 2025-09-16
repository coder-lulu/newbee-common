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

package config

import (
	"context"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// AppConfig 应用配置结构体示例
type AppConfig struct {
	App      AppSection      `json:"app"`
	Server   ServerSection   `json:"server"`
	Database DatabaseSection `json:"database"`
	Cache    CacheSection    `json:"cache"`
	Log      LogSection      `json:"log"`
}

type AppSection struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
}

type ServerSection struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
}

type DatabaseSection struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	MaxConns int    `json:"max_conns"`
}

type CacheSection struct {
	Enabled bool          `json:"enabled"`
	TTL     time.Duration `json:"ttl"`
	MaxSize int           `json:"max_size"`
}

type LogSection struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// ConfigUsageExample 配置使用示例
func ConfigUsageExample() {
	logx.Info("Starting configuration management example")

	// 1. 创建配置管理器
	validator := NewStandardUnifiedConfigValidator()

	// 添加验证规则
	for _, rule := range GetCommonValidationRules() {
		validator.AddRule(rule)
	}

	// 创建带验证的配置管理器
	configManager := NewValidatingUnifiedConfigManager(
		validator,
		WithDefaults(map[string]interface{}{
			"app.name":        "newbee-example",
			"app.version":     "1.0.0",
			"app.environment": "development",
			"server.host":     "localhost",
			"server.port":     8080,
			"log.level":       "info",
		}),
		WithUnifiedConfigSource(NewEnvUnifiedConfigSource()),
	)

	// 2. 添加文件配置源
	if fileSource := NewFileUnifiedConfigSource("config.yaml"); fileSource != nil {
		configManager.sources = append(configManager.sources, fileSource)
	}

	// 3. 加载配置
	ctx := context.Background()
	if err := configManager.LoadConfigs(ctx); err != nil {
		logx.Errorw("Failed to load configs", logx.Field("error", err))
		return
	}

	// 4. 使用配置
	appName := configManager.GetString("app.name")
	serverPort := configManager.GetInt("server.port")
	logLevel := configManager.GetString("log.level")

	logx.Infow("Configuration loaded",
		logx.Field("app_name", appName),
		logx.Field("server_port", serverPort),
		logx.Field("log_level", logLevel))

	// 5. 映射到结构体
	var appConfig AppConfig
	if err := mapConfigToStruct(configManager, &appConfig); err != nil {
		logx.Errorw("Failed to map config to struct", logx.Field("error", err))
		return
	}

	logx.Infow("Config mapped to struct",
		logx.Field("config", appConfig))

	// 6. 动态设置配置
	if err := configManager.Set("cache.enabled", true); err != nil {
		logx.Errorw("Failed to set config", logx.Field("error", err))
	}

	// 7. 验证所有配置
	if err := configManager.ValidateAll(); err != nil {
		logx.Errorw("Configuration validation failed", logx.Field("error", err))
	}

	logx.Info("Configuration management example completed")
}

// mapConfigToStruct 将配置映射到结构体
func mapConfigToStruct(cm *ValidatingUnifiedConfigManager, config *AppConfig) error {
	// App section
	config.App.Name = cm.GetString("app.name")
	config.App.Version = cm.GetString("app.version")
	config.App.Environment = cm.GetString("app.environment")

	// Server section
	config.Server.Host = cm.GetString("server.host")
	config.Server.Port = cm.GetInt("server.port")
	config.Server.ReadTimeout = cm.GetDuration("server.read_timeout")
	config.Server.WriteTimeout = cm.GetDuration("server.write_timeout")

	// Database section
	config.Database.Host = cm.GetString("database.host")
	config.Database.Port = cm.GetInt("database.port")
	config.Database.Name = cm.GetString("database.name")
	config.Database.Username = cm.GetString("database.username")
	config.Database.Password = cm.GetString("database.password")
	config.Database.MaxConns = cm.GetInt("database.max_conns")

	// Cache section
	config.Cache.Enabled = cm.GetBool("cache.enabled")
	config.Cache.TTL = cm.GetDuration("cache.ttl")
	config.Cache.MaxSize = cm.GetInt("cache.max_size")

	// Log section
	config.Log.Level = cm.GetString("log.level")
	config.Log.Format = cm.GetString("log.format")

	return nil
}

// ConfigObserverExample 配置观察者示例
type ConfigObserverExample struct {
	name string
}

func NewConfigObserverExample(name string) *ConfigObserverExample {
	return &ConfigObserverExample{name: name}
}

func (obs *ConfigObserverExample) OnConfigChanged(key string, oldValue, newValue interface{}) {
	logx.Infow("Configuration changed",
		logx.Field("observer", obs.name),
		logx.Field("key", key),
		logx.Field("old_value", oldValue),
		logx.Field("new_value", newValue))
}

// GlobalConfigExample 全局配置使用示例
func GlobalConfigExample() {
	// 使用全局配置管理器

	// 1. 添加配置源
	AddUnifiedConfigSource(NewFileUnifiedConfigSource("app.yaml"))

	// 2. 加载配置
	ctx := context.Background()
	if err := LoadUnifiedConfigs(ctx); err != nil {
		logx.Errorw("Failed to load global configs", logx.Field("error", err))
		return
	}

	// 3. 使用全局函数
	appName := GetUnifiedString("app.name")
	serverPort := GetUnifiedInt("server.port")
	debugEnabled := GetUnifiedBool("debug.enabled")

	logx.Infow("Global configuration accessed",
		logx.Field("app_name", appName),
		logx.Field("server_port", serverPort),
		logx.Field("debug_enabled", debugEnabled))

	// 4. 动态设置
	Set("runtime.start_time", time.Now())

	logx.Info("Global configuration example completed")
}

// EnvironmentSpecificConfigExample 环境特定配置示例
func EnvironmentSpecificConfigExample() {
	env := GetString("app.environment")

	// 根据环境加载不同的配置文件
	var configFile string
	switch env {
	case "development":
		configFile = "config.dev.yaml"
	case "testing":
		configFile = "config.test.yaml"
	case "staging":
		configFile = "config.staging.yaml"
	case "production":
		configFile = "config.prod.yaml"
	default:
		configFile = "config.yaml"
	}

	// 创建环境特定的配置管理器
	envConfigManager := NewUnifiedConfigManager(
		WithUnifiedConfigSource(NewFileUnifiedConfigSource(configFile)),
		WithUnifiedConfigSource(NewEnvUnifiedConfigSource(WithEnvPrefix("APP_"))),
	)

	ctx := context.Background()
	if err := envConfigManager.LoadConfigs(ctx); err != nil {
		logx.Errorw("Failed to load environment config",
			logx.Field("env", env),
			logx.Field("file", configFile),
			logx.Field("error", err))
		return
	}

	logx.Infow("Environment specific configuration loaded",
		logx.Field("environment", env),
		logx.Field("config_file", configFile))
}

// 默认配置示例
func GetDefaultAppConfig() map[string]interface{} {
	return map[string]interface{}{
		// App 配置
		"app.name":        "newbee",
		"app.version":     "1.0.0",
		"app.environment": "development",
		"app.debug":       true,

		// Server 配置
		"server.host":          "0.0.0.0",
		"server.port":          8080,
		"server.read_timeout":  "30s",
		"server.write_timeout": "30s",
		"server.idle_timeout":  "120s",

		// Database 配置
		"database.host":      "localhost",
		"database.port":      3306,
		"database.name":      "newbee",
		"database.username":  "root",
		"database.password":  "",
		"database.max_conns": 10,
		"database.timeout":   "10s",

		// Cache 配置
		"cache.enabled":  true,
		"cache.ttl":      "5m",
		"cache.max_size": 1000,

		// Log 配置
		"log.level":  "info",
		"log.format": "json",

		// Security 配置
		"security.jwt_secret":  "your-secret-key",
		"security.jwt_expire":  "24h",
		"security.bcrypt_cost": 10,
		"security.rate_limit":  100,

		// Feature 开关
		"features.audit_enabled":     true,
		"features.metrics_enabled":   true,
		"features.tracing_enabled":   false,
		"features.data_perm_enabled": true,
	}
}
