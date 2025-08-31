package tenant

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigLoader 配置加载器
type ConfigLoader struct {
	configPath string
}

// NewConfigLoader 创建配置加载器
func NewConfigLoader(configPath string) *ConfigLoader {
	return &ConfigLoader{
		configPath: configPath,
	}
}

// LoadConfig 加载插件配置
func (cl *ConfigLoader) LoadConfig() (*PluginConfig, error) {
	// 检查配置文件是否存在
	if _, err := os.Stat(cl.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", cl.configPath)
	}
	
	// 读取配置文件
	data, err := os.ReadFile(cl.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// 解析YAML配置
	var config PluginConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	// 验证配置
	if err := cl.validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	// 应用默认值
	cl.applyDefaults(&config)
	
	return &config, nil
}

// validateConfig 验证配置
func (cl *ConfigLoader) validateConfig(config *PluginConfig) error {
	// 验证全局配置
	if config.Global.MaxRetries < 0 {
		return fmt.Errorf("global.max_retries must be >= 0")
	}
	
	if config.Global.MaxConcurrent < 1 {
		return fmt.Errorf("global.max_concurrent must be >= 1")
	}
	
	// 验证超时配置
	if config.Global.TotalTimeout != "" {
		if _, err := time.ParseDuration(config.Global.TotalTimeout); err != nil {
			return fmt.Errorf("invalid global.total_timeout: %w", err)
		}
	}
	
	if config.Global.DefaultTimeout != "" {
		if _, err := time.ParseDuration(config.Global.DefaultTimeout); err != nil {
			return fmt.Errorf("invalid global.default_timeout: %w", err)
		}
	}
	
	if config.Global.HealthCheckInterval != "" {
		if _, err := time.ParseDuration(config.Global.HealthCheckInterval); err != nil {
			return fmt.Errorf("invalid global.health_check_interval: %w", err)
		}
	}
	
	// 验证插件配置
	pluginNames := make(map[string]bool)
	for _, plugin := range config.Plugins {
		if plugin.Name == "" {
			return fmt.Errorf("plugin name cannot be empty")
		}
		
		if pluginNames[plugin.Name] {
			return fmt.Errorf("duplicate plugin name: %s", plugin.Name)
		}
		pluginNames[plugin.Name] = true
		
		if plugin.Retries < 0 {
			return fmt.Errorf("plugin %s: retries must be >= 0", plugin.Name)
		}
		
		if plugin.Timeout != "" {
			if _, err := time.ParseDuration(plugin.Timeout); err != nil {
				return fmt.Errorf("plugin %s: invalid timeout: %w", plugin.Name, err)
			}
		}
	}
	
	return nil
}

// applyDefaults 应用默认值
func (cl *ConfigLoader) applyDefaults(config *PluginConfig) {
	// 全局默认值
	if config.Global.MaxRetries == 0 {
		config.Global.MaxRetries = 3
	}
	
	if config.Global.TotalTimeout == "" {
		config.Global.TotalTimeout = "600s"
	}
	
	if config.Global.DefaultTimeout == "" {
		config.Global.DefaultTimeout = "60s"
	}
	
	if config.Global.MaxConcurrent == 0 {
		config.Global.MaxConcurrent = 1
	}
	
	if config.Global.HealthCheckInterval == "" {
		config.Global.HealthCheckInterval = "30s"
	}
	
	// 插件默认值
	for i := range config.Plugins {
		if config.Plugins[i].Retries == 0 {
			config.Plugins[i].Retries = config.Global.MaxRetries
		}
		
		if config.Plugins[i].Timeout == "" {
			config.Plugins[i].Timeout = config.Global.DefaultTimeout
		}
	}
}

// SaveConfig 保存配置到文件
func (cl *ConfigLoader) SaveConfig(config *PluginConfig) error {
	// 确保目录存在
	dir := filepath.Dir(cl.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// 序列化配置
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// 写入文件
	if err := os.WriteFile(cl.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// GetConfigTemplate 获取配置模板
func GetConfigTemplate() *PluginConfig {
	return &PluginConfig{
		Plugins: []PluginInfo{
			{
				Name:    "core",
				Enabled: true,
				Config: map[string]any{
					"timeout": "120s",
				},
				Retries: 3,
			},
		},
		Global: GlobalConfig{
			MaxRetries:          3,
			TotalTimeout:        "600s",
			RollbackOnFailure:   true,
			DefaultTimeout:      "60s",
			MaxConcurrent:       1,
			HealthCheckInterval: "30s",
		},
	}
}

// MergeConfigs 合并配置
func MergeConfigs(base, overlay *PluginConfig) *PluginConfig {
	result := *base
	
	// 合并全局配置
	if overlay.Global.MaxRetries > 0 {
		result.Global.MaxRetries = overlay.Global.MaxRetries
	}
	if overlay.Global.TotalTimeout != "" {
		result.Global.TotalTimeout = overlay.Global.TotalTimeout
	}
	if overlay.Global.DefaultTimeout != "" {
		result.Global.DefaultTimeout = overlay.Global.DefaultTimeout
	}
	if overlay.Global.MaxConcurrent > 0 {
		result.Global.MaxConcurrent = overlay.Global.MaxConcurrent
	}
	if overlay.Global.HealthCheckInterval != "" {
		result.Global.HealthCheckInterval = overlay.Global.HealthCheckInterval
	}
	
	// 合并插件配置
	pluginMap := make(map[string]PluginInfo)
	for _, plugin := range result.Plugins {
		pluginMap[plugin.Name] = plugin
	}
	
	for _, overlayPlugin := range overlay.Plugins {
		if basePlugin, exists := pluginMap[overlayPlugin.Name]; exists {
			// 合并现有插件配置
			merged := basePlugin
			merged.Enabled = overlayPlugin.Enabled
			if overlayPlugin.Timeout != "" {
				merged.Timeout = overlayPlugin.Timeout
			}
			if overlayPlugin.Retries > 0 {
				merged.Retries = overlayPlugin.Retries
			}
			if len(overlayPlugin.Config) > 0 {
				if merged.Config == nil {
					merged.Config = make(map[string]any)
				}
				for k, v := range overlayPlugin.Config {
					merged.Config[k] = v
				}
			}
			pluginMap[overlayPlugin.Name] = merged
		} else {
			// 添加新插件
			pluginMap[overlayPlugin.Name] = overlayPlugin
		}
	}
	
	// 重建插件列表
	result.Plugins = make([]PluginInfo, 0, len(pluginMap))
	for _, plugin := range pluginMap {
		result.Plugins = append(result.Plugins, plugin)
	}
	
	return &result
}