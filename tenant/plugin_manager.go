package tenant

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// PluginManager 插件管理器
type PluginManager struct {
	plugins   map[string]TenantInitPlugin // 已实例化的插件
	factories map[string]PluginFactory    // 插件工厂
	config    *PluginConfig               // 插件配置
	mu        sync.RWMutex               // 读写锁
	logger    logx.Logger                // 日志记录器
}

// PluginConfig 插件全局配置
type PluginConfig struct {
	// 插件列表
	Plugins []PluginInfo `yaml:"plugins"`
	
	// 全局设置
	Global GlobalConfig `yaml:"global"`
}

// PluginInfo 插件配置信息
type PluginInfo struct {
	// 插件名称
	Name string `yaml:"name"`
	
	// 是否启用
	Enabled bool `yaml:"enabled"`
	
	// 插件特定配置
	Config map[string]any `yaml:"config"`
	
	// 超时设置（覆盖全局设置）
	Timeout string `yaml:"timeout,omitempty"`
	
	// 重试次数
	Retries int `yaml:"retries,omitempty"`
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	// 最大重试次数
	MaxRetries int `yaml:"max_retries"`
	
	// 总超时时间
	TotalTimeout string `yaml:"total_timeout"`
	
	// 失败时是否回滚
	RollbackOnFailure bool `yaml:"rollback_on_failure"`
	
	// 默认插件超时
	DefaultTimeout string `yaml:"default_timeout"`
	
	// 并发执行插件数
	MaxConcurrent int `yaml:"max_concurrent"`
	
	// 健康检查间隔
	HealthCheckInterval string `yaml:"health_check_interval"`
}

// NewPluginManager 创建插件管理器
func NewPluginManager(config *PluginConfig, logger logx.Logger) *PluginManager {
	if logger == nil {
		logger = logx.WithContext(context.Background())
	}
	
	return &PluginManager{
		plugins:   make(map[string]TenantInitPlugin),
		factories: make(map[string]PluginFactory),
		config:    config,
		logger:    logger,
	}
}

// RegisterFactory 注册插件工厂
func (pm *PluginManager) RegisterFactory(name string, factory PluginFactory) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if _, exists := pm.factories[name]; exists {
		return fmt.Errorf("plugin factory %s already registered", name)
	}
	
	pm.factories[name] = factory
	pm.logger.Infow("Plugin factory registered", logx.Field("plugin", name))
	
	return nil
}

// UnregisterFactory 注销插件工厂
func (pm *PluginManager) UnregisterFactory(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	delete(pm.factories, name)
	delete(pm.plugins, name)
	
	pm.logger.Infow("Plugin factory unregistered", logx.Field("plugin", name))
	return nil
}

// LoadPlugins 根据配置加载插件
func (pm *PluginManager) LoadPlugins() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	for _, pluginInfo := range pm.config.Plugins {
		if !pluginInfo.Enabled {
			pm.logger.Infow("Plugin disabled, skipping", logx.Field("plugin", pluginInfo.Name))
			continue
		}
		
		if err := pm.loadPlugin(pluginInfo); err != nil {
			return fmt.Errorf("failed to load plugin %s: %w", pluginInfo.Name, err)
		}
	}
	
	return nil
}

// loadPlugin 加载单个插件
func (pm *PluginManager) loadPlugin(info PluginInfo) error {
	factory, exists := pm.factories[info.Name]
	if !exists {
		return fmt.Errorf("plugin factory %s not found", info.Name)
	}
	
	// 验证配置
	if err := factory.ValidateConfig(info.Config); err != nil {
		return fmt.Errorf("invalid config for plugin %s: %w", info.Name, err)
	}
	
	// 创建插件实例
	plugin, err := factory.CreatePlugin(info.Config)
	if err != nil {
		return fmt.Errorf("failed to create plugin %s: %w", info.Name, err)
	}
	
	// 健康检查
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := plugin.HealthCheck(ctx); err != nil {
		return fmt.Errorf("plugin %s failed health check: %w", info.Name, err)
	}
	
	pm.plugins[info.Name] = plugin
	pm.logger.Infow("Plugin loaded successfully", logx.Field("plugin", info.Name))
	
	return nil
}

// GetPlugin 获取插件实例
func (pm *PluginManager) GetPlugin(name string) (TenantInitPlugin, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	plugin, exists := pm.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}
	
	return plugin, nil
}

// GetEnabledPlugins 获取所有已启用的插件
func (pm *PluginManager) GetEnabledPlugins() []TenantInitPlugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	var plugins []TenantInitPlugin
	for _, pluginInfo := range pm.config.Plugins {
		if pluginInfo.Enabled {
			if plugin, exists := pm.plugins[pluginInfo.Name]; exists {
				plugins = append(plugins, plugin)
			}
		}
	}
	
	return plugins
}

// ListPlugins 列出所有插件的元数据
func (pm *PluginManager) ListPlugins() map[string]PluginMetadata {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	result := make(map[string]PluginMetadata)
	for name, plugin := range pm.plugins {
		result[name] = plugin.GetMetadata()
	}
	
	return result
}

// ValidatePlugins 验证所有插件的依赖关系
func (pm *PluginManager) ValidatePlugins() error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// 构建插件名称集合
	pluginNames := make(map[string]bool)
	for name := range pm.plugins {
		pluginNames[name] = true
	}
	
	// 验证每个插件的依赖
	for name, plugin := range pm.plugins {
		metadata := plugin.GetMetadata()
		for _, dep := range metadata.Dependencies {
			if !pluginNames[dep] {
				return fmt.Errorf("plugin %s depends on %s, but %s is not loaded", name, dep, dep)
			}
		}
	}
	
	return nil
}

// GetExecutionOrder 获取插件的执行顺序（基于依赖关系和优先级）
func (pm *PluginManager) GetExecutionOrder() ([]TenantInitPlugin, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	plugins := pm.GetEnabledPlugins()
	if len(plugins) == 0 {
		return nil, fmt.Errorf("no enabled plugins found")
	}
	
	// 拓扑排序解决依赖关系
	sorted, err := pm.topologicalSort(plugins)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve plugin dependencies: %w", err)
	}
	
	return sorted, nil
}

// topologicalSort 拓扑排序算法
func (pm *PluginManager) topologicalSort(plugins []TenantInitPlugin) ([]TenantInitPlugin, error) {
	// 构建插件映射
	pluginMap := make(map[string]TenantInitPlugin)
	inDegree := make(map[string]int)
	graph := make(map[string][]string)
	
	for _, plugin := range plugins {
		metadata := plugin.GetMetadata()
		pluginMap[metadata.Name] = plugin
		inDegree[metadata.Name] = 0
		graph[metadata.Name] = []string{}
	}
	
	// 构建依赖图
	for _, plugin := range plugins {
		metadata := plugin.GetMetadata()
		for _, dep := range metadata.Dependencies {
			if _, exists := pluginMap[dep]; !exists {
				return nil, fmt.Errorf("plugin %s depends on %s, but %s is not available", metadata.Name, dep, dep)
			}
			graph[dep] = append(graph[dep], metadata.Name)
			inDegree[metadata.Name]++
		}
	}
	
	// Kahn算法执行拓扑排序
	var queue []string
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	
	// 按优先级排序相同层级的插件
	sort.Slice(queue, func(i, j int) bool {
		return pluginMap[queue[i]].GetMetadata().Priority < pluginMap[queue[j]].GetMetadata().Priority
	})
	
	var result []TenantInitPlugin
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, pluginMap[current])
		
		// 处理后续节点
		var nextLevel []string
		for _, neighbor := range graph[current] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				nextLevel = append(nextLevel, neighbor)
			}
		}
		
		// 按优先级排序并添加到队列
		sort.Slice(nextLevel, func(i, j int) bool {
			return pluginMap[nextLevel[i]].GetMetadata().Priority < pluginMap[nextLevel[j]].GetMetadata().Priority
		})
		
		queue = append(queue, nextLevel...)
	}
	
	// 检查是否存在循环依赖
	if len(result) != len(plugins) {
		return nil, fmt.Errorf("circular dependency detected in plugins")
	}
	
	return result, nil
}

// ExecutePlugins 执行所有插件的初始化
func (pm *PluginManager) ExecutePlugins(ctx context.Context, req *InitRequest) (*ExecutionResult, error) {
	// 获取执行顺序
	plugins, err := pm.GetExecutionOrder()
	if err != nil {
		return nil, err
	}
	
	result := &ExecutionResult{
		TenantID:    req.TenantID,
		RequestID:   req.RequestID,
		StartTime:   time.Now(),
		Status:      StatusRunning,
		PluginResults: make(map[string]*InitResponse),
	}
	
	pm.logger.Infow("Starting tenant initialization",
		logx.Field("tenant_id", req.TenantID),
		logx.Field("request_id", req.RequestID),
		logx.Field("plugin_count", len(plugins)))
	
	// 逐个执行插件
	for _, plugin := range plugins {
		metadata := plugin.GetMetadata()
		
		pm.logger.Infow("Executing plugin",
			logx.Field("plugin", metadata.Name),
			logx.Field("tenant_id", req.TenantID))
		
		pluginResult := pm.executePlugin(ctx, plugin, req)
		result.PluginResults[metadata.Name] = pluginResult
		
		if pluginResult.Status == StatusFailed {
			result.Status = StatusFailed
			result.ErrorMessage = fmt.Sprintf("Plugin %s failed: %s", metadata.Name, pluginResult.Error)
			result.FailedPlugin = metadata.Name
			break
		}
		
		pm.logger.Infow("Plugin executed successfully",
			logx.Field("plugin", metadata.Name),
			logx.Field("duration", pluginResult.Duration))
	}
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	if result.Status == StatusRunning {
		result.Status = StatusSuccess
	}
	
	pm.logger.Infow("Tenant initialization completed",
		logx.Field("tenant_id", req.TenantID),
		logx.Field("status", result.Status),
		logx.Field("duration", result.Duration))
	
	return result, nil
}

// executePlugin 执行单个插件
func (pm *PluginManager) executePlugin(ctx context.Context, plugin TenantInitPlugin, req *InitRequest) *InitResponse {
	metadata := plugin.GetMetadata()
	startTime := time.Now()
	
	result := &InitResponse{
		PluginName: metadata.Name,
		Status:     StatusRunning,
	}
	
	// 设置超时
	timeout := metadata.EstimatedDuration
	if timeout == 0 {
		timeout = 60 * time.Second // 默认超时
	}
	
	pluginCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	// 检查是否已初始化
	if initialized, err := plugin.IsInitialized(pluginCtx, req.TenantID); err != nil {
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("Failed to check initialization status: %v", err)
		result.Duration = time.Since(startTime)
		return result
	} else if initialized && req.Mode != InitModeRepair {
		result.Status = StatusSkipped
		result.Message = "Already initialized"
		result.Duration = time.Since(startTime)
		return result
	}
	
	// 执行初始化
	if err := plugin.Initialize(pluginCtx, req); err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()
	} else {
		result.Status = StatusSuccess
		result.Message = "Initialization completed successfully"
	}
	
	result.Duration = time.Since(startTime)
	return result
}

// ExecutionResult 执行结果
type ExecutionResult struct {
	TenantID      uint64                    `json:"tenant_id"`
	RequestID     string                    `json:"request_id"`
	Status        InitStatus                `json:"status"`
	StartTime     time.Time                 `json:"start_time"`
	EndTime       time.Time                 `json:"end_time"`
	Duration      time.Duration             `json:"duration"`
	PluginResults map[string]*InitResponse  `json:"plugin_results"`
	ErrorMessage  string                    `json:"error_message,omitempty"`
	FailedPlugin  string                    `json:"failed_plugin,omitempty"`
}