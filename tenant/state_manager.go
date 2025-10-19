package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coder-lulu/newbee-core/rpc/ent"
	tenant_ent "github.com/coder-lulu/newbee-core/rpc/ent/tenant"
	"github.com/coder-lulu/newbee-common/orm/ent/hooks"
	
	"github.com/zeromicro/go-zero/core/logx"
)

// StateManager 初始化状态管理器
type StateManager struct {
	db     *ent.Client
	logger logx.Logger
}

// NewStateManager 创建状态管理器
func NewStateManager(db *ent.Client, logger logx.Logger) *StateManager {
	return &StateManager{
		db:     db,
		logger: logger,
	}
}

// InitializationState 初始化状态
type InitializationState struct {
	TenantID       uint64                    `json:"tenant_id"`
	RequestID      string                    `json:"request_id"`
	Status         InitStatus                `json:"status"`
	StartTime      time.Time                 `json:"start_time"`
	EndTime        *time.Time                `json:"end_time,omitempty"`
	Duration       time.Duration             `json:"duration,omitempty"`
	Plugins        map[string]PluginState    `json:"plugins"`
	ErrorMessage   string                    `json:"error_message,omitempty"`
	FailedPlugin   string                    `json:"failed_plugin,omitempty"`
	Progress       float64                   `json:"progress"`
	TotalPlugins   int                       `json:"total_plugins"`
	CompletedPlugins int                     `json:"completed_plugins"`
}

// PluginState 插件状态
type PluginState struct {
	Status         InitStatus            `json:"status"`
	StartTime      time.Time             `json:"start_time"`
	EndTime        *time.Time            `json:"end_time,omitempty"`
	Duration       time.Duration         `json:"duration,omitempty"`
	Error          string                `json:"error,omitempty"`
	Message        string                `json:"message,omitempty"`
	Metadata       map[string]any        `json:"metadata,omitempty"`
	RetryCount     int                   `json:"retry_count"`
	Resources      []string              `json:"resources,omitempty"`
}

// CreateInitState 创建初始化状态
func (sm *StateManager) CreateInitState(ctx context.Context, req *InitRequest, pluginCount int) error {
	state := &InitializationState{
		TenantID:         req.TenantID,
		RequestID:        req.RequestID,
		Status:          StatusPending,
		StartTime:       time.Now(),
		Plugins:         make(map[string]PluginState),
		Progress:        0.0,
		TotalPlugins:    pluginCount,
		CompletedPlugins: 0,
	}
	
	return sm.saveState(ctx, state)
}

// UpdateInitStatus 更新初始化总体状态
func (sm *StateManager) UpdateInitStatus(ctx context.Context, tenantID uint64, status InitStatus, errorMsg string) error {
	state, err := sm.GetState(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get state: %w", err)
	}
	
	state.Status = status
	if errorMsg != "" {
		state.ErrorMessage = errorMsg
	}
	
	if status == StatusSuccess || status == StatusFailed {
		now := time.Now()
		state.EndTime = &now
		state.Duration = now.Sub(state.StartTime)
	}
	
	return sm.saveState(ctx, state)
}

// UpdatePluginState 更新插件状态
func (sm *StateManager) UpdatePluginState(ctx context.Context, tenantID uint64, pluginName string, pluginState PluginState) error {
	state, err := sm.GetState(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get state: %w", err)
	}
	
	if state.Plugins == nil {
		state.Plugins = make(map[string]PluginState)
	}
	
	state.Plugins[pluginName] = pluginState
	
	// 更新进度
	completedCount := 0
	for _, ps := range state.Plugins {
		if ps.Status == StatusSuccess || ps.Status == StatusSkipped {
			completedCount++
		} else if ps.Status == StatusFailed {
			state.FailedPlugin = pluginName
		}
	}
	
	state.CompletedPlugins = completedCount
	if state.TotalPlugins > 0 {
		state.Progress = float64(completedCount) / float64(state.TotalPlugins) * 100
	}
	
	return sm.saveState(ctx, state)
}

// StartPlugin 标记插件开始执行
func (sm *StateManager) StartPlugin(ctx context.Context, tenantID uint64, pluginName string) error {
	pluginState := PluginState{
		Status:    StatusRunning,
		StartTime: time.Now(),
	}
	
	return sm.UpdatePluginState(ctx, tenantID, pluginName, pluginState)
}

// CompletePlugin 标记插件执行完成
func (sm *StateManager) CompletePlugin(ctx context.Context, tenantID uint64, pluginName string, success bool, message string, errorMsg string, resources []string) error {
	state, err := sm.GetState(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get state: %w", err)
	}
	
	pluginState := state.Plugins[pluginName]
	now := time.Now()
	pluginState.EndTime = &now
	pluginState.Duration = now.Sub(pluginState.StartTime)
	pluginState.Message = message
	
	if success {
		pluginState.Status = StatusSuccess
	} else {
		pluginState.Status = StatusFailed
		pluginState.Error = errorMsg
	}
	
	if len(resources) > 0 {
		pluginState.Resources = resources
	}
	
	return sm.UpdatePluginState(ctx, tenantID, pluginName, pluginState)
}

// SkipPlugin 标记插件被跳过
func (sm *StateManager) SkipPlugin(ctx context.Context, tenantID uint64, pluginName string, reason string) error {
	pluginState := PluginState{
		Status:    StatusSkipped,
		StartTime: time.Now(),
		Message:   reason,
	}
	
	now := time.Now()
	pluginState.EndTime = &now
	pluginState.Duration = 0
	
	return sm.UpdatePluginState(ctx, tenantID, pluginName, pluginState)
}

// GetState 获取初始化状态
func (sm *StateManager) GetState(ctx context.Context, tenantID uint64) (*InitializationState, error) {
	// 从租户表的config字段中读取状态
	tenant, err := sm.db.Tenant.Query().
		Where(tenant_ent.IDEQ(tenantID)).
		Only(hooks.NewSystemContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant: %w", err)
	}
	
	if len(tenant.Config) == 0 {
		return &InitializationState{
			TenantID: tenantID,
			Status:   StatusPending,
			Plugins:  make(map[string]PluginState),
		}, nil
	}
	
	// 解析状态信息
	stateData, exists := tenant.Config["initialization_state"]
	if !exists {
		return &InitializationState{
			TenantID: tenantID,
			Status:   StatusPending,
			Plugins:  make(map[string]PluginState),
		}, nil
	}
	
	// 反序列化状态
	var state InitializationState
	stateBytes, err := json.Marshal(stateData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state data: %w", err)
	}
	
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}
	
	return &state, nil
}

// saveState 保存状态到数据库
func (sm *StateManager) saveState(ctx context.Context, state *InitializationState) error {
	// 获取当前租户配置
	tenant, err := sm.db.Tenant.Query().
		Where(tenant_ent.IDEQ(state.TenantID)).
		Only(hooks.NewSystemContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to query tenant: %w", err)
	}
	
	config := tenant.Config
	if config == nil {
		config = make(map[string]any)
	}
	
	// 保存状态
	config["initialization_state"] = state
	config["last_updated"] = time.Now().Format(time.RFC3339)
	
	// 保持向后兼容 - 设置老格式的状态字段
	if state.Status == StatusSuccess {
		config["status"] = "completed"
		config["completed_at"] = time.Now().Format(time.RFC3339)
	} else if state.Status == StatusFailed {
		config["status"] = "failed"
		config["error"] = state.ErrorMessage
	} else if state.Status == StatusRunning {
		config["status"] = "initializing"
	}
	
	// 更新租户配置
	_, err = sm.db.Tenant.UpdateOneID(state.TenantID).
		SetConfig(config).
		Save(hooks.NewSystemContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}
	
	sm.logger.Infow("State saved successfully",
		logx.Field("tenant_id", state.TenantID),
		logx.Field("status", state.Status),
		logx.Field("progress", state.Progress))
	
	return nil
}

// ListActiveInits 列出所有正在进行的初始化
func (sm *StateManager) ListActiveInits(ctx context.Context) ([]*InitializationState, error) {
	// 查询所有正在初始化的租户
	tenants, err := sm.db.Tenant.Query().
		Where(tenant_ent.ConfigNotNil()).
		All(hooks.NewSystemContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to query tenants: %w", err)
	}
	
	var activeStates []*InitializationState
	for _, t := range tenants {
		if len(t.Config) > 0 {
			if stateData, exists := t.Config["initialization_state"]; exists {
				var state InitializationState
				stateBytes, err := json.Marshal(stateData)
				if err != nil {
					continue
				}
				
				if err := json.Unmarshal(stateBytes, &state); err != nil {
					continue
				}
				
				if state.Status == StatusRunning || state.Status == StatusPending {
					activeStates = append(activeStates, &state)
				}
			}
		}
	}
	
	return activeStates, nil
}

// CleanupOldStates 清理旧的状态记录
func (sm *StateManager) CleanupOldStates(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	
	tenants, err := sm.db.Tenant.Query().
		Where(tenant_ent.ConfigNotNil()).
		All(hooks.NewSystemContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to query tenants: %w", err)
	}
	
	cleanedCount := 0
	for _, t := range tenants {
		if len(t.Config) > 0 {
			if stateData, exists := t.Config["initialization_state"]; exists {
				var state InitializationState
				stateBytes, err := json.Marshal(stateData)
				if err != nil {
					continue
				}
				
				if err := json.Unmarshal(stateBytes, &state); err != nil {
					continue
				}
				
				// 清理已完成且超过指定时间的状态
				if (state.Status == StatusSuccess || state.Status == StatusFailed) &&
					state.EndTime != nil && state.EndTime.Before(cutoff) {
					
					config := t.Config
					delete(config, "initialization_state")
					
					_, err = sm.db.Tenant.UpdateOneID(t.ID).
						SetConfig(config).
						Save(hooks.NewSystemContext(ctx))
					if err != nil {
						sm.logger.Errorw("Failed to cleanup old state",
							logx.Field("tenant_id", t.ID),
							logx.Field("error", err.Error()))
						continue
					}
					
					cleanedCount++
				}
			}
		}
	}
	
	sm.logger.Infow("Old states cleaned up",
		logx.Field("cleaned_count", cleanedCount),
		logx.Field("cutoff", cutoff))
	
	return nil
}

// GetStateMetrics 获取状态统计指标
func (sm *StateManager) GetStateMetrics(ctx context.Context) (*StateMetrics, error) {
	states, err := sm.ListActiveInits(ctx)
	if err != nil {
		return nil, err
	}
	
	metrics := &StateMetrics{
		TotalActive:   len(states),
		StatusCounts:  make(map[InitStatus]int),
		PluginMetrics: make(map[string]*PluginMetrics),
	}
	
	for _, state := range states {
		metrics.StatusCounts[state.Status]++
		
		for pluginName, pluginState := range state.Plugins {
			if metrics.PluginMetrics[pluginName] == nil {
				metrics.PluginMetrics[pluginName] = &PluginMetrics{
					StatusCounts: make(map[InitStatus]int),
				}
			}
			
			pluginMetric := metrics.PluginMetrics[pluginName]
			pluginMetric.StatusCounts[pluginState.Status]++
			
			if pluginState.Duration > 0 {
				pluginMetric.TotalDuration += pluginState.Duration
				pluginMetric.ExecutionCount++
				
				if pluginMetric.MinDuration == 0 || pluginState.Duration < pluginMetric.MinDuration {
					pluginMetric.MinDuration = pluginState.Duration
				}
				if pluginState.Duration > pluginMetric.MaxDuration {
					pluginMetric.MaxDuration = pluginState.Duration
				}
			}
		}
	}
	
	// 计算平均执行时间
	for _, pluginMetric := range metrics.PluginMetrics {
		if pluginMetric.ExecutionCount > 0 {
			pluginMetric.AvgDuration = pluginMetric.TotalDuration / time.Duration(pluginMetric.ExecutionCount)
		}
	}
	
	return metrics, nil
}

// StateMetrics 状态统计指标
type StateMetrics struct {
	TotalActive   int                        `json:"total_active"`
	StatusCounts  map[InitStatus]int         `json:"status_counts"`
	PluginMetrics map[string]*PluginMetrics  `json:"plugin_metrics"`
}

// PluginMetrics 插件统计指标
type PluginMetrics struct {
	StatusCounts   map[InitStatus]int `json:"status_counts"`
	ExecutionCount int                `json:"execution_count"`
	TotalDuration  time.Duration      `json:"total_duration"`
	AvgDuration    time.Duration      `json:"avg_duration"`
	MinDuration    time.Duration      `json:"min_duration"`
	MaxDuration    time.Duration      `json:"max_duration"`
}