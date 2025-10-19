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

package state

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisTenantStateManager Redis租户状态管理器
type RedisTenantStateManager struct {
	*RedisStateManager
	keyGen *StateKeyGenerator
}

// NewRedisTenantStateManager 创建Redis租户状态管理器
func NewRedisTenantStateManager(client redis.UniversalClient, keyPrefix string, ttl time.Duration) *RedisTenantStateManager {
	return &RedisTenantStateManager{
		RedisStateManager: NewRedisStateManager(client, keyPrefix, ttl),
		keyGen:            NewStateKeyGenerator("tenant"),
	}
}

// GetDefaultTenantID 获取默认租户ID
func (rtsm *RedisTenantStateManager) GetDefaultTenantID(ctx context.Context) (uint64, error) {
	key := string(DefaultTenantKey)
	value, err := rtsm.GetState(ctx, key)
	if err != nil {
		// 如果没有设置，返回默认值
		if defaultID, err := GetUint64Constant("tenant.default_id"); err == nil {
			return defaultID, nil
		}
		return 1, nil // 硬编码的最后默认值
	}

	switch v := value.(type) {
	case float64:
		return uint64(v), nil
	case int:
		return uint64(v), nil
	case string:
		tenantID, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 1, fmt.Errorf("invalid default tenant ID: %s", v)
		}
		return tenantID, nil
	default:
		return 1, fmt.Errorf("invalid default tenant ID type")
	}
}

// SetDefaultTenantID 设置默认租户ID
func (rtsm *RedisTenantStateManager) SetDefaultTenantID(ctx context.Context, tenantID uint64) error {
	key := string(DefaultTenantKey)
	return rtsm.SetState(ctx, key, tenantID)
}

// GetActiveTenantID 获取当前激活的租户ID
func (rtsm *RedisTenantStateManager) GetActiveTenantID(ctx context.Context, userID string) (uint64, error) {
	key := rtsm.keyGen.GenerateUserKey(userID, "active_tenant")
	value, err := rtsm.GetState(ctx, key)
	if err != nil {
		// 如果用户没有激活租户，返回默认租户
		return rtsm.GetDefaultTenantID(ctx)
	}

	switch v := value.(type) {
	case float64:
		return uint64(v), nil
	case int:
		return uint64(v), nil
	case string:
		tenantID, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			// 解析失败，返回默认租户
			return rtsm.GetDefaultTenantID(ctx)
		}
		return tenantID, nil
	default:
		return rtsm.GetDefaultTenantID(ctx)
	}
}

// SetActiveTenantID 设置当前激活的租户ID
func (rtsm *RedisTenantStateManager) SetActiveTenantID(ctx context.Context, userID string, tenantID uint64) error {
	key := rtsm.keyGen.GenerateUserKey(userID, "active_tenant")
	return rtsm.SetState(ctx, key, tenantID)
}

// GetTenantConfig 获取租户配置
func (rtsm *RedisTenantStateManager) GetTenantConfig(ctx context.Context, tenantID uint64) (map[string]interface{}, error) {
	key := rtsm.keyGen.GenerateTenantKey(strconv.FormatUint(tenantID, 10), "config")
	value, err := rtsm.GetState(ctx, key)
	if err != nil {
		return make(map[string]interface{}), nil
	}

	switch v := value.(type) {
	case map[string]interface{}:
		return v, nil
	default:
		return make(map[string]interface{}), nil
	}
}

// SetTenantConfig 设置租户配置
func (rtsm *RedisTenantStateManager) SetTenantConfig(ctx context.Context, tenantID uint64, config map[string]interface{}) error {
	key := rtsm.keyGen.GenerateTenantKey(strconv.FormatUint(tenantID, 10), "config")
	return rtsm.SetState(ctx, key, config)
}

// UnifiedStateManager 统一状态管理器
type UnifiedStateManager struct {
	StateManager
	DataPermissionStateManager
	TenantStateManager
	observers []StateObserver
}

// NewUnifiedStateManager 创建统一状态管理器
func NewUnifiedStateManager(
	stateManager StateManager,
	dataPermManager DataPermissionStateManager,
	tenantManager TenantStateManager,
) *UnifiedStateManager {
	return &UnifiedStateManager{
		StateManager:               stateManager,
		DataPermissionStateManager: dataPermManager,
		TenantStateManager:         tenantManager,
		observers:                  make([]StateObserver, 0),
	}
}

// AddObserver 添加状态观察者
func (usm *UnifiedStateManager) AddObserver(observer StateObserver) {
	usm.observers = append(usm.observers, observer)
}

// RemoveObserver 移除状态观察者
func (usm *UnifiedStateManager) RemoveObserver(observer StateObserver) {
	for i, obs := range usm.observers {
		if obs == observer {
			usm.observers = append(usm.observers[:i], usm.observers[i+1:]...)
			break
		}
	}
}

// SetState 设置状态（带通知）
func (usm *UnifiedStateManager) SetState(ctx context.Context, key string, value interface{}) error {
	// 获取旧值
	oldValue, _ := usm.StateManager.GetState(ctx, key)

	// 设置新值
	err := usm.StateManager.SetState(ctx, key, value)
	if err != nil {
		return err
	}

	// 通知观察者
	for _, observer := range usm.observers {
		observer.OnStateChanged(ctx, key, oldValue, value)
	}

	return nil
}

// DeleteState 删除状态（带通知）
func (usm *UnifiedStateManager) DeleteState(ctx context.Context, key string) error {
	// 获取旧值
	oldValue, _ := usm.StateManager.GetState(ctx, key)

	// 删除状态
	err := usm.StateManager.DeleteState(ctx, key)
	if err != nil {
		return err
	}

	// 通知观察者
	for _, observer := range usm.observers {
		observer.OnStateDeleted(ctx, key, oldValue)
	}

	return nil
}

// DefaultUnifiedStateManager 默认统一状态管理器实例
var defaultUnifiedStateManager *UnifiedStateManager

// InitializeDefaultStateManager 初始化默认状态管理器
func InitializeDefaultStateManager(client redis.UniversalClient, keyPrefix string, ttl time.Duration) {
	stateManager := NewRedisStateManager(client, keyPrefix, ttl)
	dataPermManager := NewRedisDataPermissionStateManager(client, keyPrefix+":dataperm", ttl)
	tenantManager := NewRedisTenantStateManager(client, keyPrefix+":tenant", ttl)

	defaultUnifiedStateManager = NewUnifiedStateManager(stateManager, dataPermManager, tenantManager)
}

// GetDefaultStateManager 获取默认状态管理器
func GetDefaultStateManager() *UnifiedStateManager {
	return defaultUnifiedStateManager
}

// 便捷函数
func GetState(ctx context.Context, key string) (interface{}, error) {
	if defaultUnifiedStateManager == nil {
		return nil, fmt.Errorf("state manager not initialized")
	}
	return defaultUnifiedStateManager.GetState(ctx, key)
}

func SetState(ctx context.Context, key string, value interface{}) error {
	if defaultUnifiedStateManager == nil {
		return fmt.Errorf("state manager not initialized")
	}
	return defaultUnifiedStateManager.SetState(ctx, key, value)
}

func GetDataPermissionScope(ctx context.Context, userID string) (uint8, error) {
	if defaultUnifiedStateManager == nil {
		return uint8(DataPermOwn), fmt.Errorf("state manager not initialized")
	}
	return defaultUnifiedStateManager.GetDataPermissionScope(ctx, userID)
}

func GetActiveTenantID(ctx context.Context, userID string) (uint64, error) {
	if defaultUnifiedStateManager == nil {
		return 1, fmt.Errorf("state manager not initialized")
	}
	return defaultUnifiedStateManager.GetActiveTenantID(ctx, userID)
}
