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
)

// StateManager 状态管理器接口
type StateManager interface {
	// GetState 获取指定键的状态值
	GetState(ctx context.Context, key string) (interface{}, error)

	// SetState 设置指定键的状态值
	SetState(ctx context.Context, key string, value interface{}) error

	// DeleteState 删除指定键的状态
	DeleteState(ctx context.Context, key string) error

	// GetStates 批量获取状态
	GetStates(ctx context.Context, keys []string) (map[string]interface{}, error)

	// SetStates 批量设置状态
	SetStates(ctx context.Context, states map[string]interface{}) error

	// ListStates 列出所有状态键
	ListStates(ctx context.Context, prefix string) ([]string, error)
}

// DataPermissionStateManager 数据权限状态管理器
type DataPermissionStateManager interface {
	// GetDataPermissionScope 获取数据权限范围
	GetDataPermissionScope(ctx context.Context, userID string) (uint8, error)

	// SetDataPermissionScope 设置数据权限范围
	SetDataPermissionScope(ctx context.Context, userID string, scope uint8) error

	// GetCustomDepartments 获取自定义部门权限
	GetCustomDepartments(ctx context.Context, userID string) ([]uint64, error)

	// SetCustomDepartments 设置自定义部门权限
	SetCustomDepartments(ctx context.Context, userID string, deptIDs []uint64) error

	// GetSubDepartments 获取子部门权限
	GetSubDepartments(ctx context.Context, deptID uint64) ([]uint64, error)

	// SetSubDepartments 设置子部门权限
	SetSubDepartments(ctx context.Context, deptID uint64, subDeptIDs []uint64) error

	// GetUserDepartment 获取用户所属部门
	GetUserDepartment(ctx context.Context, userID string) (uint64, error)

	// SetUserDepartment 设置用户所属部门
	SetUserDepartment(ctx context.Context, userID string, deptID uint64) error
}

// TenantStateManager 租户状态管理器
type TenantStateManager interface {
	// GetDefaultTenantID 获取默认租户ID
	GetDefaultTenantID(ctx context.Context) (uint64, error)

	// SetDefaultTenantID 设置默认租户ID
	SetDefaultTenantID(ctx context.Context, tenantID uint64) error

	// GetActiveTenantID 获取当前激活的租户ID
	GetActiveTenantID(ctx context.Context, userID string) (uint64, error)

	// SetActiveTenantID 设置当前激活的租户ID
	SetActiveTenantID(ctx context.Context, userID string, tenantID uint64) error

	// GetTenantConfig 获取租户配置
	GetTenantConfig(ctx context.Context, tenantID uint64) (map[string]interface{}, error)

	// SetTenantConfig 设置租户配置
	SetTenantConfig(ctx context.Context, tenantID uint64, config map[string]interface{}) error
}

// StateProvider 状态提供者接口
type StateProvider interface {
	// GetName 获取提供者名称
	GetName() string

	// Initialize 初始化提供者
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Close 关闭提供者
	Close(ctx context.Context) error

	// HealthCheck 健康检查
	HealthCheck(ctx context.Context) error
}

// StateObserver 状态观察者接口
type StateObserver interface {
	// OnStateChanged 状态变更通知
	OnStateChanged(ctx context.Context, key string, oldValue, newValue interface{})

	// OnStateDeleted 状态删除通知
	OnStateDeleted(ctx context.Context, key string, oldValue interface{})
}

// StateBroadcaster 状态广播器接口
type StateBroadcaster interface {
	// Subscribe 订阅状态变更
	Subscribe(ctx context.Context, pattern string, observer StateObserver) error

	// Unsubscribe 取消订阅
	Unsubscribe(ctx context.Context, pattern string, observer StateObserver) error

	// Broadcast 广播状态变更
	Broadcast(ctx context.Context, key string, oldValue, newValue interface{}) error
}

// CacheableStateManager 可缓存的状态管理器
type CacheableStateManager interface {
	StateManager

	// InvalidateCache 使缓存失效
	InvalidateCache(ctx context.Context, key string) error

	// InvalidatePattern 使模式匹配的缓存失效
	InvalidatePattern(ctx context.Context, pattern string) error

	// GetCacheStats 获取缓存统计
	GetCacheStats(ctx context.Context) (map[string]interface{}, error)
}

// AsyncStateManager 异步状态管理器
type AsyncStateManager interface {
	StateManager

	// SetStateAsync 异步设置状态
	SetStateAsync(ctx context.Context, key string, value interface{}) <-chan error

	// SetStatesAsync 异步批量设置状态
	SetStatesAsync(ctx context.Context, states map[string]interface{}) <-chan error

	// DeleteStateAsync 异步删除状态
	DeleteStateAsync(ctx context.Context, key string) <-chan error
}
