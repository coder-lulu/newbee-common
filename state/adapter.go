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

// StateAdapter 状态适配器，提供向后兼容的接口
type StateAdapter struct {
	stateManager *UnifiedStateManager
}

// NewStateAdapter 创建状态适配器
func NewStateAdapter(stateManager *UnifiedStateManager) *StateAdapter {
	return &StateAdapter{
		stateManager: stateManager,
	}
}

// GetDefaultTenantID 获取默认租户ID（兼容接口）
func (sa *StateAdapter) GetDefaultTenantID(ctx context.Context) uint64 {
	if sa.stateManager == nil {
		return 1 // 硬编码默认值
	}

	tenantID, err := sa.stateManager.GetDefaultTenantID(ctx)
	if err != nil {
		return 1 // 错误时返回默认值
	}

	return tenantID
}

// GetDataPermissionScope 获取数据权限范围（兼容接口）
func (sa *StateAdapter) GetDataPermissionScope(ctx context.Context, userID string) uint8 {
	if sa.stateManager == nil {
		return uint8(DataPermOwn) // 默认最严格权限
	}

	scope, err := sa.stateManager.GetDataPermissionScope(ctx, userID)
	if err != nil {
		return uint8(DataPermOwn) // 错误时返回最严格权限
	}

	return scope
}

// GetCustomDepartments 获取自定义部门权限（兼容接口）
func (sa *StateAdapter) GetCustomDepartments(ctx context.Context, userID string) []uint64 {
	if sa.stateManager == nil {
		return []uint64{}
	}

	depts, err := sa.stateManager.GetCustomDepartments(ctx, userID)
	if err != nil {
		return []uint64{}
	}

	return depts
}

// GetSubDepartments 获取子部门权限（兼容接口）
func (sa *StateAdapter) GetSubDepartments(ctx context.Context, deptID uint64) []uint64 {
	if sa.stateManager == nil {
		return []uint64{}
	}

	subDepts, err := sa.stateManager.GetSubDepartments(ctx, deptID)
	if err != nil {
		return []uint64{}
	}

	return subDepts
}

// GetUserDepartment 获取用户所属部门（兼容接口）
func (sa *StateAdapter) GetUserDepartment(ctx context.Context, userID string) uint64 {
	if sa.stateManager == nil {
		return 0
	}

	deptID, err := sa.stateManager.GetUserDepartment(ctx, userID)
	if err != nil {
		return 0
	}

	return deptID
}

// GetActiveTenantID 获取当前激活的租户ID（兼容接口）
func (sa *StateAdapter) GetActiveTenantID(ctx context.Context, userID string) uint64 {
	if sa.stateManager == nil {
		return 1
	}

	tenantID, err := sa.stateManager.GetActiveTenantID(ctx, userID)
	if err != nil {
		return 1
	}

	return tenantID
}

// 全局适配器实例
var defaultStateAdapter *StateAdapter

// InitializeStateAdapter 初始化状态适配器
func InitializeStateAdapter(stateManager *UnifiedStateManager) {
	defaultStateAdapter = NewStateAdapter(stateManager)
}

// GetDefaultStateAdapter 获取默认状态适配器
func GetDefaultStateAdapter() *StateAdapter {
	return defaultStateAdapter
}

// EnumCompat 枚举兼容性结构
type EnumCompat struct {
	adapter *StateAdapter
}

// NewEnumCompat 创建枚举兼容性结构
func NewEnumCompat(adapter *StateAdapter) *EnumCompat {
	return &EnumCompat{adapter: adapter}
}

// GetTenantDefaultId 获取默认租户ID（兼容entenum包）
func (ec *EnumCompat) GetTenantDefaultId(ctx context.Context) uint64 {
	if ec.adapter == nil {
		return 1
	}
	return ec.adapter.GetDefaultTenantID(ctx)
}

// GetDataPermAll 获取全部数据权限值
func (ec *EnumCompat) GetDataPermAll() uint8 {
	return uint8(DataPermAll)
}

// GetDataPermCustomDept 获取自定义部门数据权限值
func (ec *EnumCompat) GetDataPermCustomDept() uint8 {
	return uint8(DataPermCustomDept)
}

// GetDataPermOwnDeptAndSub 获取本部门及下属部门数据权限值
func (ec *EnumCompat) GetDataPermOwnDeptAndSub() uint8 {
	return uint8(DataPermOwnDeptAndSub)
}

// GetDataPermOwnDept 获取本部门数据权限值
func (ec *EnumCompat) GetDataPermOwnDept() uint8 {
	return uint8(DataPermOwnDept)
}

// GetDataPermOwn 获取个人数据权限值
func (ec *EnumCompat) GetDataPermOwn() uint8 {
	return uint8(DataPermOwn)
}

// 全局枚举兼容性实例
var defaultEnumCompat *EnumCompat

// InitializeEnumCompat 初始化枚举兼容性
func InitializeEnumCompat(adapter *StateAdapter) {
	defaultEnumCompat = NewEnumCompat(adapter)
}

// GetDefaultEnumCompat 获取默认枚举兼容性
func GetDefaultEnumCompat() *EnumCompat {
	return defaultEnumCompat
}

// 便捷的枚举兼容函数
func GetTenantDefaultId(ctx context.Context) uint64 {
	if defaultEnumCompat == nil {
		return 1
	}
	return defaultEnumCompat.GetTenantDefaultId(ctx)
}

func GetDataPermAll() uint8 {
	if defaultEnumCompat == nil {
		return 1
	}
	return defaultEnumCompat.GetDataPermAll()
}

func GetDataPermCustomDept() uint8 {
	if defaultEnumCompat == nil {
		return 2
	}
	return defaultEnumCompat.GetDataPermCustomDept()
}

func GetDataPermOwnDeptAndSub() uint8 {
	if defaultEnumCompat == nil {
		return 3
	}
	return defaultEnumCompat.GetDataPermOwnDeptAndSub()
}

func GetDataPermOwnDept() uint8 {
	if defaultEnumCompat == nil {
		return 4
	}
	return defaultEnumCompat.GetDataPermOwnDept()
}

func GetDataPermOwn() uint8 {
	if defaultEnumCompat == nil {
		return 5
	}
	return defaultEnumCompat.GetDataPermOwn()
}
