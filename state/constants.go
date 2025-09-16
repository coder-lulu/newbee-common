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
	"fmt"
)

// StateKey 状态键类型
type StateKey string

// 数据权限相关常量
const (
	// 数据权限范围状态键
	DataPermScopeKey StateKey = "data_perm:scope"

	// 自定义部门权限状态键
	CustomDeptKey StateKey = "data_perm:custom_dept"

	// 子部门权限状态键
	SubDeptKey StateKey = "data_perm:sub_dept"

	// 用户部门状态键
	UserDeptKey StateKey = "user:dept"

	// 租户相关状态键
	DefaultTenantKey StateKey = "tenant:default"
	ActiveTenantKey  StateKey = "tenant:active"
	TenantConfigKey  StateKey = "tenant:config"
)

// DataPermScope 数据权限范围枚举
type DataPermScope uint8

const (
	// DataPermAll 全部数据权限
	DataPermAll DataPermScope = 1

	// DataPermCustomDept 自定义部门数据权限
	DataPermCustomDept DataPermScope = 2

	// DataPermOwnDeptAndSub 本部门及下属部门数据权限
	DataPermOwnDeptAndSub DataPermScope = 3

	// DataPermOwnDept 本部门数据权限
	DataPermOwnDept DataPermScope = 4

	// DataPermOwn 个人数据权限
	DataPermOwn DataPermScope = 5
)

// String 返回数据权限范围的字符串表示
func (d DataPermScope) String() string {
	switch d {
	case DataPermAll:
		return "all"
	case DataPermCustomDept:
		return "custom_dept"
	case DataPermOwnDeptAndSub:
		return "own_dept_and_sub"
	case DataPermOwnDept:
		return "own_dept"
	case DataPermOwn:
		return "own"
	default:
		return "unknown"
	}
}

// Value 返回数据权限范围的数值
func (d DataPermScope) Value() uint8 {
	return uint8(d)
}

// DataPermScopeFromValue 从数值创建数据权限范围
func DataPermScopeFromValue(value uint8) DataPermScope {
	switch value {
	case 1:
		return DataPermAll
	case 2:
		return DataPermCustomDept
	case 3:
		return DataPermOwnDeptAndSub
	case 4:
		return DataPermOwnDept
	case 5:
		return DataPermOwn
	default:
		return DataPermOwn // 默认最严格权限
	}
}

// IsValid 检查数据权限范围是否有效
func (d DataPermScope) IsValid() bool {
	return d >= DataPermAll && d <= DataPermOwn
}

// ConstantManager 常量管理器
type ConstantManager struct {
	constants map[string]interface{}
}

// NewConstantManager 创建新的常量管理器
func NewConstantManager() *ConstantManager {
	return &ConstantManager{
		constants: make(map[string]interface{}),
	}
}

// SetConstant 设置常量
func (cm *ConstantManager) SetConstant(key string, value interface{}) {
	cm.constants[key] = value
}

// GetConstant 获取常量
func (cm *ConstantManager) GetConstant(key string) (interface{}, bool) {
	value, exists := cm.constants[key]
	return value, exists
}

// GetString 获取字符串常量
func (cm *ConstantManager) GetString(key string) (string, error) {
	value, exists := cm.constants[key]
	if !exists {
		return "", fmt.Errorf("constant %s not found", key)
	}

	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("constant %s is not a string", key)
	}

	return str, nil
}

// GetUint64 获取uint64常量
func (cm *ConstantManager) GetUint64(key string) (uint64, error) {
	value, exists := cm.constants[key]
	if !exists {
		return 0, fmt.Errorf("constant %s not found", key)
	}

	switch v := value.(type) {
	case uint64:
		return v, nil
	case int:
		return uint64(v), nil
	case int64:
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("constant %s cannot be converted to uint64", key)
	}
}

// GetUint8 获取uint8常量
func (cm *ConstantManager) GetUint8(key string) (uint8, error) {
	value, exists := cm.constants[key]
	if !exists {
		return 0, fmt.Errorf("constant %s not found", key)
	}

	switch v := value.(type) {
	case uint8:
		return v, nil
	case int:
		return uint8(v), nil
	case int64:
		return uint8(v), nil
	case uint64:
		return uint8(v), nil
	default:
		return 0, fmt.Errorf("constant %s cannot be converted to uint8", key)
	}
}

// Initialize 初始化默认常量
func (cm *ConstantManager) Initialize() {
	// 初始化默认租户ID
	cm.SetConstant("tenant.default_id", uint64(1))

	// 初始化数据权限范围常量
	cm.SetConstant("data_perm.all", uint8(DataPermAll))
	cm.SetConstant("data_perm.custom_dept", uint8(DataPermCustomDept))
	cm.SetConstant("data_perm.own_dept_and_sub", uint8(DataPermOwnDeptAndSub))
	cm.SetConstant("data_perm.own_dept", uint8(DataPermOwnDept))
	cm.SetConstant("data_perm.own", uint8(DataPermOwn))
}

// 全局常量管理器实例
var defaultConstantManager = NewConstantManager()

func init() {
	defaultConstantManager.Initialize()
}

// GetDefaultConstantManager 获取默认常量管理器
func GetDefaultConstantManager() *ConstantManager {
	return defaultConstantManager
}

// 便捷函数
func GetConstant(key string) (interface{}, bool) {
	return defaultConstantManager.GetConstant(key)
}

func GetStringConstant(key string) (string, error) {
	return defaultConstantManager.GetString(key)
}

func GetUint64Constant(key string) (uint64, error) {
	return defaultConstantManager.GetUint64(key)
}

func GetUint8Constant(key string) (uint8, error) {
	return defaultConstantManager.GetUint8(key)
}

// 状态键生成器
type StateKeyGenerator struct {
	prefix string
}

// NewStateKeyGenerator 创建状态键生成器
func NewStateKeyGenerator(prefix string) *StateKeyGenerator {
	return &StateKeyGenerator{prefix: prefix}
}

// GenerateKey 生成状态键
func (skg *StateKeyGenerator) GenerateKey(parts ...string) string {
	key := skg.prefix
	for _, part := range parts {
		key += ":" + part
	}
	return key
}

// GenerateUserKey 生成用户相关的状态键
func (skg *StateKeyGenerator) GenerateUserKey(userID string, suffix string) string {
	return skg.GenerateKey("user", userID, suffix)
}

// GenerateTenantKey 生成租户相关的状态键
func (skg *StateKeyGenerator) GenerateTenantKey(tenantID string, suffix string) string {
	return skg.GenerateKey("tenant", tenantID, suffix)
}

// GenerateDeptKey 生成部门相关的状态键
func (skg *StateKeyGenerator) GenerateDeptKey(deptID string, suffix string) string {
	return skg.GenerateKey("dept", deptID, suffix)
}
