// Copyright 2023 The Ryan SU Authors (https://github.com/suyuan32). All Rights Reserved.
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
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
)

// DataPermissionConfig 数据权限配置
type DataPermissionConfig struct {
	// Enable 是否启用数据权限
	Enable bool `json:"enable" yaml:"enable"`
	
	// TenantMode 租户模式配置
	TenantMode *TenantModeConfig `json:"tenantMode" yaml:"tenantMode"`
	
	// Cache 缓存配置
	Cache *DataPermCacheConfig `json:"cache" yaml:"cache"`
	
	// Tables 表权限配置
	Tables []*DataPermTableConfig `json:"tables" yaml:"tables"`
	
	// DefaultScope 默认数据权限范围
	DefaultScope uint8 `json:"defaultScope" yaml:"defaultScope"`
}

// TenantModeConfig 租户模式配置
type TenantModeConfig struct {
	// Enable 是否启用租户模式
	Enable bool `json:"enable" yaml:"enable"`
	
	// DefaultTenantId 默认租户ID（非租户模式使用）
	DefaultTenantId uint64 `json:"defaultTenantId" yaml:"defaultTenantId"`
	
	// TenantField 租户字段名
	TenantField string `json:"tenantField" yaml:"tenantField"`
}

// DataPermCacheConfig 数据权限缓存配置
type DataPermCacheConfig struct {
	// Expiration 缓存过期时间（秒），0表示永不过期
	Expiration int `json:"expiration" yaml:"expiration"`
	
	// Prefix Redis键前缀
	Prefix string `json:"prefix" yaml:"prefix"`
	
	// EnableAutoRefresh 是否启用自动刷新
	EnableAutoRefresh bool `json:"enableAutoRefresh" yaml:"enableAutoRefresh"`
	
	// RefreshInterval 自动刷新间隔（秒）
	RefreshInterval int `json:"refreshInterval" yaml:"refreshInterval"`
}

// DataPermTableConfig 数据权限表配置
type DataPermTableConfig struct {
	// TableName 表名
	TableName string `json:"tableName" yaml:"tableName"`
	
	// Enable 是否启用该表的数据权限
	Enable bool `json:"enable" yaml:"enable"`
	
	// DepartmentField 部门字段名
	DepartmentField string `json:"departmentField" yaml:"departmentField"`
	
	// UserField 用户字段名，用于个人数据权限
	UserField string `json:"userField" yaml:"userField"`
	
	// TenantField 租户字段名
	TenantField string `json:"tenantField" yaml:"tenantField"`
	
	// SupportedScopes 支持的权限范围
	SupportedScopes []uint8 `json:"supportedScopes" yaml:"supportedScopes"`
	
	// CustomFilters 自定义过滤条件
	CustomFilters map[string]interface{} `json:"customFilters" yaml:"customFilters"`
}

// DefaultDataPermissionConfig 返回默认的数据权限配置
func DefaultDataPermissionConfig() *DataPermissionConfig {
	return &DataPermissionConfig{
		Enable: true,
		TenantMode: &TenantModeConfig{
			Enable:          false,
			DefaultTenantId: entenum.TenantDefaultId,
			TenantField:     "tenant_id",
		},
		Cache: &DataPermCacheConfig{
			Expiration:        0, // 永不过期
			Prefix:            "dataperm:",
			EnableAutoRefresh: false,
			RefreshInterval:   3600, // 1小时
		},
		Tables:       []*DataPermTableConfig{},
		DefaultScope: entenum.DataPermOwnDept,
	}
}

// WithTenantMode 启用租户模式
func (c *DataPermissionConfig) WithTenantMode(defaultTenantId uint64) *DataPermissionConfig {
	c.TenantMode.Enable = true
	c.TenantMode.DefaultTenantId = defaultTenantId
	return c
}

// WithCache 设置缓存配置
func (c *DataPermissionConfig) WithCache(expiration int, prefix string) *DataPermissionConfig {
	c.Cache.Expiration = expiration
	c.Cache.Prefix = prefix
	return c
}

// AddTable 添加表配置
func (c *DataPermissionConfig) AddTable(config *DataPermTableConfig) *DataPermissionConfig {
	c.Tables = append(c.Tables, config)
	return c
}

// AddTables 批量添加表配置
func (c *DataPermissionConfig) AddTables(configs ...*DataPermTableConfig) *DataPermissionConfig {
	c.Tables = append(c.Tables, configs...)
	return c
}

// NewDataPermTableConfig 创建新的表权限配置
func NewDataPermTableConfig(tableName string) *DataPermTableConfig {
	return &DataPermTableConfig{
		TableName:       tableName,
		Enable:          true,
		DepartmentField: "department_id",
		UserField:       "user_id",
		TenantField:     "tenant_id",
		SupportedScopes: []uint8{
			entenum.DataPermAll,
			entenum.DataPermCustomDept,
			entenum.DataPermOwnDeptAndSub,
			entenum.DataPermOwnDept,
			entenum.DataPermSelf,
		},
		CustomFilters: make(map[string]interface{}),
	}
}

// WithDepartmentField 设置部门字段
func (t *DataPermTableConfig) WithDepartmentField(field string) *DataPermTableConfig {
	t.DepartmentField = field
	return t
}

// WithUserField 设置用户字段
func (t *DataPermTableConfig) WithUserField(field string) *DataPermTableConfig {
	t.UserField = field
	return t
}

// WithTenantField 设置租户字段
func (t *DataPermTableConfig) WithTenantField(field string) *DataPermTableConfig {
	t.TenantField = field
	return t
}

// WithSupportedScopes 设置支持的权限范围
func (t *DataPermTableConfig) WithSupportedScopes(scopes ...uint8) *DataPermTableConfig {
	t.SupportedScopes = scopes
	return t
}

// WithCustomFilter 添加自定义过滤条件
func (t *DataPermTableConfig) WithCustomFilter(key string, value interface{}) *DataPermTableConfig {
	t.CustomFilters[key] = value
	return t
}

// IsScopeSupported 检查是否支持指定的权限范围
func (t *DataPermTableConfig) IsScopeSupported(scope uint8) bool {
	for _, s := range t.SupportedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// GetTableConfig 根据表名获取表配置
func (c *DataPermissionConfig) GetTableConfig(tableName string) *DataPermTableConfig {
	for _, table := range c.Tables {
		if table.TableName == tableName {
			return table
		}
	}
	return nil
}

// IsTableEnabled 检查表是否启用数据权限
func (c *DataPermissionConfig) IsTableEnabled(tableName string) bool {
	config := c.GetTableConfig(tableName)
	return config != nil && config.Enable
}

// PresetConfigs 预设的表配置
var PresetConfigs = map[string]*DataPermTableConfig{
	"users": NewDataPermTableConfig("users").
		WithUserField("id").
		WithDepartmentField("department_id"),
	
	"departments": NewDataPermTableConfig("departments").
		WithDepartmentField("id").
		WithSupportedScopes(entenum.DataPermAll, entenum.DataPermOwnDeptAndSub),
	
	"roles": NewDataPermTableConfig("roles").
		WithSupportedScopes(entenum.DataPermAll, entenum.DataPermCustomDept),
	
	"positions": NewDataPermTableConfig("positions").
		WithDepartmentField("department_id"),
	
	"tokens": NewDataPermTableConfig("tokens").
		WithUserField("user_id").
		WithSupportedScopes(entenum.DataPermSelf),
}

// GetPresetConfig 获取预设配置
func GetPresetConfig(tableName string) *DataPermTableConfig {
	if config, exists := PresetConfigs[tableName]; exists {
		// 返回副本避免修改原始配置
		newConfig := *config
		return &newConfig
	}
	return nil
}

// BuildConfigFromPresets 从预设配置构建完整配置
func BuildConfigFromPresets(tableNames ...string) *DataPermissionConfig {
	config := DefaultDataPermissionConfig()
	
	for _, tableName := range tableNames {
		if presetConfig := GetPresetConfig(tableName); presetConfig != nil {
			config.AddTable(presetConfig)
		} else {
			// 使用默认配置
			config.AddTable(NewDataPermTableConfig(tableName))
		}
	}
	
	return config
}