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

package hooks

import (
	"context"
	"errors"
	"sync"

	"github.com/coder-lulu/newbee-common/orm/ent/entctx/deptctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
	"github.com/zeromicro/go-zero/core/logx"
)

// Hook系统状态管理（防止新旧Hook系统冲突）
var (
	hookSystemInitialized bool
	hookSystemMutex       sync.Mutex
	hookSystemType        string // "new" or "legacy"
)

// InitDefaultHookConfigs 初始化默认的Hook配置
// 这个函数应该在应用启动时调用一次
func InitDefaultHookConfigs() {
	// 注册租户Hook配置
	GlobalHookManager.RegisterField(&FieldConfig{
		FieldName:         "tenant_id",
		FieldType:         FieldTypeTenant,
		SetterMethod:      "SetTenantID",
		GetterMethod:      "TenantID",
		ContextExtractor:  fromContext,
		ShouldApplyFilter: shouldApplyTenantFilter,
		IsSystemContext:   isSystemContext,
		ExcludedEntities: []string{
			"Tenant",        // 租户表自身不需要租户过滤
			"AuditLog",      // 审计日志表：租户ID作为普通字段手动管理
			"API",           // API接口表：系统级数据
			"OauthProvider", // OAuth提供商表：系统级数据
			"OauthSession",  // OAuth会话表：系统级数据
			"CasbinRule",    // Casbin规则表：系统级数据
		},
		RequireValue:     true, // 租户ID严格模式
		DefaultValue:     entenum.TenantDefaultId,
		SecurityCritical: true, // 🔒 安全关键字段：宽松模式下缺少值时返回空结果
	})

	// 注册部门Hook配置
	GlobalHookManager.RegisterField(&FieldConfig{
		FieldName:    "department_id",
		FieldType:    FieldTypeDepartment,
		SetterMethod: "SetDepartmentID",
		GetterMethod: "DepartmentID",
		ContextExtractor: func(ctx context.Context) (uint64, error) {
			deptID, err := deptctx.GetDepartmentIDFromCtx(ctx)
			if err != nil || deptID == 0 {
				return 0, err
			}
			return deptID, nil
		},
		ShouldApplyFilter: func(tableName string) bool {
			// 部门过滤通常由数据权限中间件处理
			// 这里返回false表示不在query hook中强制过滤
			return false
		},
		IsSystemContext: isSystemContext,
		ExcludedEntities: []string{
			// 核心系统表
			"Tenant",        // 租户表
			"Department",    // 部门表自身
			"AuditLog",      // 审计日志表：无department_id字段
			"API",           // API接口表：系统级数据
			"OauthProvider", // OAuth提供商表：系统级数据
			"CasbinRule",    // Casbin规则表：系统级数据

			// 字典系统（系统级数据）
			"Dictionary",       // ✅ 字典表：系统级数据，无department_id字段
			"DictionaryDetail", // ✅ 字典详情表：系统级数据，无department_id字段

			// 系统配置
			"Configuration", // ✅ 配置表：系统级数据，无department_id字段
			"Menu",          // ✅ 菜单表：无department_id字段

			// 使用Field定义的表（有department_id但通过Field直接管理）
			"Token",        // ✅ Token表：使用Field定义department_id
			"OauthAccount", // ✅ OAuth账号表：使用Field定义department_id
			"OauthSession", // ✅ OAuth会话表：使用Field定义department_id

			// 使用非标准字段名的表
			"Position", // ✅ 职位表：使用Field定义dept_id（非department_id）
			"Role",     // ✅ 角色表：使用JSON字段custom_dept_ids（非department_id）
		},
		RequireValue:     false, // 部门ID宽松模式（不是所有实体都需要）
		DefaultValue:     0,
		SecurityCritical: false, // 普通字段：宽松模式下缺少值时跳过过滤
	})

	logx.Infow("Default hook configs initialized successfully",
		logx.Field("tenant_hook", "enabled"),
		logx.Field("department_hook", "enabled"))
}

// RegisterTenantHooks 仅注册租户相关的hooks（向后兼容）
// 等同于旧版的 TenantMutationHook() 和 TenantQueryInterceptor()
func RegisterTenantHooks(client interface{}) error {
	return RegisterHooksToClient(client, FieldTypeTenant)
}

// RegisterDepartmentHooksUnified 仅注册部门相关的hooks（向后兼容）
// 等同于旧版的 DepartmentMutationHook()
func RegisterDepartmentHooksUnified(client interface{}) error {
	return RegisterHooksToClient(client, FieldTypeDepartment)
}

// RegisterAllHooks 注册所有已配置的hooks
// 这是推荐的用法，一次性注册所有hooks
func RegisterAllHooks(client interface{}) error {
	return RegisterHooksToClient(client)
}

// QuickSetup 快速设置（初始化配置 + 注册所有hooks）
// 最简单的使用方式，适用于大多数场景
func QuickSetup(client interface{}) error {
	hookSystemMutex.Lock()
	defer hookSystemMutex.Unlock()

	// 🔒 互斥检测：防止与旧版Hook系统冲突
	if hookSystemInitialized {
		if hookSystemType == "legacy" {
			return errors.New(
				"hook system conflict: legacy hooks already registered. " +
					"Do not mix TenantMutationHook() with QuickSetup()")
		}
		// 已经用新Hook初始化过，允许（幂等）
		logx.Infow("Hook system already initialized, skipping duplicate setup")
		return nil
	}

	// 初始化默认配置
	InitDefaultHookConfigs()

	// 注册所有hooks
	if err := RegisterAllHooks(client); err != nil {
		return err
	}

	// 标记已初始化
	hookSystemInitialized = true
	hookSystemType = "new"

	logx.Infow("✅ Hook system initialized successfully",
		logx.Field("system_type", "unified_hook_manager"),
		logx.Field("version", "2.0"))

	return nil
}
