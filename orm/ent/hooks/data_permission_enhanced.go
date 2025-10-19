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
	"fmt"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"

	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/coder-lulu/newbee-common/state"
)

// EnhancedDataPermissionConfig 增强的数据权限配置
type EnhancedDataPermissionConfig struct {
	// 是否启用数据权限控制
	Enabled bool
	
	// 需要进行数据权限控制的字段名称（通常是 department_id）
	DepartmentField string
	
	// 需要进行数据权限控制的用户字段名称（通常是 created_by 或 user_id）
	UserField string
	
	// 是否在系统上下文中跳过数据权限检查
	SkipSystemContext bool
	
	// 是否使用状态管理器
	UseStateManager bool
}

// DefaultEnhancedDataPermissionConfig 返回默认的增强数据权限配置
func DefaultEnhancedDataPermissionConfig() *EnhancedDataPermissionConfig {
	return &EnhancedDataPermissionConfig{
		Enabled:           true,
		DepartmentField:   "department_id",
		UserField:         "created_by",
		SkipSystemContext: true,
		UseStateManager:   true, // 默认启用状态管理器
	}
}

// NewEnhancedDataPermissionInterceptor 创建增强的数据权限拦截器
// 这个拦截器优先使用状态管理器，降级为传统方式
func NewEnhancedDataPermissionInterceptor(config *EnhancedDataPermissionConfig) ent.Interceptor {
	if config == nil {
		config = DefaultEnhancedDataPermissionConfig()
	}
	
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// 如果数据权限控制未启用，直接执行查询
			if !config.Enabled {
				return next.Query(ctx, query)
			}
			
			// 如果是系统上下文且配置为跳过，则直接执行查询
			if config.SkipSystemContext && IsSystemContext(ctx) {
				return next.Query(ctx, query)
			}
			
			// 应用增强的数据权限过滤
			if err := applyEnhancedDataPermissionFilter(ctx, query, config); err != nil {
				return nil, fmt.Errorf("failed to apply enhanced data permission filter: %w", err)
			}
			
			return next.Query(ctx, query)
		})
	})
}

// applyEnhancedDataPermissionFilter 应用增强的数据权限过滤逻辑
func applyEnhancedDataPermissionFilter(ctx context.Context, query ent.Query, config *EnhancedDataPermissionConfig) error {
	var dataScope uint8
	
	// 优先使用状态管理器获取数据权限范围
	if config.UseStateManager {
		// 从上下文获取用户ID
		userID, userErr := datapermctx.GetUserIDFromCtx(ctx)
		if userErr == nil && userID != "" {
			// 使用状态管理器获取数据权限范围
			if adapter := state.GetDefaultStateAdapter(); adapter != nil {
				dataScope = adapter.GetDataPermissionScope(ctx, userID)
			} else {
				// 状态管理器未初始化，降级为传统方式
				rawScope, rawErr := datapermctx.GetScopeFromCtx(ctx)
				if rawErr != nil {
					dataScope = state.DataPermOwn.Value() // 使用状态管理器的常量
				} else {
					dataScope = uint8(rawScope) // 转换类型
				}
			}
		} else {
			// 无法获取用户ID，降级为传统方式
			rawScope, rawErr := datapermctx.GetScopeFromCtx(ctx)
			if rawErr != nil {
				dataScope = state.DataPermOwn.Value()
			} else {
				dataScope = uint8(rawScope) // 转换类型
			}
		}
	} else {
		// 使用传统方式获取数据权限范围
		rawScope, rawErr := datapermctx.GetScopeFromCtx(ctx)
		if rawErr != nil {
			dataScope = state.DataPermOwn.Value()
		} else {
			dataScope = uint8(rawScope) // 转换类型
		}
	}
	
	// 根据数据权限范围应用过滤条件
	switch state.DataPermScope(dataScope) {
	case state.DataPermAll:
		// 全部数据权限：不添加任何过滤条件
		return nil
		
	case state.DataPermCustomDept:
		// 自定义部门数据权限
		return applyEnhancedCustomDeptFilter(ctx, query, config)
		
	case state.DataPermOwnDeptAndSub:
		// 本部门及下属部门数据权限
		return applyEnhancedSubDeptFilter(ctx, query, config)
		
	case state.DataPermOwnDept:
		// 本部门数据权限
		return applyEnhancedOwnDeptFilter(ctx, query, config)
		
	case state.DataPermOwn:
		// 个人数据权限：只能查看自己创建的数据
		return applyEnhancedUserDataFilter(ctx, query, config)
		
	default:
		// 未知的数据权限范围，默认为最严格的权限
		return applyEnhancedUserDataFilter(ctx, query, config)
	}
}

// applyEnhancedCustomDeptFilter 应用增强的自定义部门过滤条件
func applyEnhancedCustomDeptFilter(ctx context.Context, query ent.Query, config *EnhancedDataPermissionConfig) error {
	var customDeptIds []uint64
	var err error
	
	// 优先使用状态管理器
	if config.UseStateManager {
		userID, userErr := datapermctx.GetUserIDFromCtx(ctx)
		if userErr == nil && userID != "" {
			if adapter := state.GetDefaultStateAdapter(); adapter != nil {
				customDeptIds = adapter.GetCustomDepartments(ctx, userID)
			} else {
				// 降级为传统方式
				customDeptIds, err = datapermctx.GetCustomDeptFromCtx(ctx)
				if err != nil {
					return applyEnhancedUserDataFilter(ctx, query, config)
				}
			}
		} else {
			customDeptIds, err = datapermctx.GetCustomDeptFromCtx(ctx)
			if err != nil {
				return applyEnhancedUserDataFilter(ctx, query, config)
			}
		}
	} else {
		customDeptIds, err = datapermctx.GetCustomDeptFromCtx(ctx)
		if err != nil {
			return applyEnhancedUserDataFilter(ctx, query, config)
		}
	}
	
	// 确保自定义部门ID不为空
	if len(customDeptIds) == 0 {
		return applyEnhancedUserDataFilter(ctx, query, config)
	}
	
	// 应用部门过滤条件
	return applyDepartmentFilter(query, config.DepartmentField, convertUint64ToStringSlice(customDeptIds))
}

// applyEnhancedSubDeptFilter 应用增强的子部门过滤条件
func applyEnhancedSubDeptFilter(ctx context.Context, query ent.Query, config *EnhancedDataPermissionConfig) error {
	var userDeptId uint64
	var subDeptIds []uint64
	var err error
	
	// 优先使用状态管理器获取用户部门
	if config.UseStateManager {
		userID, userErr := datapermctx.GetUserIDFromCtx(ctx)
		if userErr == nil && userID != "" {
			if adapter := state.GetDefaultStateAdapter(); adapter != nil {
				userDeptId = adapter.GetUserDepartment(ctx, userID)
				subDeptIds = adapter.GetSubDepartments(ctx, userDeptId)
			} else {
				// 降级为传统方式
				userDeptId, err = datapermctx.GetUserDeptFromCtx(ctx)
				if err != nil {
					return applyEnhancedUserDataFilter(ctx, query, config)
				}
				subDeptIds, err = datapermctx.GetSubDeptFromCtx(ctx)
				if err != nil {
					return applyEnhancedUserDataFilter(ctx, query, config)
				}
			}
		} else {
			userDeptId, err = datapermctx.GetUserDeptFromCtx(ctx)
			if err != nil {
				return applyEnhancedUserDataFilter(ctx, query, config)
			}
			subDeptIds, err = datapermctx.GetSubDeptFromCtx(ctx)
			if err != nil {
				return applyEnhancedUserDataFilter(ctx, query, config)
			}
		}
	} else {
		userDeptId, err = datapermctx.GetUserDeptFromCtx(ctx)
		if err != nil {
			return applyEnhancedUserDataFilter(ctx, query, config)
		}
		subDeptIds, err = datapermctx.GetSubDeptFromCtx(ctx)
		if err != nil {
			return applyEnhancedUserDataFilter(ctx, query, config)
		}
	}
	
	// 确保部门ID有效
	if userDeptId == 0 {
		return applyEnhancedUserDataFilter(ctx, query, config)
	}
	
	// 将用户部门和子部门合并
	allDeptIds := append([]uint64{userDeptId}, subDeptIds...)
	
	return applyDepartmentFilter(query, config.DepartmentField, convertUint64ToStringSlice(allDeptIds))
}

// applyEnhancedOwnDeptFilter 应用增强的本部门过滤条件
func applyEnhancedOwnDeptFilter(ctx context.Context, query ent.Query, config *EnhancedDataPermissionConfig) error {
	var userDeptId uint64
	var err error
	
	// 优先使用状态管理器
	if config.UseStateManager {
		userID, userErr := datapermctx.GetUserIDFromCtx(ctx)
		if userErr == nil && userID != "" {
			if adapter := state.GetDefaultStateAdapter(); adapter != nil {
				userDeptId = adapter.GetUserDepartment(ctx, userID)
			} else {
				// 降级为传统方式
				userDeptId, err = datapermctx.GetUserDeptFromCtx(ctx)
				if err != nil {
					return applyEnhancedUserDataFilter(ctx, query, config)
				}
			}
		} else {
			userDeptId, err = datapermctx.GetUserDeptFromCtx(ctx)
			if err != nil {
				return applyEnhancedUserDataFilter(ctx, query, config)
			}
		}
	} else {
		userDeptId, err = datapermctx.GetUserDeptFromCtx(ctx)
		if err != nil {
			return applyEnhancedUserDataFilter(ctx, query, config)
		}
	}
	
	if userDeptId == 0 {
		return applyEnhancedUserDataFilter(ctx, query, config)
	}
	
	return applyDepartmentFilter(query, config.DepartmentField, []string{fmt.Sprintf("%d", userDeptId)})
}

// applyEnhancedUserDataFilter 应用增强的用户数据过滤条件
func applyEnhancedUserDataFilter(ctx context.Context, query ent.Query, config *EnhancedDataPermissionConfig) error {
	// 获取当前用户ID
	userId, err := datapermctx.GetUserIDFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get user id from context: %w", err)
	}
	
	if userId == "" {
		return fmt.Errorf("user id is required for data permission filtering")
	}
	
	// Method 1: Try Modify interface (most efficient)
	if modifyQuery, ok := query.(interface{ Modify(func(*sql.Selector)) }); ok {
		modifyQuery.Modify(func(s *sql.Selector) {
			s.Where(sql.EQ(s.C(config.UserField), userId))
		})
		return nil
	}
	
	// Method 2: Try Where interface
	type whereQuery interface {
		Where(...func(*sql.Selector))
	}
	if whereQ, ok := query.(whereQuery); ok {
		whereQ.Where(func(selector *sql.Selector) {
			selector.Where(sql.EQ(config.UserField, userId))
		})
		return nil
	}
	
	// Method 3: Try WhereP if available
	type wherePQuery interface {
		WhereP(func(*sql.Selector))
	}
	if wherePQ, ok := query.(wherePQuery); ok {
		wherePQ.WhereP(func(selector *sql.Selector) {
			sql.FieldEQ(config.UserField, userId)(selector)
		})
		return nil
	}
	
	// If no method works, continue without modification (log warning)
	return fmt.Errorf("query type %T does not support where conditions", query)
}

// 辅助函数
func convertUint64ToStringSlice(ids []uint64) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = fmt.Sprintf("%d", id)
	}
	return result
}

// GetEnhancedDataPermissionInterceptor 获取标准增强数据权限拦截器
// 使用默认配置的便捷方法
func GetEnhancedDataPermissionInterceptor() ent.Interceptor {
	return NewEnhancedDataPermissionInterceptor(DefaultEnhancedDataPermissionConfig())
}

// GetLegacyCompatibleDataPermissionInterceptor 获取兼容传统方式的数据权限拦截器
// 不使用状态管理器，保持与原有代码的兼容性
func GetLegacyCompatibleDataPermissionInterceptor() ent.Interceptor {
	config := DefaultEnhancedDataPermissionConfig()
	config.UseStateManager = false // 禁用状态管理器
	return NewEnhancedDataPermissionInterceptor(config)
}