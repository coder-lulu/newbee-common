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
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
)

// DataPermissionConfig 数据权限配置
type DataPermissionConfig struct {
	// 是否启用数据权限控制
	Enabled bool
	
	// 需要进行数据权限控制的字段名称（通常是 department_id）
	DepartmentField string
	
	// 需要进行数据权限控制的用户字段名称（通常是 created_by 或 user_id）
	UserField string
	
	// 是否在系统上下文中跳过数据权限检查
	SkipSystemContext bool
}

// DefaultDataPermissionConfig 返回默认的数据权限配置
func DefaultDataPermissionConfig() *DataPermissionConfig {
	return &DataPermissionConfig{
		Enabled:           true,
		DepartmentField:   "department_id",
		UserField:         "created_by",
		SkipSystemContext: true,
	}
}

// NewDataPermissionInterceptor 创建数据权限拦截器
// 这个拦截器可以在任何 schema 中使用，避免代码重复
func NewDataPermissionInterceptor(config *DataPermissionConfig) ent.Interceptor {
	if config == nil {
		config = DefaultDataPermissionConfig()
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
			
			// 应用数据权限过滤
			if err := applyDataPermissionFilter(ctx, query, config); err != nil {
				return nil, fmt.Errorf("failed to apply data permission filter: %w", err)
			}
			
			return next.Query(ctx, query)
		})
	})
}

// applyDataPermissionFilter 应用数据权限过滤逻辑
func applyDataPermissionFilter(ctx context.Context, query ent.Query, config *DataPermissionConfig) error {
	// 获取数据权限范围
	dataScope, err := datapermctx.GetScopeFromCtx(ctx)
	if err != nil {
		// 如果没有数据权限上下文，默认只能查看自己的数据
		dataScope = entenum.DataPermOwn
	}
	
	// 根据数据权限范围应用过滤条件
	switch dataScope {
	case entenum.DataPermAll:
		// 全部数据权限：不添加任何过滤条件
		return nil
		
	case entenum.DataPermCustomDept:
		// 自定义部门数据权限
		customDeptIds, err := datapermctx.GetCustomDeptFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get custom dept ids: %w", err)
		}
		
		// 确保自定义部门ID不为空
		if len(customDeptIds) == 0 {
			// 如果没有自定义部门，降级为只能查看自己的数据
			return applyUserDataFilter(ctx, query, config)
		}
		
		// 将 uint64 转换为字符串
		customDeptIdStrs := make([]string, len(customDeptIds))
		for i, id := range customDeptIds {
			customDeptIdStrs[i] = fmt.Sprintf("%d", id)
		}
		
		return applyDepartmentFilter(query, config.DepartmentField, customDeptIdStrs)
		
	case entenum.DataPermOwnDeptAndSub:
		// 本部门及下属部门数据权限
		subDeptIds, err := datapermctx.GetSubDeptFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get sub dept ids: %w", err)
		}
		
		// 确保部门ID不为空
		if len(subDeptIds) == 0 {
			// 如果没有部门信息，降级为只能查看自己的数据
			return applyUserDataFilter(ctx, query, config)
		}
		
		// 将 uint64 转换为字符串
		subDeptIdStrs := make([]string, len(subDeptIds))
		for i, id := range subDeptIds {
			subDeptIdStrs[i] = fmt.Sprintf("%d", id)
		}
		
		return applyDepartmentFilter(query, config.DepartmentField, subDeptIdStrs)
		
	case entenum.DataPermOwnDept:
		// 本部门数据权限
		userDeptId, err := datapermctx.GetUserDeptFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get user dept id: %w", err)
		}
		
		if userDeptId == 0 {
			// 如果没有部门信息，降级为只能查看自己的数据
			return applyUserDataFilter(ctx, query, config)
		}
		
		return applyDepartmentFilter(query, config.DepartmentField, []string{fmt.Sprintf("%d", userDeptId)})
		
	case entenum.DataPermOwn:
		// 个人数据权限：只能查看自己创建的数据
		return applyUserDataFilter(ctx, query, config)
		
	default:
		// 未知的数据权限范围，默认为最严格的权限
		return applyUserDataFilter(ctx, query, config)
	}
}

// applyDepartmentFilter 应用部门过滤条件
func applyDepartmentFilter(query ent.Query, deptField string, deptIds []string) error {
	// 将字符串ID转换为整型
	intIds := make([]interface{}, len(deptIds))
	for i, id := range deptIds {
		intIds[i] = id
	}
	
	// Method 1: Try Modify interface (most efficient)
	if modifyQuery, ok := query.(interface{ Modify(func(*sql.Selector)) }); ok {
		modifyQuery.Modify(func(s *sql.Selector) {
			s.Where(sql.In(s.C(deptField), intIds...))
		})
		return nil
	}
	
	// Method 2: Try Where interface
	type whereQuery interface {
		Where(...func(*sql.Selector))
	}
	if whereQ, ok := query.(whereQuery); ok {
		whereQ.Where(func(selector *sql.Selector) {
			selector.Where(sql.In(deptField, intIds...))
		})
		return nil
	}
	
	// Method 3: Try WhereP if available
	type wherePQuery interface {
		WhereP(func(*sql.Selector))
	}
	if wherePQ, ok := query.(wherePQuery); ok {
		wherePQ.WhereP(func(selector *sql.Selector) {
			sql.FieldIn(deptField, intIds...)(selector)
		})
		return nil
	}
	
	// If no method works, continue without modification (log warning)
	return fmt.Errorf("query type %T does not support where conditions", query)
}

// applyUserDataFilter 应用用户数据过滤条件
func applyUserDataFilter(ctx context.Context, query ent.Query, config *DataPermissionConfig) error {
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

// GetDataPermissionInterceptor 获取标准数据权限拦截器
// 使用默认配置的便捷方法
func GetDataPermissionInterceptor() ent.Interceptor {
	return NewDataPermissionInterceptor(DefaultDataPermissionConfig())
}

// GetCustomDataPermissionInterceptor 获取自定义数据权限拦截器
// 允许指定自定义字段名称
func GetCustomDataPermissionInterceptor(deptField, userField string) ent.Interceptor {
	config := &DataPermissionConfig{
		Enabled:           true,
		DepartmentField:   deptField,
		UserField:         userField,
		SkipSystemContext: true,
	}
	return NewDataPermissionInterceptor(config)
}