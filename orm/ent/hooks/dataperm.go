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

package hooks

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/deptctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/userctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
	"github.com/zeromicro/go-zero/core/errorx"
	"github.com/zeromicro/go-zero/core/logx"
)

// DataPermTableConfig 数据权限表配置
type DataPermTableConfig struct {
	// TableName 表名
	TableName string
	// DepartmentField 部门字段名，默认为 "department_id"
	DepartmentField string
	// UserField 用户字段名，用于个人数据权限，默认为 "user_id"
	UserField string
	// EnableTenantMode 是否启用租户模式
	EnableTenantMode bool
	// TenantField 租户字段名，默认为 "tenant_id"
	TenantField string
}

// DefaultDataPermTableConfig 返回默认的数据权限表配置
func DefaultDataPermTableConfig(tableName string) *DataPermTableConfig {
	return &DataPermTableConfig{
		TableName:        tableName,
		DepartmentField:  "department_id",
		UserField:        "user_id",
		EnableTenantMode: false,
		TenantField:      "tenant_id",
	}
}

// WithTenantMode 启用租户模式
func (c *DataPermTableConfig) WithTenantMode(tenantField string) *DataPermTableConfig {
	c.EnableTenantMode = true
	if tenantField != "" {
		c.TenantField = tenantField
	}
	return c
}

// WithDepartmentField 设置部门字段名
func (c *DataPermTableConfig) WithDepartmentField(field string) *DataPermTableConfig {
	c.DepartmentField = field
	return c
}

// WithUserField 设置用户字段名
func (c *DataPermTableConfig) WithUserField(field string) *DataPermTableConfig {
	c.UserField = field
	return c
}

// EntClient 定义通用的Ent Client接口
type EntClient interface {
	Intercept(...ent.Interceptor)
}

// QueryWithWhere 定义具有Where方法的查询接口
type QueryWithWhere interface {
	Where(func(*sql.Selector))
}

// CreateDataPermissionInterceptor 创建基于接口的高性能数据权限拦截器
func CreateDataPermissionInterceptor(
	departmentField string,
	userField string,
) func(next ent.Querier) ent.Querier {
	config := &DataPermTableConfig{
		DepartmentField: departmentField,
		UserField:       userField,
	}

	return func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// 跳过系统上下文
			if IsSystemContext(ctx) {
				logx.Infow("SystemContext bypassing data permission interceptor",
					logx.Field("action", "bypass_data_permission"))
				return next.Query(ctx, query)
			}

			// 应用数据权限过滤（如果查询支持Where方法）
			if err := applyDataPermissionIfSupported(ctx, query, config); err != nil {
				return nil, err
			}

			return next.Query(ctx, query)
		})
	}
}

// NewDataPermissionInterceptor 保持向后兼容的创建函数
func NewDataPermissionInterceptor(configs ...*DataPermTableConfig) ent.Interceptor {
	// 使用第一个配置或默认配置
	var config *DataPermTableConfig
	if len(configs) > 0 && configs[0] != nil {
		config = configs[0]
	} else {
		config = DefaultDataPermTableConfig("")
	}

	interceptorFunc := CreateDataPermissionInterceptor(config.DepartmentField, config.UserField)
	return ent.InterceptFunc(interceptorFunc)
}

// applyDataPermissionIfSupported 如果查询支持Where方法，则应用数据权限
func applyDataPermissionIfSupported(ctx context.Context, query ent.Query, config *DataPermTableConfig) error {
	// 使用接口断言检查查询是否支持Where方法
	type whereQuery interface {
		Where(...func(*sql.Selector))
	}

	whereQ, ok := query.(whereQuery)
	if !ok {
		// 查询不支持Where方法，跳过数据权限过滤
		return nil
	}

	// 应用数据权限过滤
	// 注意：租户隔离由独立的TenantQueryInterceptor处理，此处只处理数据权限
	return applyDataPermissionFilter(ctx, whereQ, config)
}

// applyDataPermissionFilter 应用数据权限过滤
func applyDataPermissionFilter(ctx context.Context, query interface{ Where(...func(*sql.Selector)) }, config *DataPermTableConfig) error {
	// 获取数据权限范围
	dataScope, err := datapermctx.GetScopeFromCtx(ctx)
	if err != nil {
		return err
	}

	switch dataScope {
	case entenum.DataPermAll:
		// 全部数据权限，无需过滤
		return nil

	case entenum.DataPermCustomDept:
		customDeptIds, err := datapermctx.GetCustomDeptFromCtx(ctx)
		if err != nil {
			return err
		}
		
		if len(customDeptIds) == 0 {
			query.Where(func(selector *sql.Selector) {
				selector.Where(sql.False())
			})
			return nil
		}

		values := make([]interface{}, len(customDeptIds))
		for i, id := range customDeptIds {
			values[i] = id
		}
		
		query.Where(func(selector *sql.Selector) {
			sql.FieldIn(config.DepartmentField, values...)(selector)
		})

	case entenum.DataPermOwnDeptAndSub:
		subDeptIds, err := datapermctx.GetSubDeptFromCtx(ctx)
		if err != nil {
			return err
		}
		
		if len(subDeptIds) == 0 {
			query.Where(func(selector *sql.Selector) {
				selector.Where(sql.False())
			})
			return nil
		}

		values := make([]interface{}, len(subDeptIds))
		for i, id := range subDeptIds {
			values[i] = id
		}
		
		query.Where(func(selector *sql.Selector) {
			sql.FieldIn(config.DepartmentField, values...)(selector)
		})

	case entenum.DataPermOwnDept:
		deptId, err := deptctx.GetDepartmentIDFromCtx(ctx)
		if err != nil {
			return err
		}
		
		query.Where(func(selector *sql.Selector) {
			selector.Where(sql.EQ(config.DepartmentField, deptId))
		})

	case entenum.DataPermSelf:
		userId, err := userctx.GetUserIDFromCtx(ctx)
		if err != nil {
			return err
		}
		
		query.Where(func(selector *sql.Selector) {
			selector.Where(sql.EQ(config.UserField, userId))
		})

	default:
		return errorx.NewInvalidArgumentError("unsupported data permission scope")
	}

	return nil
}

// RegisterDataPermissionInterceptorV3 推荐的高性能注册方式
func RegisterDataPermissionInterceptorV3(client EntClient) {
	// 使用通用的数据权限拦截器，支持所有实体
	interceptor := CreateDataPermissionInterceptor("department_id", "user_id")
	client.Intercept(ent.InterceptFunc(interceptor))
}

// RegisterDataPermissionInterceptors 保持向后兼容的注册函数
func RegisterDataPermissionInterceptors(client EntClient, tables ...string) {
	// 使用新的高性能方案，忽略tables参数（现在自动支持所有实体）
	RegisterDataPermissionInterceptorV3(client)
}

// RegisterDataPermissionInterceptorsWithTenant 保持向后兼容的带租户注册函数
// 注意：租户隔离应该由独立的TenantQueryInterceptor处理
// 这个函数保持向后兼容，但实际只注册数据权限拦截器
func RegisterDataPermissionInterceptorsWithTenant(client EntClient, tables ...string) {
	// 使用标准的数据权限拦截器
	// 租户隔离由TenantQueryInterceptor独立处理
	RegisterDataPermissionInterceptorV3(client)
}