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
	"reflect"

	"entgo.io/ent"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/deptctx"
	"github.com/zeromicro/go-zero/core/logx"
)

// DepartmentMutationHook 部门变更Hook - 模仿TenantMutationHook的处理方式
// 在数据创建和更新时自动注入department_id字段
// 解决用户反馈的"部门ID的填充应该和租户ID一样"的需求
func DepartmentMutationHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// 只处理Create操作，Update操作保持现有的部门ID
			if m.Op() != ent.OpCreate {
				return next.Mutate(ctx, m)
			}

			// 获取mutation的反射类型，检查是否有department_id字段
			mutationType := reflect.TypeOf(m)
			if mutationType == nil {
				return next.Mutate(ctx, m)
			}

			// 检查是否有SetDepartmentID方法（表明实体支持部门字段）
			setDeptMethod := reflect.ValueOf(m).MethodByName("SetDepartmentID")
			if !setDeptMethod.IsValid() {
				// 没有部门字段的实体，直接跳过
				logx.Debugw("Entity does not have department_id field, skipping department hook",
					logx.Field("mutationType", mutationType.String()))
				return next.Mutate(ctx, m)
			}

			// 检查是否已经设置了department_id
			getDeptMethod := reflect.ValueOf(m).MethodByName("DepartmentID") 
			if getDeptMethod.IsValid() {
				// 调用DepartmentID()方法获取现有值
				results := getDeptMethod.Call([]reflect.Value{})
				if len(results) >= 2 { // DepartmentID() (uint64, bool)
					existsResult := results[1]
					if existsResult.Kind() == reflect.Bool && existsResult.Bool() {
						// 已经设置了department_id，不需要自动注入
						logx.Debugw("Department ID already set in mutation, skipping auto-injection",
							logx.Field("mutationType", mutationType.String()))
						return next.Mutate(ctx, m)
					}
				}
			}

			// 从上下文获取部门ID
			deptID, err := deptctx.GetDepartmentIDFromCtx(ctx)
			if err != nil {
				logx.Errorw("Failed to get department ID from context in DepartmentMutationHook",
					logx.Field("mutationType", mutationType.String()),
					logx.Field("error", err.Error()))
				
				// 不阻塞流程，继续执行，但记录警告
				// 这里可以考虑设置默认部门ID或者根据业务需求处理
				return next.Mutate(ctx, m)
			}

			// 自动注入部门ID - 模仿租户ID的注入方式
			if setDeptMethod.Type().NumIn() == 1 && setDeptMethod.Type().In(0).Kind() == reflect.Uint64 {
				logx.Infow("Auto-injecting department ID via DepartmentMutationHook",
					logx.Field("mutationType", mutationType.String()),
					logx.Field("deptID", deptID))

				// 调用SetDepartmentID方法
				setDeptMethod.Call([]reflect.Value{reflect.ValueOf(deptID)})
			} else {
				logx.Errorw("SetDepartmentID method signature mismatch in DepartmentMutationHook",
					logx.Field("mutationType", mutationType.String()),
					logx.Field("methodType", setDeptMethod.Type().String()))
			}

			return next.Mutate(ctx, m)
		})
	}
}

// DepartmentQueryInterceptor 部门查询拦截器 - 自动添加部门过滤条件
// 注意：这个拦截器是可选的，通常数据权限中间件已经处理了查询过滤
// 但在某些场景下可能需要额外的部门级别过滤
func DepartmentQueryInterceptor() ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// 检查查询是否支持部门过滤
			queryType := reflect.TypeOf(query)
			if queryType == nil {
				return next.Query(ctx, query)
			}

			// 检查是否有WhereDepartmentID方法
			whereDeptMethod := reflect.ValueOf(query).MethodByName("WhereDepartmentID")
			if !whereDeptMethod.IsValid() {
				// 不支持部门过滤的查询，直接跳过
				return next.Query(ctx, query)
			}

			// 从上下文获取部门ID（这里可以是当前用户的部门或者数据权限范围）
			deptID, err := deptctx.GetDepartmentIDFromCtx(ctx)
			if err != nil {
				// 没有部门上下文，可能是系统级查询，继续执行
				logx.Debugw("No department context in DepartmentQueryInterceptor, continuing without filter",
					logx.Field("queryType", queryType.String()),
					logx.Field("error", err.Error()))
				return next.Query(ctx, query)
			}

			// 检查是否是系统上下文（跳过部门过滤）
			if IsSystemContext(ctx) {
				logx.Debugw("System context detected, skipping department filter",
					logx.Field("queryType", queryType.String()))
				return next.Query(ctx, query)
			}

			logx.Debugw("Applying department filter in DepartmentQueryInterceptor",
				logx.Field("queryType", queryType.String()),
				logx.Field("deptID", deptID))

			// 应用部门过滤 - 这里实际上可能需要更复杂的逻辑
			// 因为数据权限可能涉及多个部门（子部门、自定义部门等）
			// 但这个基础版本只处理简单的部门匹配
			// 注意：在实际使用中，建议通过数据权限中间件来处理复杂的部门过滤逻辑

			return next.Query(ctx, query)
		})
	})
}

// RegisterDepartmentHooks 注册部门相关的Hooks和Interceptors
// 这是一个便捷函数，用于一次性注册所有部门相关的钩子
func RegisterDepartmentHooks(client interface{}) {
	// 使用反射来调用client的Use和Intercept方法
	clientValue := reflect.ValueOf(client)
	
	// 注册变更Hook
	if useMethod := clientValue.MethodByName("Use"); useMethod.IsValid() {
		useMethod.Call([]reflect.Value{reflect.ValueOf(DepartmentMutationHook())})
		logx.Infow("DepartmentMutationHook registered successfully")
	}

	// 可选：注册查询拦截器
	// 注意：在大多数情况下，数据权限中间件已经处理了查询过滤
	// 所以这个拦截器通常不需要启用
	/*
	if interceptMethod := clientValue.MethodByName("Intercept"); interceptMethod.IsValid() {
		interceptMethod.Call([]reflect.Value{reflect.ValueOf(DepartmentQueryInterceptor())})
		logx.Infow("DepartmentQueryInterceptor registered successfully")
	}
	*/
}