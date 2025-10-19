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

package deptctx

import (
	"context"
	"strconv"

	"github.com/zeromicro/go-zero/core/logx"
)

// EnhancedDeptContextInjector 增强的部门上下文注入器
// 模仿租户ID的处理方式，统一处理部门ID相关的上下文注入
type EnhancedDeptContextInjector struct {
	// 可以添加配置选项，比如缓存、日志等
}

// NewEnhancedDeptContextInjector 创建增强的部门上下文注入器
func NewEnhancedDeptContextInjector() *EnhancedDeptContextInjector {
	return &EnhancedDeptContextInjector{}
}

// InjectDepartmentContext 注入部门相关的上下文信息
// 这个函数应该在dataPerm中间件中调用，确保所有微服务都能获得完整的部门上下文
func (injector *EnhancedDeptContextInjector) InjectDepartmentContext(ctx context.Context, deptID uint64, customDepts string, subDepts string) context.Context {
	// 注入基础部门ID
	ctx = context.WithValue(ctx, "deptId", deptID)
	ctx = context.WithValue(ctx, "department_id", deptID)
	
	// 注入自定义部门数据 - 解决 "failed to get custom departmrnt ids from context" 错误
	if customDepts != "" {
		ctx = context.WithValue(ctx, "customDept", customDepts)
		ctx = context.WithValue(ctx, "custom_dept", customDepts)
		logx.Debugw("Enhanced dept context: injected custom departments", 
			logx.Field("deptID", deptID),
			logx.Field("customDepts", customDepts))
	}
	
	// 注入子部门数据 - 解决 "failed to get sub departmrnt ids from context" 错误  
	if subDepts != "" {
		ctx = context.WithValue(ctx, "subDept", subDepts)
		ctx = context.WithValue(ctx, "sub_dept", subDepts)
		logx.Debugw("Enhanced dept context: injected sub departments", 
			logx.Field("deptID", deptID),
			logx.Field("subDepts", subDepts))
	}
	
	// 兼容性：同时设置字符串格式
	deptIDStr := strconv.FormatUint(deptID, 10)
	ctx = context.WithValue(ctx, "deptIdStr", deptIDStr)
	
	logx.Infow("Enhanced department context injected successfully", 
		logx.Field("deptID", deptID),
		logx.Field("hasCustomDepts", customDepts != ""),
		logx.Field("hasSubDepts", subDepts != ""))
	
	return ctx
}

// GetEnhancedDeptDataFromContext 从增强的上下文中获取部门数据
func GetEnhancedDeptDataFromContext(ctx context.Context) (deptID uint64, customDepts string, subDepts string) {
	// 获取基础部门ID
	if deptID, err := GetDepartmentIDFromCtx(ctx); err == nil {
		deptIDResult := deptID
		
		// 获取自定义部门数据
		if customValue, ok := ctx.Value("customDept").(string); ok {
			customDepts = customValue
		} else if customValue, ok := ctx.Value("custom_dept").(string); ok {
			customDepts = customValue
		}
		
		// 获取子部门数据
		if subValue, ok := ctx.Value("subDept").(string); ok {
			subDepts = subValue
		} else if subValue, ok := ctx.Value("sub_dept").(string); ok {
			subDepts = subValue
		}
		
		return deptIDResult, customDepts, subDepts
	}
	
	return 0, "", ""
}

// ValidateEnhancedDeptContext 验证增强的部门上下文是否完整
func ValidateEnhancedDeptContext(ctx context.Context) (isValid bool, missingFields []string) {
	var missing []string
	
	// 检查基础部门ID
	if _, err := GetDepartmentIDFromCtx(ctx); err != nil {
		missing = append(missing, "deptId")
	}
	
	// 注意：自定义部门和子部门不是必须的，取决于用户的权限级别
	// 但如果存在，应该是有效的
	
	return len(missing) == 0, missing
}