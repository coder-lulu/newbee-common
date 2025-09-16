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

package entenum

import (
	"context"
	"github.com/coder-lulu/newbee-common/state"
)

// 向后兼容的常量定义，现在通过状态管理器获取
var (
	// TenantDefaultId is the default id of tenant
	// 现在通过状态管理器动态获取，但保持变量名兼容
	TenantDefaultId uint64 = 1 // 默认值，将被状态管理器覆盖
)

// 数据权限常量 - 保持向后兼容性
const (
	// DataPermAll is the data permission of all data
	DataPermAll    = 1
	DataPermAllStr = "1"

	// DataPermCustomDept is the data permission of custom department data
	DataPermCustomDept    = 2
	DataPermCustomDeptStr = "2"

	// DataPermOwnDeptAndSub is the data permission of users's own department and sub departments data
	DataPermOwnDeptAndSub    = 3
	DataPermOwnDeptAndSubStr = "3"

	// DataPermOwnDept is the data permission of users's own department data
	DataPermOwnDept    = 4
	DataPermOwnDeptStr = "4"

	// DataPermOwn is the data permission of your own data
	DataPermOwn    = 5
	DataPermOwnStr = "5"
	
	// Backward compatibility aliases
	DataPermSelf    = DataPermOwn
	DataPermSelfStr = DataPermOwnStr
)

// GetTenantDefaultId 动态获取默认租户ID
// 优先从状态管理器获取，降级为静态常量
func GetTenantDefaultId(ctx context.Context) uint64 {
	// 尝试从状态管理器获取
	if adapter := state.GetDefaultStateAdapter(); adapter != nil {
		return adapter.GetDefaultTenantID(ctx)
	}
	
	// 降级为静态常量
	return TenantDefaultId
}

// GetDataPermScope 动态获取数据权限范围
func GetDataPermScope(ctx context.Context, userID string) uint8 {
	// 尝试从状态管理器获取
	if adapter := state.GetDefaultStateAdapter(); adapter != nil {
		return adapter.GetDataPermissionScope(ctx, userID)
	}
	
	// 降级为最严格权限
	return DataPermOwn
}

// 新增的便捷函数，保持API一致性
func GetDataPermScopeString(scope uint8) string {
	switch scope {
	case DataPermAll:
		return DataPermAllStr
	case DataPermCustomDept:
		return DataPermCustomDeptStr
	case DataPermOwnDeptAndSub:
		return DataPermOwnDeptAndSubStr
	case DataPermOwnDept:
		return DataPermOwnDeptStr
	case DataPermOwn:
		return DataPermOwnStr
	default:
		return DataPermOwnStr
	}
}

// 初始化函数，在包加载时调用
func init() {
	// 可以在这里设置默认值，但实际值将通过状态管理器动态获取
}
