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
	"strconv"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
	"google.golang.org/grpc/metadata"
)

// SetTenantIDToContext 将租户ID设置到context中
// 这个函数用于在需要时手动设置租户上下文，通常用于系统级操作
// 现在使用统一的keys包确保字段一致
func SetTenantIDToContext(ctx context.Context, tenantID uint64) context.Context {
	tenantIDStr := strconv.FormatUint(tenantID, 10)

	cm := keys.NewContextManager()
	ctx = cm.SetTenantID(ctx, tenantIDStr)

	// 显式清除任何遗留的系统上下文标记，避免被当成 system context 处理
	ctx = context.WithValue(ctx, keys.SystemContextKey, false)

	md := metadata.New(map[string]string{
		keys.TenantIDKey.String(): tenantIDStr,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)
	return ctx
}

// GetCurrentTenantID 从 context 中获取当前租户 ID
func GetCurrentTenantID(ctx context.Context) uint64 {
	return tenantctx.GetTenantIDFromCtx(ctx)
}

// IsValidTenantContext 判断上下文中是否包含有效的租户信息
func IsValidTenantContext(ctx context.Context) bool {
	if isSystemContext(ctx) {
		return true
	}
	tenantID := GetCurrentTenantID(ctx)
	return tenantID > 0
}

// IsSystemContext 对外暴露的系统上下文判断
func IsSystemContext(ctx context.Context) bool {
	return isSystemContext(ctx)
}
