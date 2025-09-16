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
// 现在使用统一的keys包来确保一致性
func SetTenantIDToContext(ctx context.Context, tenantID uint64) context.Context {
	tenantIDStr := strconv.FormatUint(tenantID, 10)
	
	// 使用统一的ContextManager进行设置
	cm := keys.NewContextManager()
	ctx = cm.SetTenantID(ctx, tenantIDStr)

	// 设置到gRPC metadata中，使用统一的key
	md := metadata.New(map[string]string{
		keys.TenantIDKey.String(): tenantIDStr,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	return ctx
}

// GetCurrentTenantID 从context中获取当前租户ID
func GetCurrentTenantID(ctx context.Context) uint64 {
	return tenantctx.GetTenantIDFromCtx(ctx)
}

// IsValidTenantContext 检查context中是否有有效的租户ID
func IsValidTenantContext(ctx context.Context) bool {
	if isSystemContext(ctx) {
		return true // 系统上下文总是有效的
	}
	tenantID := GetCurrentTenantID(ctx)
	return tenantID > 0
}

// IsSystemContext 检查是否为系统上下文（对外暴露的版本）
func IsSystemContext(ctx context.Context) bool {
	return isSystemContext(ctx)
}
