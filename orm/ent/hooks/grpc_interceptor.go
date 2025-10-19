// Copyright 2024 The NewBee Authors. All Rights Reserved.

package hooks

import (
	"context"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// SystemContextClientInterceptor 是一个 gRPC 客户端拦截器，
// 负责将 SystemContext 标识和租户上下文传递到服务端
func SystemContextClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// 获取或创建 metadata
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		// 检查是否为 SystemContext
		isSysCtx := isSystemContext(ctx)
		if isSysCtx {
			// 将 SystemContext 标识添加到 gRPC metadata
			md.Set(string(keys.SystemContextKey), "true")
		}

		// 🔥 关键修复：传递租户ID到gRPC metadata
		// 从context中获取租户ID并添加到metadata
		cm := keys.NewContextManager()
		tenantID := cm.GetTenantID(ctx)
		originalTenant := cm.GetOriginalTenantID(ctx)
		userID := cm.GetUserID(ctx)

		// 🔍 调试日志：查看context中的所有值（仅非SystemContext时）
		if !isSysCtx {
			deptID := cm.GetDeptID(ctx)
			dataScope := cm.GetDataScope(ctx)
			roleCodes := cm.GetRoleCodes(ctx)

			logx.Infow("SystemContextClientInterceptor - Context Values",
				logx.Field("method", method),
				logx.Field("tenant_id", tenantID),
				logx.Field("user_id", userID),
				logx.Field("dept_id", deptID),
				logx.Field("role_codes", roleCodes),
				logx.Field("data_scope", dataScope),
				logx.Field("is_system_ctx", false))
		}

		if tenantID != "" && tenantID != "0" {
			md.Set(keys.TenantIDKey.String(), tenantID)
			if originalTenant != "" {
				md.Set(keys.OriginalTenantIDKey.String(), originalTenant)
			}
			if !isSysCtx {
				logx.Infow("✅ Added tenant_id to gRPC metadata",
					logx.Field("key", keys.TenantIDKey.String()),
					logx.Field("value", tenantID))
			}
		} else if !isSysCtx {
			// 只有非SystemContext时才警告缺少tenant_id
			logx.Infow("⚠️ No tenant_id to add to metadata",
				logx.Field("tenant_id", tenantID))
		}

		// 传递其他上下文信息
		if userID != "" {
			md.Set(keys.UserIDKey.String(), userID)
		}

		// 传递部门ID
		deptID := cm.GetDeptID(ctx)
		if deptID != "" {
			md.Set(keys.DeptIDKey.String(), deptID)
		}

		// 传递数据权限范围
		dataScope := cm.GetDataScope(ctx)
		if dataScope != "" {
			md.Set(keys.DataScopeKey.String(), dataScope)
			md.Set(string(datapermctx.ScopeKey), dataScope)
		}

		// 🔥 关键修复：传递角色代码
		roleCodes := cm.GetRoleCodes(ctx)
		if roleCodes != "" {
			md.Set(keys.RoleCodesKey.String(), roleCodes)
			if !isSysCtx {
				logx.Infow("✅ Added role_codes to gRPC metadata",
					logx.Field("key", keys.RoleCodesKey.String()),
					logx.Field("value", roleCodes))
			}
		} else if !isSysCtx {
			// 只有非SystemContext时才报错缺少roleCodes
			logx.Errorw("⚠️ RoleCodes is empty in context",
				logx.Field("tenant_id", tenantID),
				logx.Field("user_id", userID))
		}

		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// SystemContextStreamClientInterceptor 是一个 gRPC 流式客户端拦截器，
// 负责将 SystemContext 标识和租户上下文传递到服务端
func SystemContextStreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		// 获取或创建 metadata
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		// 检查是否为 SystemContext
		if isSystemContext(ctx) {
			// 将 SystemContext 标识添加到 gRPC metadata
			md.Set(string(keys.SystemContextKey), "true")
		}

		// 🔥 关键修复：传递租户ID到gRPC metadata
		// 从context中获取租户ID并添加到metadata
		cm := keys.NewContextManager()
		if tenantID := cm.GetTenantID(ctx); tenantID != "" && tenantID != "0" {
			md.Set(keys.TenantIDKey.String(), tenantID)
			if originalTenant := cm.GetOriginalTenantID(ctx); originalTenant != "" {
				md.Set(keys.OriginalTenantIDKey.String(), originalTenant)
			}
		}

		// 传递其他上下文信息
		if userID := cm.GetUserID(ctx); userID != "" {
			md.Set(keys.UserIDKey.String(), userID)
		}

		// 传递部门ID
		if deptID := cm.GetDeptID(ctx); deptID != "" {
			md.Set(keys.DeptIDKey.String(), deptID)
		}

		// 传递数据权限范围
		if dataScope := cm.GetDataScope(ctx); dataScope != "" {
			md.Set(keys.DataScopeKey.String(), dataScope)
			md.Set(string(datapermctx.ScopeKey), dataScope)
		}

		// 传递角色代码
		if roleCodes := cm.GetRoleCodes(ctx); roleCodes != "" {
			md.Set(keys.RoleCodesKey.String(), roleCodes)
		}

		ctx = metadata.NewOutgoingContext(ctx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
