// Copyright 2024 The NewBee Authors. All Rights Reserved.

package hooks

import (
	"context"
	"strconv"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ContextPropagationServerInterceptor 是一个 gRPC 服务端拦截器，
// 负责从 gRPC incoming metadata 中提取租户ID、用户ID等信息并注入到context中
//
// 这个拦截器解决了以下问题：
// 1. API服务通过客户端拦截器将context信息传递到gRPC metadata
// 2. RPC服务端需要从metadata中提取这些信息并恢复到context
// 3. RPC层的logic才能通过context获取租户ID等信息
// 4. 统一Hook系统才能正确地自动注入tenant_id等字段
func ContextPropagationServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 从 gRPC incoming metadata 中提取信息
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			// ⚠️ 没有metadata，记录警告并使用原始context继续
			// 这可能导致后续Hook无法获取租户信息
			logx.Infow("⚠️ No incoming metadata found in gRPC request",
				logx.Field("method", info.FullMethod),
				logx.Field("action", "proceeding_with_original_context"),
				logx.Field("risk", "tenant_context_may_be_missing"))
			return handler(ctx, req)
		}

		// 创建新的context，注入从metadata提取的信息
		newCtx := ctx
		cm := keys.NewContextManager()

		// ✅ 提取并注入租户ID
		// 🔒 安全修复：添加输入验证，确保tenant_id是有效的正整数
		if tenantIDs := md.Get(keys.TenantIDKey.String()); len(tenantIDs) > 0 {
			tenantIDStr := tenantIDs[0]
			if tenantIDStr != "" && tenantIDStr != "0" {
				// 验证是否为有效的正整数
				if tenantIDNum, err := strconv.ParseUint(tenantIDStr, 10, 64); err == nil && tenantIDNum > 0 {
					newCtx = cm.SetTenantID(newCtx, tenantIDStr)
					logx.Infow("✅ Extracted valid tenant_id from gRPC metadata",
						logx.Field("method", info.FullMethod),
						logx.Field("tenant_id", tenantIDStr))
				} else {
					logx.Errorw("❌ Invalid tenant_id in gRPC metadata",
						logx.Field("method", info.FullMethod),
						logx.Field("tenant_id_str", tenantIDStr),
						logx.Field("parse_error", err))
				}
			}
		}

		// ✅ 记录原始租户ID（如存在）
		if originalTenantIDs := md.Get(keys.OriginalTenantIDKey.String()); len(originalTenantIDs) > 0 {
			originalTenantID := originalTenantIDs[0]
			if originalTenantID != "" {
				newCtx = cm.SetOriginalTenantID(newCtx, originalTenantID)
				logx.Debugw("Extracted original_tenant_id from gRPC metadata",
					logx.Field("method", info.FullMethod),
					logx.Field("original_tenant_id", originalTenantID))
			}
		}

		// ✅ 提取并注入用户ID
		if userIDs := md.Get(keys.UserIDKey.String()); len(userIDs) > 0 {
			userID := userIDs[0]
			if userID != "" {
				newCtx = cm.SetUserID(newCtx, userID)
				logx.Debugw("Extracted user_id from gRPC metadata",
					logx.Field("method", info.FullMethod),
					logx.Field("user_id", userID))
			}
		}

		// ✅ 提取并注入部门ID
		if deptIDs := md.Get(keys.DeptIDKey.String()); len(deptIDs) > 0 {
			deptID := deptIDs[0]
			if deptID != "" {
				newCtx = cm.SetDeptID(newCtx, deptID)
				logx.Debugw("Extracted dept_id from gRPC metadata",
					logx.Field("method", info.FullMethod),
					logx.Field("dept_id", deptID))
			}
		}

		// ✅ 提取并注入数据权限范围
		dataScopes := md.Get(keys.DataScopeKey.String())
		if len(dataScopes) == 0 {
			dataScopes = md.Get(string(datapermctx.ScopeKey))
		}
		if len(dataScopes) > 0 {
			dataScope := dataScopes[0]
			if dataScope != "" {
				newCtx = cm.SetDataScope(newCtx, dataScope)
				newCtx = context.WithValue(newCtx, datapermctx.ScopeKey, dataScope)
				logx.Debugw("Extracted data_scope from gRPC metadata",
					logx.Field("method", info.FullMethod),
					logx.Field("data_scope", dataScope))
			}
		}

		// ✅ 提取并注入角色代码
		if roleCodes := md.Get(keys.RoleCodesKey.String()); len(roleCodes) > 0 {
			roleCode := roleCodes[0]
			if roleCode != "" {
				newCtx = cm.SetRoleCodes(newCtx, roleCode)
				logx.Debugw("Extracted role_codes from gRPC metadata",
					logx.Field("method", info.FullMethod),
					logx.Field("role_codes", roleCode))
			}
		}

		// ✅ 提取SystemContext标识
		if systemCtxFlags := md.Get(string(keys.SystemContextKey)); len(systemCtxFlags) > 0 {
			if systemCtxFlags[0] == "true" {
				newCtx = context.WithValue(newCtx, keys.SystemContextKey, true)
				logx.Infow("✅ SystemContext flag detected in metadata",
					logx.Field("method", info.FullMethod))
			}
		}

		// 🔍 调试日志：打印提取后的context状态
		logx.Infow("🔍 ContextPropagationServerInterceptor - Context after extraction",
			logx.Field("method", info.FullMethod),
			logx.Field("tenant_id", cm.GetTenantID(newCtx)),
			logx.Field("user_id", cm.GetUserID(newCtx)),
			logx.Field("dept_id", cm.GetDeptID(newCtx)),
			logx.Field("data_scope", cm.GetDataScope(newCtx)),
			logx.Field("role_codes", cm.GetRoleCodes(newCtx)),
			logx.Field("is_system_ctx", isSystemContext(newCtx)))

		// 使用注入了上下文信息的context调用handler
		return handler(newCtx, req)
	}
}

// ContextPropagationStreamServerInterceptor 是一个 gRPC 流式服务端拦截器，
// 负责从 gRPC incoming metadata 中提取租户ID、用户ID等信息并注入到context中
func ContextPropagationStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// 从流的context中提取metadata
		ctx := ss.Context()
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			// 没有metadata，使用原始context继续
			return handler(srv, ss)
		}

		// 创建新的context，注入从metadata提取的信息
		newCtx := ctx
		cm := keys.NewContextManager()

		// 提取并注入租户ID
		// 🔒 安全修复：添加输入验证，确保tenant_id是有效的正整数
		if tenantIDs := md.Get(keys.TenantIDKey.String()); len(tenantIDs) > 0 {
			tenantIDStr := tenantIDs[0]
			if tenantIDStr != "" && tenantIDStr != "0" {
				// 验证是否为有效的正整数
				if tenantIDNum, err := strconv.ParseUint(tenantIDStr, 10, 64); err == nil && tenantIDNum > 0 {
					newCtx = cm.SetTenantID(newCtx, tenantIDStr)
					logx.Debugw("Stream: Extracted valid tenant_id from gRPC metadata",
						logx.Field("method", info.FullMethod),
						logx.Field("tenant_id", tenantIDStr))
				} else {
					logx.Errorw("Stream: Invalid tenant_id in gRPC metadata",
						logx.Field("method", info.FullMethod),
						logx.Field("tenant_id_str", tenantIDStr),
						logx.Field("parse_error", err))
				}
			}
		}

		// 提取原始租户ID
		if originalTenantIDs := md.Get(keys.OriginalTenantIDKey.String()); len(originalTenantIDs) > 0 {
			originalTenantID := originalTenantIDs[0]
			if originalTenantID != "" {
				newCtx = cm.SetOriginalTenantID(newCtx, originalTenantID)
			}
		}

		// 提取并注入用户ID
		if userIDs := md.Get(keys.UserIDKey.String()); len(userIDs) > 0 {
			userID := userIDs[0]
			if userID != "" {
				newCtx = cm.SetUserID(newCtx, userID)
			}
		}

		// 提取并注入部门ID
		if deptIDs := md.Get(keys.DeptIDKey.String()); len(deptIDs) > 0 {
			deptID := deptIDs[0]
			if deptID != "" {
				newCtx = cm.SetDeptID(newCtx, deptID)
			}
		}

		// 提取并注入数据权限范围
		dataScopes := md.Get(keys.DataScopeKey.String())
		if len(dataScopes) == 0 {
			dataScopes = md.Get(string(datapermctx.ScopeKey))
		}
		if len(dataScopes) > 0 {
			dataScope := dataScopes[0]
			if dataScope != "" {
				newCtx = cm.SetDataScope(newCtx, dataScope)
				newCtx = context.WithValue(newCtx, datapermctx.ScopeKey, dataScope)
			}
		}

		// 提取并注入角色代码
		if roleCodes := md.Get(keys.RoleCodesKey.String()); len(roleCodes) > 0 {
			roleCode := roleCodes[0]
			if roleCode != "" {
				newCtx = cm.SetRoleCodes(newCtx, roleCode)
			}
		}

		// 提取SystemContext标识
		if systemCtxFlags := md.Get(string(keys.SystemContextKey)); len(systemCtxFlags) > 0 {
			if systemCtxFlags[0] == "true" {
				newCtx = context.WithValue(newCtx, keys.SystemContextKey, true)
			}
		}

		// 创建包装的ServerStream，使用新的context
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          newCtx,
		}

		return handler(srv, wrappedStream)
	}
}

// wrappedServerStream 包装原始的ServerStream，使用自定义的context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context 返回自定义的context
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
