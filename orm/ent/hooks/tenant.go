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
	"errors"
	"runtime"

	"entgo.io/ent"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
	"github.com/zeromicro/go-zero/core/logx"
)

// systemContextKey is the key for the system context.
type systemContextKey struct{}

// NewSystemContext returns a context that is flagged as a system context.
// 注意：此函数应仅用于系统初始化和管理操作，使用时会记录审计日志
func NewSystemContext(ctx context.Context) context.Context {
	// 记录调用栈信息用于审计
	_, file, line, ok := runtime.Caller(1)
	if ok {
		logx.Infow("SystemContext created",
			logx.Field("caller_file", file),
			logx.Field("caller_line", line),
			logx.Field("action", "create_system_context"))
	} else {
		logx.Errorw("SystemContext created but caller info not available",
			logx.Field("action", "create_system_context"))
	}

	return context.WithValue(ctx, systemContextKey{}, true)
}

// isSystemContext checks if the context is a system context.
func isSystemContext(ctx context.Context) bool {
	val, ok := ctx.Value(systemContextKey{}).(bool)
	return ok && val
}

// fromContext returns the tenant ID from the context.
func fromContext(ctx context.Context) (uint64, error) {
	// 使用通用的租户上下文助手来获取租户ID
	// 这能够处理多种来源：HTTP context、gRPC metadata等
	tenantID := tenantctx.GetTenantIDFromCtx(ctx)
	if tenantID > 0 {
		return tenantID, nil
	}

	// 如果没有找到有效的租户ID，返回错误
	return 0, errors.New("tenant id not found or invalid in context")
}

// TenantMutator is an interface that all tenant-scoped mutations implement.
type TenantMutator interface {
	SetTenantID(uint64)
}

// TenantMutationHook returns a hook that sets the tenant_id on all creations.
func TenantMutationHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// Skip all checks for system context or for Tenant entity itself.
			if isSystemContext(ctx) {
				logx.Infow("SystemContext bypassing tenant mutation hook",
					logx.Field("entity_type", m.Type()),
					logx.Field("operation", m.Op().String()),
					logx.Field("action", "bypass_tenant_mutation"))
				return next.Mutate(ctx, m)
			}

			if m.Type() == "Tenant" {
				return next.Mutate(ctx, m)
			}

			tenantID, err := fromContext(ctx)
			if err != nil {
				return nil, err
			}

			if m.Op().Is(ent.OpCreate) {
				if tm, ok := m.(TenantMutator); ok {
					tm.SetTenantID(tenantID)
				}
			}

			return next.Mutate(ctx, m)
		})
	}
}

// TenantQuerier is an interface for query builders that have a tenant_id field.
type TenantQuerier interface {
	WhereHasTenantWith(uint64)
}

// TenantQueryInterceptor returns a query interceptor that filters all queries by the tenant_id in the context.
func TenantQueryInterceptor() ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			// Skip all checks for system context
			if isSystemContext(ctx) {
				logx.Infow("SystemContext bypassing tenant query interceptor",
					logx.Field("action", "bypass_tenant_query"))
				return next.Query(ctx, q)
			}

			// 检查查询是否支持租户过滤
			if tq, ok := q.(TenantQuerier); ok {
				tenantID, err := fromContext(ctx)
				if err != nil {
					return nil, err
				}
				tq.WhereHasTenantWith(tenantID)
			}

			return next.Query(ctx, q)
		})
	})
}
