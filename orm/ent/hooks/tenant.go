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
	"fmt"
	"runtime"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/enum"
	"google.golang.org/grpc/metadata"
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
	// 首先检查上下文是否真正包含有效的租户信息
	// 而不是依赖可能返回默认值的GetTenantIDFromCtx
	if !isValidTenantContext(ctx) {
		return 0, errors.New("tenant id not found or invalid in context")
	}

	// 使用通用的租户上下文助手来获取租户ID
	tenantID := tenantctx.GetTenantIDFromCtx(ctx)

	return tenantID, nil
}

// isValidTenantContext checks if context contains valid tenant information
func isValidTenantContext(ctx context.Context) bool {
	// Check for uint64 tenant ID (as set by SetTenantIDToContext)
	if _, ok := ctx.Value("tenantId").(uint64); ok {
		return true
	}

	// Check for enum.TenantIdCtxKey string value
	if _, ok := ctx.Value(enum.TenantIdCtxKey).(string); ok {
		return true
	}

	// Check gRPC metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if data := md.Get(enum.TenantIdCtxKey); len(data) > 0 {
			return true
		}
	}

	return false
}

// TenantMutator is an interface that all tenant-scoped mutations implement.
type TenantMutator interface {
	SetTenantID(uint64)
}

// TenantMutationHook returns a hook that sets the tenant_id on all creations.
func TenantMutationHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// Handle system context
			if isSystemContext(ctx) {
				logx.Infow("SystemContext detected",
					logx.Field("entity_type", m.Type()),
					logx.Field("operation", m.Op().String()),
					logx.Field("action", "system_tenant_mutation"))

				// For system context, only set tenant_id to 0 if not explicitly set
				if m.Op().Is(ent.OpCreate) {
					if tm, ok := m.(TenantMutator); ok {
						// Check if tenant_id is already explicitly set
						if tenantIDValue, exists := m.Field("tenant_id"); exists {
							logx.Infow("SystemContext preserving explicitly set tenant ID",
								logx.Field("tenant_id", tenantIDValue),
								logx.Field("entity_type", m.Type()))
							// Keep the explicitly set tenant_id
						} else {
							// Only set to 0 if not explicitly provided
							tm.SetTenantID(0) // 0 indicates system entity
						}
					}
				}
				return next.Mutate(ctx, m)
			}

			// Handle public access context (similar to system context)
			if tenantctx.GetPublicAccessCtx(ctx) {
				logx.Infow("PublicContext detected",
					logx.Field("entity_type", m.Type()),
					logx.Field("operation", m.Op().String()),
					logx.Field("action", "public_tenant_mutation"))

				// For public context, only set tenant_id to 0 if not explicitly set
				if m.Op().Is(ent.OpCreate) {
					if tm, ok := m.(TenantMutator); ok {
						// Check if tenant_id is already explicitly set
						if tenantIDValue, exists := m.Field("tenant_id"); exists {
							logx.Infow("PublicContext preserving explicitly set tenant ID",
								logx.Field("tenant_id", tenantIDValue),
								logx.Field("entity_type", m.Type()))
							// Keep the explicitly set tenant_id
						} else {
							// Only set to 0 if not explicitly provided
							tm.SetTenantID(0) // 0 indicates system/public entity
						}
					}
				}
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

// TenantQueryInterceptor returns a query interceptor that filters all queries by tenant_id.
func TenantQueryInterceptor() ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			// 系统上下文跳过租户过滤
			if isSystemContext(ctx) {
				return next.Query(ctx, q)
			}

			// 公共访问上下文跳过租户过滤 (用于访问共享数据)
			if tenantctx.GetPublicAccessCtx(ctx) {
				return next.Query(ctx, q)
			}

			// 获取租户ID
			tenantID, err := fromContext(ctx)
			if err != nil {
				return nil, err
			}

			// 使用高效的类型断言方式添加租户过滤
			addTenantFilterEfficient(q, tenantID)

			return next.Query(ctx, q)
		})
	})
}

// addTenantFilterEfficient 使用高效的方式添加租户过滤器
func addTenantFilterEfficient(q ent.Query, tenantID uint64) {
	// 先尝试使用类型断言到具体的Query类型，避免使用reflection
	// 这比reflection快，因为不需要反射查找字段
	switch query := q.(type) {
	case interface{ Modify(func(*sql.Selector)) }:
		// 直接使用Modify方法，这是最高效的方式
		query.Modify(func(s *sql.Selector) {
			if shouldApplyTenantFilter(s.TableName()) {
				s.Where(sql.EQ(s.C("tenant_id"), tenantID))
			}
		})
		return
	}

	// 如果上述方法失败，回退到较慢但更通用的方式
	// 但是去掉昂贵的reflection，直接处理
	logx.Debugw("Query type assertion failed, tenant filter may not be applied",
		logx.Field("query_type", fmt.Sprintf("%T", q)))
}

// TenantFilterConfig 租户过滤配置
type TenantFilterConfig struct {
	// ExcludedTables 不需要租户过滤的表名列表
	ExcludedTables map[string]bool
	// ExcludedPatterns 不需要租户过滤的表名模式（支持通配符）
	ExcludedPatterns []string
	// GlobalTables 全局表（任何微服务都应该排除的表类型）
	GlobalTables []string
}

var (
	// defaultTenantFilterConfig 默认租户过滤配置
	defaultTenantFilterConfig = &TenantFilterConfig{
		ExcludedTables: make(map[string]bool),
		ExcludedPatterns: []string{
			"*_tenants",         // 所有租户表
			"*_audit_logs",      // 所有审计日志表
			"*_oauth_providers", // 所有OAuth提供商表
			"*_apis",            // 所有API表
			"*_migrations",      // 数据库迁移表
			"*_schema_*",        // 数据库schema表
		},
		GlobalTables: []string{
			"tenants", "audit_logs", "oauth_providers", "apis", "migrations",
		},
	}
)

// SetTenantFilterConfig 设置租户过滤配置（供各微服务自定义）
func SetTenantFilterConfig(config *TenantFilterConfig) {
	if config != nil {
		defaultTenantFilterConfig = config
	}
}

// AddExcludedTable 添加不需要租户过滤的表
func AddExcludedTable(tableName string) {
	if defaultTenantFilterConfig.ExcludedTables == nil {
		defaultTenantFilterConfig.ExcludedTables = make(map[string]bool)
	}
	defaultTenantFilterConfig.ExcludedTables[tableName] = true
}

// ShouldApplyTenantFilter 公开的函数，用于测试表是否需要租户过滤
func ShouldApplyTenantFilter(tableName string) bool {
	return shouldApplyTenantFilter(tableName)
}

// shouldApplyTenantFilter 检查表是否需要应用租户过滤
func shouldApplyTenantFilter(tableName string) bool {
	config := defaultTenantFilterConfig

	// 检查直接排除的表
	if config.ExcludedTables[tableName] {
		return false
	}

	// 检查通配符模式
	for _, pattern := range config.ExcludedPatterns {
		if matchPattern(pattern, tableName) {
			return false
		}
	}

	// 检查全局表类型（基于表名后缀）
	for _, globalType := range config.GlobalTables {
		if strings.HasSuffix(tableName, globalType) ||
			strings.Contains(tableName, "_"+globalType) ||
			strings.Contains(tableName, globalType+"_") {
			return false
		}
	}

	// 默认情况下，假设表需要租户过滤
	return true
}

// matchPattern 简单的通配符匹配（支持*）
func matchPattern(pattern, str string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// *xxx* 模式
		middle := pattern[1 : len(pattern)-1]
		return strings.Contains(str, middle)
	} else if strings.HasPrefix(pattern, "*") {
		// *xxx 模式
		suffix := pattern[1:]
		return strings.HasSuffix(str, suffix)
	} else if strings.HasSuffix(pattern, "*") {
		// xxx* 模式
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(str, prefix)
	}

	// 精确匹配
	return pattern == str
}
