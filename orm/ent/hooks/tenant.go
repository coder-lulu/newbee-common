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
	"reflect"
	"runtime"
	"strings"
	"unsafe"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/metadata"
)

// 注意：SystemContext 相关的键值现在使用统一的 keys 管理器

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

	return context.WithValue(ctx, keys.SystemContextKey, true)
}

// isSystemContext checks if the context is a system context.
func isSystemContext(ctx context.Context) bool {
	// 首先检查上下文值
	val, ok := ctx.Value(keys.SystemContextKey).(bool)
	if ok && val {
		return true
	}
	
	// 检查 gRPC metadata 中的 SystemContext 标识
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if data := md.Get(string(keys.SystemContextKey)); len(data) > 0 && data[0] == "true" {
			return true
		}
	}
	
	return false
}

// fromContext returns the tenant ID from the context.
// 🔧 简化逻辑：直接调用 GetTenantIDFromCtx，它会处理所有查找逻辑
func fromContext(ctx context.Context) (uint64, error) {
	// GetTenantIDFromCtx 会自动从 context value 或 metadata 中提取租户ID
	tenantID := tenantctx.GetTenantIDFromCtx(ctx)

	if tenantID > 0 {
		logx.Infow("✅ fromContext - successfully got tenant_id",
			logx.Field("tenant_id", tenantID))
		return tenantID, nil
	}

	// 检查是否有上下文信息但转换失败（用于诊断）
	hasContextValue := ctx.Value(keys.TenantIDKey) != nil
	hasMetadata := false
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if data := md.Get(string(keys.TenantIDKey)); len(data) > 0 {
			hasMetadata = true
			logx.Errorw("❌ fromContext - tenant_id exists in metadata but GetTenantIDFromCtx failed",
				logx.Field("has_context_value", hasContextValue),
				logx.Field("has_metadata", hasMetadata),
				logx.Field("metadata_value", data[0]))
		}
	}

	if hasContextValue {
		logx.Errorw("❌ fromContext - tenant_id exists in context value but GetTenantIDFromCtx failed",
			logx.Field("has_context_value", hasContextValue),
			logx.Field("context_value", ctx.Value(keys.TenantIDKey)))
	}

	if !hasContextValue && !hasMetadata {
		logx.Errorw("❌ fromContext - no tenant_id found in context or metadata",
			logx.Field("context_keys", fmt.Sprintf("%v", ctx)))
	}

	// 拒绝请求，防止使用默认租户ID（TenantDefaultId）导致的安全漏洞
	return 0, errors.New("tenant id not found or invalid in context: refusing to use default tenant ID for security reasons")
}

// isValidTenantContext checks if context contains valid tenant information
func isValidTenantContext(ctx context.Context) bool {
	// 检查context value中是否有租户ID
	if tenantIDStr, ok := ctx.Value(keys.TenantIDKey).(string); ok && tenantIDStr != "" && tenantIDStr != "0" {
		return true
	}

	// 检查gRPC metadata中是否有租户ID
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if data := md.Get(string(keys.TenantIDKey)); len(data) > 0 && data[0] != "" && data[0] != "0" {
			return true
		}
	}

	// 如果两者都没有，返回false
	return false
}

// DiagnoseTenantContext 诊断租户上下文状态，用于调试
func DiagnoseTenantContext(ctx context.Context) map[string]any {
	result := make(map[string]any)

	result["is_system_context"] = isSystemContext(ctx)
	result["is_public_context"] = tenantctx.GetPublicAccessCtx(ctx)
	result["has_string_tenant_id"] = ctx.Value(keys.TenantIDKey) != nil
	result["is_valid_tenant_context"] = isValidTenantContext(ctx)

	// 获取实际的租户ID值
	if tenantIDStr, ok := ctx.Value(keys.TenantIDKey).(string); ok {
		result["string_tenant_id"] = tenantIDStr
	}

	result["tenant_id_from_helper"] = tenantctx.GetTenantIDFromCtx(ctx)

	// 检查 gRPC metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if data := md.Get(string(keys.TenantIDKey)); len(data) > 0 {
			result["grpc_metadata_tenant_id"] = data[0]
		}
	}

	return result
}

// TenantMutator is an interface that all tenant-scoped mutations implement.
type TenantMutator interface {
	SetTenantID(uint64)
}

// getTenantIDFromMutation 使用反射调用mutation的TenantID()方法获取tenant_id值
// 返回 (tenantID uint64, exists bool)
func getTenantIDFromMutation(m ent.Mutation) (uint64, bool) {
	// 使用反射调用mutation的TenantID()方法
	// 所有ent生成的mutation都有 func (m *XxxMutation) TenantID() (uint64, bool) 方法
	mv := reflect.ValueOf(m)
	method := mv.MethodByName("TenantID")

	if !method.IsValid() {
		// 方法不存在（可能不是tenant-scoped的entity）
		return 0, false
	}

	// 调用TenantID()方法
	results := method.Call([]reflect.Value{})
	if len(results) != 2 {
		// 返回值数量不对
		return 0, false
	}

	// 第一个返回值是uint64类型的tenant_id值
	// 第二个返回值是bool类型的exists标志
	tenantID := results[0].Uint()
	exists := results[1].Bool()

	return tenantID, exists
}

// TenantMutationHook returns a hook that sets the tenant_id on all creations.
//
// Deprecated: 此函数已被弃用，请使用统一Hook系统替代。
// 推荐使用: hooks.QuickSetup(db) 一键设置所有hooks
// 或者使用: hooks.RegisterTenantHooks(db) 仅注册租户hooks
// 详细文档: /opt/code/newbee/common/docs/统一Hook系统使用指南.md
func TenantMutationHook() ent.Hook {
	// 🔒 互斥检测：防止与新版Hook系统冲突
	hookSystemMutex.Lock()
	defer hookSystemMutex.Unlock()

	if hookSystemInitialized && hookSystemType == "new" {
		logx.Errorw("❌ Hook system conflict detected!",
			logx.Field("error", "new hook system already initialized"),
			logx.Field("action", "this TenantMutationHook() call will be ignored"),
			logx.Field("recommendation", "remove TenantMutationHook() and use QuickSetup() instead"))
		// 返回空Hook避免重复处理
		return func(next ent.Mutator) ent.Mutator {
			return next
		}
	}

	// 标记使用旧版Hook
	if !hookSystemInitialized {
		hookSystemInitialized = true
		hookSystemType = "legacy"
		logx.Infow("⚠️ Using legacy TenantMutationHook",
			logx.Field("deprecated", true),
			logx.Field("recommendation", "migrate to QuickSetup()"))
	}

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
						// 🔧 修复: 使用反射调用mutation的TenantID()方法，正确检测tenant_id是否已设置
						tenantIDValue, exists := getTenantIDFromMutation(m)
						if exists {
							logx.Infow("SystemContext preserving explicitly set tenant ID",
								logx.Field("tenant_id", tenantIDValue),
								logx.Field("entity_type", m.Type()))
							// Keep the explicitly set tenant_id
						} else {
							// Only set to 0 if not explicitly provided
							tm.SetTenantID(0) // 0 indicates system entity
							logx.Infow("SystemContext setting tenant_id to 0 (no explicit value provided)",
								logx.Field("entity_type", m.Type()))
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
						// 🔧 修复: 使用反射调用mutation的TenantID()方法，正确检测tenant_id是否已设置
						tenantIDValue, exists := getTenantIDFromMutation(m)
						if exists {
							logx.Infow("PublicContext preserving explicitly set tenant ID",
								logx.Field("tenant_id", tenantIDValue),
								logx.Field("entity_type", m.Type()))
							// Keep the explicitly set tenant_id
						} else {
							// Only set to 0 if not explicitly provided
							tm.SetTenantID(0) // 0 indicates system/public entity
							logx.Infow("PublicContext setting tenant_id to 0 (no explicit value provided)",
								logx.Field("entity_type", m.Type()))
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
//
// Deprecated: 此函数已被弃用，请使用统一Hook系统替代。
// 推荐使用: hooks.QuickSetup(db) 一键设置所有hooks
// 或者使用: hooks.RegisterTenantHooks(db) 仅注册租户hooks
// 详细文档: /opt/code/newbee/common/docs/统一Hook系统使用指南.md
func TenantQueryInterceptor() ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			// 系统上下文跳过租户过滤
			if isSystemContext(ctx) {
				logx.WithContext(ctx).Debugw("SystemContext detected, bypassing tenant filter",
					logx.Field("query_type", fmt.Sprintf("%T", q)))
				return next.Query(ctx, q)
			}

			// 公共访问上下文跳过租户过滤 (用于访问共享数据)
			if tenantctx.GetPublicAccessCtx(ctx) {
				logx.WithContext(ctx).Debugw("PublicAccess context detected, bypassing tenant filter",
					logx.Field("query_type", fmt.Sprintf("%T", q)))
				return next.Query(ctx, q)
			}

			// 获取租户ID
			tenantID, err := fromContext(ctx)
			if err != nil {
				// 添加详细的上下文诊断信息
				logx.WithContext(ctx).Errorw("Failed to get tenant ID from context",
					logx.Field("error", err.Error()),
					logx.Field("query_type", fmt.Sprintf("%T", q)),
					logx.Field("has_uint64_tenant_id", ctx.Value("tenantId") != nil),
					logx.Field("has_string_tenant_id", ctx.Value(keys.TenantIDKey) != nil),
					logx.Field("is_system_context", isSystemContext(ctx)),
					logx.Field("is_public_context", tenantctx.GetPublicAccessCtx(ctx)))
				return nil, err
			}

			// 🔍 添加日志：记录拦截器被触发
			logx.WithContext(ctx).Infow("🔍 TenantQueryInterceptor triggered",
				logx.Field("query_type", fmt.Sprintf("%T", q)),
				logx.Field("tenant_id", tenantID))

			// 使用高效的类型断言方式添加租户过滤
			addTenantFilterEfficient(q, tenantID)

			return next.Query(ctx, q)
		})
	})
}

// addTenantFilterEfficient 使用高效的方式添加租户过滤器
func addTenantFilterEfficient(q ent.Query, tenantID uint64) {
	// ent的Query都有modifiers字段，我们可以通过反射直接添加modifier
	// 这是最通用且最高效的方式

	// 尝试类型断言到带有Modify方法的接口（注意：Modify返回的是Select，不是Query）
	// 我们需要直接访问modifiers字段

	// 使用通用的方式：通过ent提供的modifier功能
	// 所有ent生成的Query都支持通过modifiers字段添加SQL修改器

	// 注意：ent的Query.Modify方法签名
	// func (q *Query) Modify(modifiers ...func(s *sql.Selector)) *Select

	// 尝试另一种方式：检查Query是否有modifiers字段（通过反射）
	// 但首先尝试最直接的方式：使用ent的内部机制

	// 正确的方式：创建一个modifier函数并添加到查询中
	modifier := func(s *sql.Selector) {
		tableName := s.TableName()
		shouldFilter := shouldApplyTenantFilter(tableName)

		logx.Infow("🔍 Tenant filter check",
			logx.Field("table", tableName),
			logx.Field("should_filter", shouldFilter),
			logx.Field("tenant_id", tenantID))

		if shouldFilter {
			s.Where(sql.EQ(s.C("tenant_id"), tenantID))
			logx.Infow("✅ Tenant filter APPLIED",
				logx.Field("table", tableName),
				logx.Field("tenant_id", tenantID))
		} else {
			logx.Infow("⏭️  Tenant filter SKIPPED",
				logx.Field("table", tableName),
				logx.Field("reason", "table in exclusion list"))
		}
	}

	// 尝试通过反射访问modifiers字段并添加modifier
	if success := tryAddModifier(q, modifier); success {
		logx.Debugw("✅ Successfully added tenant filter modifier via reflection")
		return
	}

	// 如果反射失败，记录错误
	logx.Errorw("❌ Failed to add tenant filter, query type not supported",
		logx.Field("query_type", fmt.Sprintf("%T", q)))
}

// tryAddModifier 尝试通过反射添加modifier到查询
func tryAddModifier(q ent.Query, modifier func(*sql.Selector)) bool {
	// 使用反射访问Query的modifiers字段
	v := reflect.ValueOf(q)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// 查找modifiers字段
	modifiersField := v.FieldByName("modifiers")
	if !modifiersField.IsValid() {
		return false
	}

	// 检查类型是否正确
	if modifiersField.Kind() != reflect.Slice {
		return false
	}

	// 使用反射设置字段（需要确保字段可设置）
	if !modifiersField.CanSet() {
		// 尝试使用unsafe来设置私有字段
		modifiersField = reflect.NewAt(modifiersField.Type(), unsafe.Pointer(modifiersField.UnsafeAddr())).Elem()
	}

	// 添加modifier到切片
	newModifiers := reflect.Append(modifiersField, reflect.ValueOf(modifier))
	modifiersField.Set(newModifiers)

	return true
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
