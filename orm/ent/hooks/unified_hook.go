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
	"strings"
	"unsafe"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/zeromicro/go-zero/core/logx"
)

// FieldType 字段类型枚举
type FieldType string

const (
	FieldTypeTenant     FieldType = "tenant_id"
	FieldTypeDepartment FieldType = "department_id"
	FieldTypeUser       FieldType = "user_id"
	FieldTypeCreatedBy  FieldType = "created_by"
)

// FieldConfig 字段配置
type FieldConfig struct {
	// FieldName 数据库字段名
	FieldName string

	// FieldType 字段类型（用于识别）
	FieldType FieldType

	// SetterMethod mutation中设置字段值的方法名（如 "SetTenantID"）
	SetterMethod string

	// GetterMethod mutation中获取字段值的方法名（如 "TenantID"）
	GetterMethod string

	// ContextExtractor 从context中��取字段值的函数
	ContextExtractor func(context.Context) (uint64, error)

	// ShouldApplyFilter 判断表是否需要应用过滤的函数
	ShouldApplyFilter func(tableName string) bool

	// IsSystemContext 判断是否为系统上下文（跳过过滤）
	IsSystemContext func(context.Context) bool

	// ExcludedEntities 不需要Hook处理的实体类型名称（如 "Tenant"）
	ExcludedEntities []string

	// RequireValue 是否要求字段值必须存在（true=严格模式，false=宽松模式）
	RequireValue bool

	// DefaultValue 当字段值不存在时的默认值（仅在RequireValue=false时使用）
	DefaultValue uint64

	// SecurityCritical 是否为安全关键字段（如tenant_id）
	// true: 宽松模式下缺少值时返回空结果（防止数据泄露）
	// false: 宽松模式下缺少值时跳过过滤（允许查询）
	SecurityCritical bool
}

func isEntityExcluded(entityType string, excluded []string) bool {
	for _, candidate := range excluded {
		if strings.EqualFold(entityType, candidate) {
			return true
		}
	}
	return false
}

// UnifiedHookManager 统一Hook管理器
type UnifiedHookManager struct {
	configs map[FieldType]*FieldConfig
}

// NewUnifiedHookManager 创建统一Hook管理器
func NewUnifiedHookManager() *UnifiedHookManager {
	return &UnifiedHookManager{
		configs: make(map[FieldType]*FieldConfig),
	}
}

// RegisterField 注册字段配置
func (m *UnifiedHookManager) RegisterField(config *FieldConfig) {
	m.configs[config.FieldType] = config
	logx.Infow("Registered unified hook field",
		logx.Field("field_type", config.FieldType),
		logx.Field("field_name", config.FieldName),
		logx.Field("require_value", config.RequireValue))
}

// GetConfig 获取字段配置
func (m *UnifiedHookManager) GetConfig(fieldType FieldType) *FieldConfig {
	return m.configs[fieldType]
}

// CreateMutationHook 创建变更Hook（用于Create操作）
func (m *UnifiedHookManager) CreateMutationHook(fieldType FieldType) ent.Hook {
	config := m.configs[fieldType]
	if config == nil {
		logx.Errorw("Field config not found for mutation hook",
			logx.Field("field_type", fieldType))
		return func(next ent.Mutator) ent.Mutator {
			return next
		}
	}

	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			// 🔍 添加Hook入口日志
			logx.Infow("🎯 MutationHook ENTRY",
				logx.Field("field_type", config.FieldType),
				logx.Field("entity_type", mutation.Type()),
				logx.Field("operation", mutation.Op().String()))

			entityType := mutation.Type()
			if isEntityExcluded(entityType, config.ExcludedEntities) {
				logx.Debugw("Entity excluded from hook",
					logx.Field("field_type", config.FieldType),
					logx.Field("entity_type", entityType))
				return next.Mutate(ctx, mutation)
			}

			// 检查是否为系统上下文
			if config.IsSystemContext != nil && config.IsSystemContext(ctx) {
				logx.Debugw("System context detected, handling specially",
					logx.Field("field_type", config.FieldType),
					logx.Field("entity_type", mutation.Type()),
					logx.Field("operation", mutation.Op().String()))

				// 如果上下文中存在显式的租户/部门值，优先使用它
				if mutation.Op().Is(ent.OpCreate) && config.ContextExtractor != nil {
					if ctxValue, err := config.ContextExtractor(ctx); err == nil && ctxValue > 0 {
						m.setFieldValue(mutation, config, ctxValue)
						logx.Infow("System context: honoring explicit context value",
							logx.Field("field_type", config.FieldType),
							logx.Field("entity_type", entityType),
							logx.Field("value", ctxValue))
						return next.Mutate(ctx, mutation)
					}
				}

				// 系统上下文：仅在Create操作时处理
				if mutation.Op().Is(ent.OpCreate) {
					// ✅ 修复: 使用反射调用mutation的Getter方法来正确检测字段是否被设置
					existingValue, exists := getFieldFromMutation(mutation, config.GetterMethod)
					if exists {
						// 检查是否为非默认值
						var isDefaultValue bool
						if uint64Val, ok := existingValue.(uint64); ok {
							// 🔧 修复: 只检查0和config.DefaultValue，移除对1的检查
							// tenant_id=1是合法的第一个租户ID，不应该被视为默认值
							isDefaultValue = (uint64Val == 0 || uint64Val == config.DefaultValue)
						}

						if !isDefaultValue {
							// 显式设置的非默认值，保留它
							logx.Infow("System context: field explicitly set, preserving value",
								logx.Field("field_type", config.FieldType),
								logx.Field("value", existingValue))
						} else {
							// 默认值，设置为0（系统级实体）
							m.setFieldValue(mutation, config, 0)
							logx.Infow("System context: override default value to 0",
								logx.Field("field_type", config.FieldType),
								logx.Field("entity_type", entityType),
								logx.Field("old_value", existingValue))
						}
					} else {
						// 字段未设置，设置为0
						m.setFieldValue(mutation, config, 0)
						logx.Infow("System context: set field to 0",
							logx.Field("field_type", config.FieldType),
							logx.Field("entity_type", entityType))
					}
				}
				return next.Mutate(ctx, mutation)
			}

			// 只处理Create操作
			if !mutation.Op().Is(ent.OpCreate) {
				return next.Mutate(ctx, mutation)
			}

			// ✅ 修复: 使用反射调用mutation的Getter方法来正确检测字段是否被设置
			existingValue, exists := getFieldFromMutation(mutation, config.GetterMethod)
			if exists {
				// 检查是否为非默认值
				var isDefaultValue bool
				if uint64Val, ok := existingValue.(uint64); ok {
					// 🔧 修复: 只检查0和config.DefaultValue，移除对1的检查
					// tenant_id=1是合法的第一个租户ID，不应该被视为默认值
					isDefaultValue = (uint64Val == 0 || uint64Val == config.DefaultValue)
				}

				if !isDefaultValue {
					// 字段值不是默认值，说明是显式设置的，保留它
					logx.Infow("⚠️ Field explicitly set, preserving value",
						logx.Field("field_type", config.FieldType),
						logx.Field("entity_type", entityType),
						logx.Field("value", existingValue))
					return next.Mutate(ctx, mutation)
				}

				// 字段值是默认值，继续从context设置正确的值
				logx.Infow("🔄 Field has default value, will override from context",
					logx.Field("field_type", config.FieldType),
					logx.Field("entity_type", entityType),
					logx.Field("default_value", existingValue))
			}

			// 从上下文提取字段值
			fieldValue, err := config.ContextExtractor(ctx)
			if err != nil {
				if config.RequireValue {
					// 严格模式：字段值必须存在
					logx.Errorw("Required field value not found in context",
						logx.Field("field_type", config.FieldType),
						logx.Field("entity_type", entityType),
						logx.Field("error", err.Error()))
					return nil, fmt.Errorf("%s: %w", config.FieldType, err)
				} else {
					// 宽松模式：使用默认值
					fieldValue = config.DefaultValue
					logx.Infow("Field value not found, using default",
						logx.Field("field_type", config.FieldType),
						logx.Field("default_value", fieldValue))
				}
			}

			// 设置字段值
			if err := m.setFieldValue(mutation, config, fieldValue); err != nil {
				logx.Errorw("Failed to set field value",
					logx.Field("field_type", config.FieldType),
					logx.Field("error", err.Error()))
				return nil, err
			}

			logx.Infow("Auto-injected field value",
				logx.Field("field_type", config.FieldType),
				logx.Field("entity_type", entityType),
				logx.Field("value", fieldValue))

			return next.Mutate(ctx, mutation)
		})
	}
}

// CreateQueryInterceptor 创建查询拦截器（用于Query操作）
func (m *UnifiedHookManager) CreateQueryInterceptor(fieldType FieldType) ent.Interceptor {
	config := m.configs[fieldType]
	if config == nil {
		logx.Errorw("Field config not found for query interceptor",
			logx.Field("field_type", fieldType))
		return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
			return next
		})
	}

	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// 检查是否为系统上下文
			if config.IsSystemContext != nil && config.IsSystemContext(ctx) {
				logx.Debugw("System context detected, bypassing filter",
					logx.Field("field_type", config.FieldType),
					logx.Field("query_type", fmt.Sprintf("%T", query)))
				return next.Query(ctx, query)
			}

			// 从上下文获取字段值
			fieldValue, err := config.ContextExtractor(ctx)
			if err != nil {
				if config.RequireValue {
					// 严格模式：必须有字段值
					logx.Errorw("Required field value not found in context",
						logx.Field("field_type", config.FieldType),
						logx.Field("query_type", fmt.Sprintf("%T", query)),
						logx.Field("error", err.Error()))
					return nil, fmt.Errorf("%s: %w", config.FieldType, err)
				} else {
					// 🔒 宽松模式：根据SecurityCritical标志决定处理方式
					if config.SecurityCritical {
						// 安全关键字段（如tenant_id）：返回空结果防止数据泄露
						logx.Infow("⚠️ Security-critical field value not found in relaxed mode, returning empty result",
							logx.Field("field_type", config.FieldType),
							logx.Field("query_type", fmt.Sprintf("%T", query)))

						// 添加一个永远不匹配的SQL条件，返回空结果
						emptyModifier := func(s *sql.Selector) {
							// 安全地获取表名
							defer func() {
								if r := recover(); r != nil {
									logx.Debugw("Cannot get table name in empty modifier",
										logx.Field("field_type", config.FieldType))
								}
							}()

							tableName := s.TableName()
							logx.Infow("🔒 Applying empty filter for security-critical field",
								logx.Field("field_type", config.FieldType),
								logx.Field("table", tableName))

							// 使用 sql.False() 返回空结果
							s.Where(sql.False())
						}

						if success := tryAddModifierUnified(query, emptyModifier); !success {
							logx.Errorw("Failed to add empty filter",
								logx.Field("field_type", config.FieldType))
						}

						return next.Query(ctx, query)
					} else {
						// 普通字段（如department_id）：跳过过滤，允许查询
						logx.Debugw("Optional field value not found, skipping filter",
							logx.Field("field_type", config.FieldType),
							logx.Field("query_type", fmt.Sprintf("%T", query)))
						return next.Query(ctx, query)
					}
				}
			}

			logx.Infow("Applying field filter",
				logx.Field("field_type", config.FieldType),
				logx.Field("query_type", fmt.Sprintf("%T", query)),
				logx.Field("value", fieldValue))

			// 添加SQL过滤器
			m.addQueryFilter(query, config, fieldValue)

			return next.Query(ctx, query)
		})
	})
}

// setFieldValue 使用反射设置字段值
func (m *UnifiedHookManager) setFieldValue(mutation ent.Mutation, config *FieldConfig, value uint64) error {
	mutationValue := reflect.ValueOf(mutation)
	setterMethod := mutationValue.MethodByName(config.SetterMethod)

	if !setterMethod.IsValid() {
		return fmt.Errorf("setter method %s not found", config.SetterMethod)
	}

	// 检查方法签名
	if setterMethod.Type().NumIn() != 1 || setterMethod.Type().In(0).Kind() != reflect.Uint64 {
		return fmt.Errorf("invalid setter method signature: expected func(uint64), got %s",
			setterMethod.Type().String())
	}

	// 调用setter方法
	setterMethod.Call([]reflect.Value{reflect.ValueOf(value)})
	return nil
}

// addQueryFilter 添加查询过滤器
func (m *UnifiedHookManager) addQueryFilter(query ent.Query, config *FieldConfig, value uint64) {
	// 创建SQL modifier
	modifier := func(s *sql.Selector) {
		// 安全地获取表名，避免panic
		var tableName string
		defer func() {
			if r := recover(); r != nil {
				// 无法获取表名（如子查询），跳过过滤
				logx.Debugw("Skip filter: cannot get table name (possibly subquery)",
					logx.Field("field_type", config.FieldType),
					logx.Field("recover", r))
			}
		}()

		tableName = s.TableName()

		// 检查是否需要应用过滤
		shouldFilter := true
		if config.ShouldApplyFilter != nil {
			shouldFilter = config.ShouldApplyFilter(tableName)
		}

		logx.Debugw("Field filter check",
			logx.Field("field_type", config.FieldType),
			logx.Field("table", tableName),
			logx.Field("should_filter", shouldFilter),
			logx.Field("value", value))

		if shouldFilter {
			s.Where(sql.EQ(s.C(config.FieldName), value))
			logx.Infow("Field filter APPLIED",
				logx.Field("field_type", config.FieldType),
				logx.Field("table", tableName),
				logx.Field("value", value))
		} else {
			logx.Debugw("Field filter SKIPPED",
				logx.Field("field_type", config.FieldType),
				logx.Field("table", tableName),
				logx.Field("reason", "table in exclusion list"))
		}
	}

	// 使用反射添加modifier到query
	if success := tryAddModifierUnified(query, modifier); !success {
		logx.Errorw("Failed to add query filter",
			logx.Field("field_type", config.FieldType),
			logx.Field("query_type", fmt.Sprintf("%T", query)))
	}
}

// tryAddModifierUnified 尝试通过反射添加modifier到查询
func tryAddModifierUnified(q ent.Query, modifier func(*sql.Selector)) bool {
	v := reflect.ValueOf(q)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	modifiersField := v.FieldByName("modifiers")
	if !modifiersField.IsValid() || modifiersField.Kind() != reflect.Slice {
		return false
	}

	if !modifiersField.CanSet() {
		modifiersField = reflect.NewAt(modifiersField.Type(),
			unsafe.Pointer(modifiersField.UnsafeAddr())).Elem()
	}

	newModifiers := reflect.Append(modifiersField, reflect.ValueOf(modifier))
	modifiersField.Set(newModifiers)

	return true
}

// getFieldFromMutation 使用反射调用mutation的字段getter方法获取字段值
// 返回 (fieldValue any, exists bool)
// 这个函数与tenant.go中的getTenantIDFromMutation类似，但更通用，支持任意字段
func getFieldFromMutation(m ent.Mutation, getterMethod string) (any, bool) {
	// 使用反射调用mutation的getter方法
	// 所有ent生成的mutation都有 func (m *XxxMutation) FieldName() (Type, bool) 方法
	mv := reflect.ValueOf(m)
	method := mv.MethodByName(getterMethod)

	if !method.IsValid() {
		// 方法不存在（可能字段类型不支持）
		return nil, false
	}

	// 调用getter方法
	results := method.Call([]reflect.Value{})
	if len(results) != 2 {
		// 返回值数量不对
		return nil, false
	}

	// 第一个返回值是字段值
	// 第二个返回值是bool类型的exists标志
	fieldValue := results[0].Interface()
	exists := results[1].Bool()

	return fieldValue, exists
}

// GlobalHookManager 全局Hook管理器实例
var GlobalHookManager = NewUnifiedHookManager()

// RegisterHooksToClient 将所有注册的hooks应用到ent client
func RegisterHooksToClient(client interface{}, fieldTypes ...FieldType) error {
	clientValue := reflect.ValueOf(client)

	// 获取Use方法（用于注册mutation hooks）
	useMethod := clientValue.MethodByName("Use")
	if !useMethod.IsValid() {
		return errors.New("client does not have Use method")
	}

	// 获取Intercept方法（用于注册query interceptors）
	interceptMethod := clientValue.MethodByName("Intercept")
	if !interceptMethod.IsValid() {
		return errors.New("client does not have Intercept method")
	}

	// 如果没有指定字段类型，则注册所有已配置的字段
	if len(fieldTypes) == 0 {
		for fieldType := range GlobalHookManager.configs {
			fieldTypes = append(fieldTypes, fieldType)
		}
	}

	// 注册每个字段的hooks
	for _, fieldType := range fieldTypes {
		config := GlobalHookManager.GetConfig(fieldType)
		if config == nil {
			logx.Infow("Field config not found, skipping",
				logx.Field("field_type", fieldType))
			continue
		}

		// 注册mutation hook
		mutationHook := GlobalHookManager.CreateMutationHook(fieldType)
		useMethod.Call([]reflect.Value{reflect.ValueOf(mutationHook)})
		logx.Infow("Registered mutation hook",
			logx.Field("field_type", fieldType))

		// 注册query interceptor
		queryInterceptor := GlobalHookManager.CreateQueryInterceptor(fieldType)
		interceptMethod.Call([]reflect.Value{reflect.ValueOf(queryInterceptor)})
		logx.Infow("Registered query interceptor",
			logx.Field("field_type", fieldType))
	}

	return nil
}
