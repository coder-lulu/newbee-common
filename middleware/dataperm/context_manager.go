// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
)

// EnhancedContextManager 增强的上下文管理器 - 负责在请求上下文中注入数据权限信息
type EnhancedContextManager struct {
	logger *logging.MiddlewareLogger
}

// PermissionContext 权限上下文信息
type PermissionContext struct {
	UserID       string                 `json:"user_id"`
	TenantID     string                 `json:"tenant_id"`
	DepartmentID string                 `json:"department_id"`
	Roles        []string               `json:"roles"`
	DataScope    string                 `json:"data_scope"`
	DataRules    []*DataScopeRule       `json:"data_rules"`
	FieldMasks   map[string]string      `json:"field_masks"`
	SQLFilters   []string               `json:"sql_filters"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// DataPermLevel 数据权限级别
type DataPermLevel string

const (
	DataPermAll        DataPermLevel = "all"          // 全部数据
	DataPermOwnDept    DataPermLevel = "own_dept"     // 本部门
	DataPermOwnDeptSub DataPermLevel = "own_dept_sub" // 本部门及子部门
	DataPermSelf       DataPermLevel = "self"         // 仅自己
	DataPermCustom     DataPermLevel = "custom"       // 自定义
	DataPermStrict     DataPermLevel = "strict"       // 最严格
)

// NewEnhancedContextManager 创建增强的上下文管理器
func NewEnhancedContextManager(logger *logging.MiddlewareLogger) *EnhancedContextManager {
	return &EnhancedContextManager{
		logger: logger,
	}
}

// SetEnhancedPermissions 设置增强的权限信息到上下文
func (cm *EnhancedContextManager) SetEnhancedPermissions(ctx context.Context, userID, tenantID string, dataRules []*DataScopeRule) context.Context {
	permCtx := &PermissionContext{
		UserID:     userID,
		TenantID:   tenantID,
		DataRules:  dataRules,
		FieldMasks: make(map[string]string),
		SQLFilters: []string{},
		Metadata:   make(map[string]interface{}),
	}

	// 从数据规则中提取字段掩码和SQL过滤条件
	cm.extractPermissionInfo(permCtx, dataRules)

	// 将权限上下文注入到请求上下文中
	ctx = context.WithValue(ctx, keys.DataPermContextKey, permCtx)
	ctx = cm.attachDataScopeContext(ctx, permCtx)

	cm.logger.WithContext(ctx).
		WithField("user_id", userID).
		WithField("tenant_id", tenantID).
		WithField("rules_count", len(dataRules)).
		Debug("enhanced permissions set in context")

	return ctx
}

// SetDefaultPermissions 设置默认权限（用于fallback）
func (cm *EnhancedContextManager) SetDefaultPermissions(ctx context.Context, userID, tenantID string) context.Context {
	// 创建默认的最保守权限规则
	defaultRule := &DataScopeRule{
		Resource:   "default",
		Action:     "read",
		Conditions: []string{fmt.Sprintf("user_id = '%s'", userID)},
		Fields:     []string{}, // 空字段列表 = 默认字段
		FieldMasks: make(map[string]string),
		Priority:   1,
		Metadata: map[string]string{
			"source":     "default_fallback",
			"level":      "conservative",
			"data_scope": string(DataPermSelf),
		},
	}

	// 添加租户隔离条件
	if tenantID != "" {
		defaultRule.Conditions = append(defaultRule.Conditions, fmt.Sprintf("tenant_id = '%s'", tenantID))
	}

	return cm.SetEnhancedPermissions(ctx, userID, tenantID, []*DataScopeRule{defaultRule})
}

// SetStrictPermissions 设置最严格的权限（用于权限被拒绝时）
func (cm *EnhancedContextManager) SetStrictPermissions(ctx context.Context, userID, tenantID string) context.Context {
	strictRule := &DataScopeRule{
		Resource:   "restricted",
		Action:     "denied",
		Conditions: []string{"1 = 0"}, // 拒绝所有访问
		Fields:     []string{},
		FieldMasks: map[string]string{
			"*": "full", // 所有字段全部掩码
		},
		Priority: 0,
		Metadata: map[string]string{
			"source":     "permission_denied",
			"level":      "strict",
			"data_scope": string(DataPermStrict),
		},
	}

	return cm.SetEnhancedPermissions(ctx, userID, tenantID, []*DataScopeRule{strictRule})
}

// GetPermissionContext 从上下文中获取权限信息
func (cm *EnhancedContextManager) GetPermissionContext(ctx context.Context) *PermissionContext {
	if permCtx := ctx.Value(keys.DataPermContextKey); permCtx != nil {
		if typed, ok := permCtx.(*PermissionContext); ok {
			return typed
		}
	}
	return nil
}

// GetDataRules 获取数据规则
func (cm *EnhancedContextManager) GetDataRules(ctx context.Context) []*DataScopeRule {
	if permCtx := cm.GetPermissionContext(ctx); permCtx != nil {
		return permCtx.DataRules
	}
	return []*DataScopeRule{}
}

// GetSQLFilters 获取SQL过滤条件
func (cm *EnhancedContextManager) GetSQLFilters(ctx context.Context) []string {
	if permCtx := cm.GetPermissionContext(ctx); permCtx != nil {
		return permCtx.SQLFilters
	}
	return []string{}
}

// GetFieldMasks 获取字段掩码信息
func (cm *EnhancedContextManager) GetFieldMasks(ctx context.Context) map[string]string {
	if permCtx := cm.GetPermissionContext(ctx); permCtx != nil {
		return permCtx.FieldMasks
	}
	return make(map[string]string)
}

// GetDataScope 获取数据权限范围
func (cm *EnhancedContextManager) GetDataScope(ctx context.Context) string {
	if permCtx := cm.GetPermissionContext(ctx); permCtx != nil {
		return permCtx.DataScope
	}
	return string(DataPermSelf) // 默认最严格
}

// IsFieldAccessible 检查字段是否可访问
func (cm *EnhancedContextManager) IsFieldAccessible(ctx context.Context, fieldName string) bool {
	permCtx := cm.GetPermissionContext(ctx)
	if permCtx == nil {
		return false // 无权限上下文时默认拒绝
	}

	// 检查字段掩码
	if maskType, exists := permCtx.FieldMasks[fieldName]; exists {
		return maskType != "full" // full掩码表示完全不可访问
	}

	// 检查是否在允许的字段列表中
	if len(permCtx.DataRules) > 0 {
		for _, rule := range permCtx.DataRules {
			// 如果字段列表为空，表示允许所有字段
			if len(rule.Fields) == 0 {
				return true
			}

			// 检查字段是否在允许列表中
			for _, allowedField := range rule.Fields {
				if allowedField == fieldName || allowedField == "*" {
					return true
				}
			}
		}
		return false // 有字段列表但不在其中
	}

	return true // 无特定规则时允许访问
}

// GetFieldMaskType 获取字段的掩码类型
func (cm *EnhancedContextManager) GetFieldMaskType(ctx context.Context, fieldName string) string {
	permCtx := cm.GetPermissionContext(ctx)
	if permCtx == nil {
		return "none"
	}

	// 检查具体字段的掩码
	if maskType, exists := permCtx.FieldMasks[fieldName]; exists {
		return maskType
	}

	// 检查通配符掩码
	if maskType, exists := permCtx.FieldMasks["*"]; exists {
		return maskType
	}

	return "none"
}

// HasPermissionFor 检查是否对特定资源和操作有权限
func (cm *EnhancedContextManager) HasPermissionFor(ctx context.Context, resource, action string) bool {
	permCtx := cm.GetPermissionContext(ctx)
	if permCtx == nil {
		return false
	}

	for _, rule := range permCtx.DataRules {
		if (rule.Resource == resource || rule.Resource == "*") &&
			(rule.Action == action || rule.Action == "*") {

			// 检查是否有拒绝条件
			for _, condition := range rule.Conditions {
				if condition == "1 = 0" { // 明确拒绝
					return false
				}
			}
			return true
		}
	}

	return false
}

// ApplyFieldMask 应用字段掩码
func (cm *EnhancedContextManager) ApplyFieldMask(ctx context.Context, fieldName string, value interface{}) interface{} {
	maskType := cm.GetFieldMaskType(ctx, fieldName)

	switch maskType {
	case "none":
		return value
	case "full":
		return "***" // 完全隐藏
	case "partial":
		return cm.applyPartialMask(value)
	case "encrypt":
		return cm.applyEncryptMask(value)
	default:
		return value
	}
}

// GetPermissionSummary 获取权限摘要信息（用于调试和监控）
func (cm *EnhancedContextManager) GetPermissionSummary(ctx context.Context) map[string]interface{} {
	permCtx := cm.GetPermissionContext(ctx)
	if permCtx == nil {
		return map[string]interface{}{
			"status": "no_permission_context",
		}
	}

	summary := map[string]interface{}{
		"user_id":           permCtx.UserID,
		"tenant_id":         permCtx.TenantID,
		"data_scope":        permCtx.DataScope,
		"rules_count":       len(permCtx.DataRules),
		"sql_filters":       permCtx.SQLFilters,
		"field_masks":       permCtx.FieldMasks,
		"accessible_fields": cm.getAccessibleFields(permCtx),
	}

	return summary
}

// 内部辅助方法

// extractPermissionInfo 从数据规则中提取权限信息
func (cm *EnhancedContextManager) extractPermissionInfo(permCtx *PermissionContext, dataRules []*DataScopeRule) {
	// 合并所有规则的SQL条件
	sqlConditions := []string{}
	fieldMasks := make(map[string]string)

	// 确定数据权限范围（取最高优先级规则的范围）
	maxPriority := -1
	var dataScope string = string(DataPermSelf)

	for _, rule := range dataRules {
		// 收集SQL条件
		sqlConditions = append(sqlConditions, rule.Conditions...)

		// 收集字段掩码
		for field, maskType := range rule.FieldMasks {
			fieldMasks[field] = maskType
		}

		// 确定数据权限范围
		if rule.Priority > maxPriority {
			maxPriority = rule.Priority
			if scope, exists := rule.Metadata["data_scope"]; exists {
				dataScope = scope
			}
		}
	}

	permCtx.SQLFilters = cm.deduplicateConditions(sqlConditions)
	permCtx.FieldMasks = fieldMasks
	normalizedScope, scopeLabel := normalizeDataScope(dataScope)
	permCtx.DataScope = normalizedScope
	if permCtx.Metadata == nil {
		permCtx.Metadata = make(map[string]interface{})
	}
	permCtx.Metadata["data_scope_label"] = scopeLabel
	permCtx.Metadata["data_scope_raw"] = strings.TrimSpace(dataScope)

	// 设置元数据
	permCtx.Metadata["rules_processed"] = len(dataRules)
	permCtx.Metadata["sql_conditions_count"] = len(permCtx.SQLFilters)
	permCtx.Metadata["field_masks_count"] = len(permCtx.FieldMasks)
}

// attachDataScopeContext 将归一化后的数据域传播到标准上下文与 gRPC metadata
func (cm *EnhancedContextManager) attachDataScopeContext(ctx context.Context, permCtx *PermissionContext) context.Context {
	if permCtx == nil {
		return ctx
	}

	dataScope := strings.TrimSpace(permCtx.DataScope)
	if dataScope == "" {
		return ctx
	}

	baseCM := keys.NewContextManager()
	ctx = baseCM.SetDataScope(ctx, dataScope)

	// 设置统一的数据权限 metadata，供 RPC 层 ent hook 读取
	ctx = datapermctx.WithScopeContext(ctx, dataScope)

	return ctx
}

// normalizeDataScope 将插件内部的数据域枚举标准化为 ent 使用的整型字符串
func normalizeDataScope(scope string) (string, string) {
	trimmed := strings.TrimSpace(scope)
	if trimmed == "" {
		return entenum.DataPermOwnStr, string(DataPermSelf)
	}

	if label, ok := scopeLabelByNumeric[trimmed]; ok {
		return trimmed, label
	}

	lower := strings.ToLower(trimmed)
	switch lower {
	case string(DataPermAll):
		return entenum.DataPermAllStr, string(DataPermAll)
	case string(DataPermOwnDeptSub), "own_dept_and_sub", "dept_and_sub":
		return entenum.DataPermOwnDeptAndSubStr, string(DataPermOwnDeptSub)
	case string(DataPermOwnDept):
		return entenum.DataPermOwnDeptStr, string(DataPermOwnDept)
	case string(DataPermCustom):
		return entenum.DataPermCustomDeptStr, string(DataPermCustom)
	case string(DataPermStrict):
		return entenum.DataPermOwnStr, string(DataPermStrict)
	case string(DataPermSelf), "own":
		return entenum.DataPermOwnStr, string(DataPermSelf)
	}

	return entenum.DataPermOwnStr, lower
}

var scopeLabelByNumeric = map[string]string{
	entenum.DataPermAllStr:           string(DataPermAll),
	entenum.DataPermCustomDeptStr:    string(DataPermCustom),
	entenum.DataPermOwnDeptAndSubStr: string(DataPermOwnDeptSub),
	entenum.DataPermOwnDeptStr:       string(DataPermOwnDept),
	entenum.DataPermOwnStr:           string(DataPermSelf),
}

// deduplicateConditions 去重SQL条件
func (cm *EnhancedContextManager) deduplicateConditions(conditions []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, condition := range conditions {
		if !seen[condition] && condition != "" {
			seen[condition] = true
			result = append(result, condition)
		}
	}

	return result
}

// applyPartialMask 应用部分掩码
func (cm *EnhancedContextManager) applyPartialMask(value interface{}) interface{} {
	str := fmt.Sprintf("%v", value)
	if len(str) <= 3 {
		return "***"
	}

	// 保留前后各一个字符，中间用*代替
	return str[:1] + "***" + str[len(str)-1:]
}

// applyEncryptMask 应用加密掩码
func (cm *EnhancedContextManager) applyEncryptMask(_ interface{}) interface{} {
	// 简化的加密掩码实现
	return "[ENCRYPTED]"
}

// getAccessibleFields 获取可访问的字段列表
func (cm *EnhancedContextManager) getAccessibleFields(permCtx *PermissionContext) []string {
	accessibleFields := []string{}

	for _, rule := range permCtx.DataRules {
		for _, field := range rule.Fields {
			// 检查字段是否被完全掩码
			if maskType, exists := permCtx.FieldMasks[field]; exists && maskType == "full" {
				continue
			}
			accessibleFields = append(accessibleFields, field)
		}
	}

	return cm.deduplicateFields(accessibleFields)
}

// deduplicateFields 去重字段列表
func (cm *EnhancedContextManager) deduplicateFields(fields []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, field := range fields {
		if !seen[field] {
			seen[field] = true
			result = append(result, field)
		}
	}

	return result
}

// SerializePermissionContext 序列化权限上下文（用于日志和调试）
func (cm *EnhancedContextManager) SerializePermissionContext(ctx context.Context) string {
	permCtx := cm.GetPermissionContext(ctx)
	if permCtx == nil {
		return "{}"
	}

	data, err := json.Marshal(permCtx)
	if err != nil {
		cm.logger.WithError(err).Warn("failed to serialize permission context")
		return "{}"
	}

	return string(data)
}
