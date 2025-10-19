// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/redis/go-redis/v9"
)

// RedisClient 定义Redis操作接口，兼容不同的Redis客户端
type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

// PermissionRuleEngine 权限规则引擎 - 负责将Casbin权限转换为数据过滤规则
type PermissionRuleEngine struct {
	casbinProvider CasbinProvider
	redis          RedisClient
	logger         *logging.MiddlewareLogger

	// 规则模板缓存
	ruleTemplates map[string]*RuleTemplate

	// 配置参数
	cacheExpiry   time.Duration
	enableMetrics bool
}

// RuleTemplate 规则模板定义
type RuleTemplate struct {
	ServiceName  string            `json:"service_name"`
	ResourceType string            `json:"resource_type"`
	Action       string            `json:"action"`
	SQLTemplate  string            `json:"sql_template"`
	FieldRules   []FieldRule       `json:"field_rules"`
	Conditions   []ConditionRule   `json:"conditions"`
	Priority     int               `json:"priority"`
	Metadata     map[string]string `json:"metadata"`
}

// FieldRule 字段级规则
type FieldRule struct {
	FieldName    string   `json:"field_name"`
	AccessLevels []string `json:"access_levels"` // read, write, admin
	MaskType     string   `json:"mask_type"`     // none, partial, full, encrypt
	MaskPattern  string   `json:"mask_pattern"`  // 掩码模式
	Conditions   []string `json:"conditions"`    // 应用条件
}

// ConditionRule 条件规则
type ConditionRule struct {
	Name       string                 `json:"name"`
	Expression string                 `json:"expression"` // 逻辑表达式
	SQLFilter  string                 `json:"sql_filter"` // 对应的SQL条件
	Parameters map[string]interface{} `json:"parameters"` // 动态参数
	Priority   int                    `json:"priority"`   // 优先级
}

// RuleGenerationContext 规则生成上下文
type RuleGenerationContext struct {
	UserID       string            `json:"user_id"`
	TenantID     string            `json:"tenant_id"`
	DepartmentID string            `json:"department_id"`
	Roles        []string          `json:"roles"`
	Context      map[string]string `json:"context"`
}

// NewPermissionRuleEngine 创建权限规则引擎
func NewPermissionRuleEngine(casbinProvider CasbinProvider, redis RedisClient, logger *logging.MiddlewareLogger) (*PermissionRuleEngine, error) {
	engine := &PermissionRuleEngine{
		casbinProvider: casbinProvider,
		redis:          redis,
		logger:         logger,
		ruleTemplates:  make(map[string]*RuleTemplate),
		cacheExpiry:    15 * time.Minute,
		enableMetrics:  true,
	}

	// 初始化默认规则模板
	if err := engine.initDefaultRuleTemplates(); err != nil {
		return nil, fmt.Errorf("failed to initialize default rule templates: %w", err)
	}

	logger.Info("permission rule engine initialized successfully")
	return engine, nil
}

// GenerateDataRules 生成数据过滤规则
func (e *PermissionRuleEngine) GenerateDataRules(ctx context.Context, userID, resource, action string, appliedRules []string) ([]*DataScopeRule, error) {
	startTime := time.Now()
	logger := e.logger.WithContext(ctx).WithFields(map[string]interface{}{
		"user_id":  userID,
		"resource": resource,
		"action":   action,
	})

	// 1. 构建规则生成上下文
	ruleCtx, err := e.buildRuleContext(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to build rule context: %w", err)
	}

	// 2. 检查缓存
	cacheKey := e.buildCacheKey(userID, resource, action, ruleCtx.TenantID)
	if cachedRules := e.getCachedRules(ctx, cacheKey); cachedRules != nil {
		logger.WithField("from_cache", true).Debug("using cached data rules")
		return cachedRules, nil
	}

	// 3. 基于Casbin规则生成数据过滤规则
	dataRules := []*DataScopeRule{}

	// 3.1 获取资源相关的规则模板
	templates := e.getMatchingTemplates(resource, action)
	for _, template := range templates {
		rule, err := e.generateRuleFromTemplate(ctx, template, ruleCtx, appliedRules)
		if err != nil {
			logger.WithError(err).WithField("template", template.ResourceType).Warn("failed to generate rule from template")
			continue
		}
		if rule != nil {
			dataRules = append(dataRules, rule)
		}
	}

	// 3.2 基于用户角色生成默认规则
	for _, role := range ruleCtx.Roles {
		if defaultRule := e.generateDefaultRuleForRole(ctx, role, resource, action, ruleCtx); defaultRule != nil {
			dataRules = append(dataRules, defaultRule)
		}
	}

	// 3.3 如果没有生成任何规则，使用最严格的默认规则
	if len(dataRules) == 0 {
		strictRule := e.generateStrictDefaultRule(resource, action)
		dataRules = append(dataRules, strictRule)
	}

	// 4. 缓存结果
	e.setCachedRules(ctx, cacheKey, dataRules)

	// 5. 记录指标
	duration := time.Since(startTime)
	logger.WithField("rules_count", len(dataRules)).
		WithField("duration_ms", duration.Milliseconds()).
		Info("data rules generated successfully")

	return dataRules, nil
}

// buildRuleContext 构建规则生成上下文
func (e *PermissionRuleEngine) buildRuleContext(ctx context.Context, userID string) (*RuleGenerationContext, error) {
	cm := keys.NewContextManager()

	tenantID := cm.GetTenantID(ctx)
	departmentID := cm.GetDeptID(ctx)
	dataScope := cm.GetDataScope(ctx)

	roles := splitRoleCodes(cm.GetRoleCodes(ctx))

	// 如果中间件已经注入了 PermissionContext，则优先复用其中的信息
	if permCtxVal := ctx.Value(keys.DataPermContextKey); permCtxVal != nil {
		if permCtx, ok := permCtxVal.(*PermissionContext); ok {
			if len(roles) == 0 && len(permCtx.Roles) > 0 {
				roles = append(roles, permCtx.Roles...)
			}
			if tenantID == "" && permCtx.TenantID != "" {
				tenantID = permCtx.TenantID
			}
			if departmentID == "" && permCtx.DepartmentID != "" {
				departmentID = permCtx.DepartmentID
			}
			if dataScope == "" && permCtx.DataScope != "" {
				dataScope = permCtx.DataScope
			}
		}
	}

	if len(roles) == 0 {
		fetchedRoles, err := e.casbinProvider.GetUserRolesWithCache(ctx, userID)
		if err != nil {
			e.logger.WithError(err).Warn("failed to get user roles, using empty roles")
		} else {
			roles = append(roles, fetchedRoles...)
		}
	}

	// 兼容旧版上下文提取逻辑，避免缺失
	if tenantID == "" {
		tenantID = e.extractFromContext(ctx, "tenant_id", "")
	}
	if departmentID == "" {
		departmentID = e.extractFromContext(ctx, "department_id", "")
	}

	roles = deduplicateStrings(roles)

	additional := make(map[string]string)
	if dataScope != "" {
		additional["data_scope"] = dataScope
	}
	if originalTenant := cm.GetOriginalTenantID(ctx); originalTenant != "" {
		additional["original_tenant_id"] = originalTenant
	}

	return &RuleGenerationContext{
		UserID:       userID,
		TenantID:     tenantID,
		DepartmentID: departmentID,
		Roles:        roles,
		Context:      additional,
	}, nil
}

func splitRoleCodes(roleCodes string) []string {
	if roleCodes == "" {
		return nil
	}
	split := strings.Split(roleCodes, ",")
	result := make([]string, 0, len(split))
	for _, raw := range split {
		code := strings.TrimSpace(raw)
		if code != "" {
			result = append(result, code)
		}
	}
	return result
}

func deduplicateStrings(values []string) []string {
	if len(values) <= 1 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

// getMatchingTemplates 获取匹配的规则模板
func (e *PermissionRuleEngine) getMatchingTemplates(resource, action string) []*RuleTemplate {
	var templates []*RuleTemplate

	for _, template := range e.ruleTemplates {
		if e.templateMatches(template, resource, action) {
			templates = append(templates, template)
		}
	}

	return templates
}

// templateMatches 检查模板是否匹配
func (e *PermissionRuleEngine) templateMatches(template *RuleTemplate, resource, action string) bool {
	// 精确匹配
	if template.ResourceType == resource && template.Action == action {
		return true
	}

	// 通配符匹配
	if template.ResourceType == "*" || template.Action == "*" {
		return true
	}

	// 前缀匹配
	if strings.HasSuffix(template.ResourceType, "*") {
		prefix := strings.TrimSuffix(template.ResourceType, "*")
		return strings.HasPrefix(resource, prefix)
	}

	return false
}

// generateRuleFromTemplate 从模板生成规则
func (e *PermissionRuleEngine) generateRuleFromTemplate(_ context.Context, template *RuleTemplate, ruleCtx *RuleGenerationContext, _ []string) (*DataScopeRule, error) {
	rule := &DataScopeRule{
		Resource:   template.ResourceType,
		Action:     template.Action,
		Priority:   template.Priority,
		Conditions: []string{},
		Fields:     []string{},
		FieldMasks: make(map[string]string),
		Metadata:   make(map[string]string),
	}

	// 1. 生成SQL过滤条件
	if template.SQLTemplate != "" {
		sqlCondition, err := e.renderSQLTemplate(template.SQLTemplate, ruleCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render SQL template: %w", err)
		}
		rule.Conditions = append(rule.Conditions, sqlCondition)
	}

	// 2. 处理字段级规则
	for _, fieldRule := range template.FieldRules {
		if e.userHasFieldAccess(ruleCtx, fieldRule) {
			rule.Fields = append(rule.Fields, fieldRule.FieldName)

			// 设置字段掩码
			if fieldRule.MaskType != "none" {
				rule.FieldMasks[fieldRule.FieldName] = fieldRule.MaskType
			}
		}
	}

	// 3. 处理条件规则
	for _, condRule := range template.Conditions {
		if e.conditionApplies(ruleCtx, condRule) {
			renderedCondition, err := e.renderCondition(condRule, ruleCtx)
			if err != nil {
				e.logger.WithError(err).Warn("failed to render condition")
				continue
			}
			rule.Conditions = append(rule.Conditions, renderedCondition)
		}
	}

	// 4. 设置元数据
	for k, v := range template.Metadata {
		rule.Metadata[k] = v
	}
	rule.Metadata["template"] = template.ResourceType + ":" + template.Action
	rule.Metadata["generated_at"] = time.Now().Format(time.RFC3339)

	return rule, nil
}

// generateDefaultRuleForRole 为角色生成默认规则
func (e *PermissionRuleEngine) generateDefaultRuleForRole(_ context.Context, role, resource, action string, ruleCtx *RuleGenerationContext) *DataScopeRule {
	// 基于角色的默认数据权限映射
	dataScope := e.getRoleDataScope(role)

	rule := &DataScopeRule{
		Resource: resource,
		Action:   action,
		Priority: 50, // 中等优先级
		Metadata: map[string]string{
			"source":       "role_default",
			"role":         role,
			"data_scope":   dataScope,
			"generated_at": time.Now().Format(time.RFC3339),
		},
	}

	// 根据数据范围生成SQL条件（使用安全的参数化条件）
	switch dataScope {
	case "all":
		// 全部数据访问 - 无额外条件
	case "own_dept":
		if ruleCtx.DepartmentID != "" && e.isValidID(ruleCtx.DepartmentID) {
			rule.Conditions = append(rule.Conditions, fmt.Sprintf("department_id = '%s'", e.sanitizeID(ruleCtx.DepartmentID)))
		}
	case "own_dept_and_sub":
		if ruleCtx.DepartmentID != "" && e.isValidID(ruleCtx.DepartmentID) {
			// 使用安全的查询条件，避免SQL注入
			rule.Conditions = append(rule.Conditions, fmt.Sprintf("department_id IN (SELECT id FROM departments WHERE parent_path LIKE '%%%s%%')", e.sanitizeID(ruleCtx.DepartmentID)))
		}
	case "self":
		if e.isValidID(ruleCtx.UserID) {
			rule.Conditions = append(rule.Conditions, fmt.Sprintf("user_id = '%s'", e.sanitizeID(ruleCtx.UserID)))
		}
	default:
		// 最严格的权限 - 只能访问自己的数据
		if e.isValidID(ruleCtx.UserID) {
			rule.Conditions = append(rule.Conditions, fmt.Sprintf("user_id = '%s'", e.sanitizeID(ruleCtx.UserID)))
		}
	}

	// 添加租户隔离条件
	if ruleCtx.TenantID != "" && e.isValidID(ruleCtx.TenantID) {
		rule.Conditions = append(rule.Conditions, fmt.Sprintf("tenant_id = '%s'", e.sanitizeID(ruleCtx.TenantID)))
	}

	return rule
}

// generateStrictDefaultRule 生成最严格的默认规则
func (e *PermissionRuleEngine) generateStrictDefaultRule(resource, action string) *DataScopeRule {
	return &DataScopeRule{
		Resource:   resource,
		Action:     action,
		Conditions: []string{"1 = 0"}, // 拒绝所有访问
		Fields:     []string{},
		FieldMasks: make(map[string]string),
		Priority:   1, // 最低优先级
		Metadata: map[string]string{
			"source":       "strict_default",
			"generated_at": time.Now().Format(time.RFC3339),
		},
	}
}

// getRoleDataScope 获取角色的数据权限范围
func (e *PermissionRuleEngine) getRoleDataScope(role string) string {
	// 角色到数据权限的映射
	roleScopeMap := map[string]string{
		"super_admin":  "all",
		"admin":        "all",
		"dept_manager": "own_dept_and_sub",
		"manager":      "own_dept",
		"user":         "self",
		"readonly":     "self",
	}

	if scope, exists := roleScopeMap[role]; exists {
		return scope
	}

	return "self" // 默认最严格
}

// Helper methods for template rendering and condition checking
func (e *PermissionRuleEngine) renderSQLTemplate(template string, ctx *RuleGenerationContext) (string, error) {
	result := template

	// 安全的模板变量替换 - 验证和清理所有值
	replacements := map[string]string{
		"{{user_id}}":       e.sanitizeTemplateValue(ctx.UserID),
		"{{tenant_id}}":     e.sanitizeTemplateValue(ctx.TenantID),
		"{{department_id}}": e.sanitizeTemplateValue(ctx.DepartmentID),
	}

	for placeholder, value := range replacements {
		// 只有值通过验证才进行替换
		if value != "" {
			result = strings.ReplaceAll(result, placeholder, value)
		} else {
			// 如果值无效，记录警告并移除整个占位符
			e.logger.WithField("placeholder", placeholder).Warn("invalid template value, removing placeholder")
			result = strings.ReplaceAll(result, placeholder, "''")
		}
	}

	return result, nil
}

// sanitizeTemplateValue 安全清理模板值
func (e *PermissionRuleEngine) sanitizeTemplateValue(value string) string {
	if !e.isValidID(value) {
		return ""
	}
	return e.sanitizeID(value)
}

func (e *PermissionRuleEngine) userHasFieldAccess(ctx *RuleGenerationContext, fieldRule FieldRule) bool {
	// 检查用户角色是否匹配字段访问级别
	for _, role := range ctx.Roles {
		for _, accessLevel := range fieldRule.AccessLevels {
			if e.roleMatchesAccessLevel(role, accessLevel) {
				return true
			}
		}
	}
	return false
}

func (e *PermissionRuleEngine) roleMatchesAccessLevel(role, accessLevel string) bool {
	roleAccessMap := map[string][]string{
		"super_admin": {"read", "write", "admin"},
		"admin":       {"read", "write", "admin"},
		"manager":     {"read", "write"},
		"user":        {"read"},
		"readonly":    {"read"},
	}

	allowedAccess, exists := roleAccessMap[role]
	if !exists {
		return false
	}

	for _, allowed := range allowedAccess {
		if allowed == accessLevel {
			return true
		}
	}
	return false
}

func (e *PermissionRuleEngine) conditionApplies(ctx *RuleGenerationContext, condition ConditionRule) bool {
	// 检查条件优先级，如果条件优先级太低，可能不适用
	if condition.Priority < 10 {
		return false
	}

	// 检查是否有必要的参数
	for key := range condition.Parameters {
		if key == "required_role" {
			if requiredRole, ok := condition.Parameters[key].(string); ok {
				// 检查用户是否具有所需角色
				for _, userRole := range ctx.Roles {
					if userRole == requiredRole {
						return true
					}
				}
				return false
			}
		}
	}

	// 默认情况下应用条件
	return true
}

func (e *PermissionRuleEngine) renderCondition(condition ConditionRule, ctx *RuleGenerationContext) (string, error) {
	return e.renderSQLTemplate(condition.SQLFilter, ctx)
}

func (e *PermissionRuleEngine) extractFromContext(ctx context.Context, key, defaultValue string) string {
	if value := ctx.Value(key); value != nil {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return defaultValue
}

// Cache operations
func (e *PermissionRuleEngine) buildCacheKey(userID, resource, action, tenantID string) string {
	return fmt.Sprintf("dataperm:rules:%s:%s:%s:%s", tenantID, userID, resource, action)
}

func (e *PermissionRuleEngine) getCachedRules(ctx context.Context, cacheKey string) []*DataScopeRule {
	if e.redis == nil {
		return nil
	}

	// 添加超时控制，避免Redis连接阻塞
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	data, err := e.redis.Get(ctxWithTimeout, cacheKey).Result()
	if err != nil {
		// 区分Redis错误类型，避免无效日志
		if err != redis.Nil {
			e.logger.WithError(err).WithField("cache_key", cacheKey).Warn("failed to get cached rules")
		}
		return nil
	}

	var rules []*DataScopeRule
	if err := json.Unmarshal([]byte(data), &rules); err != nil {
		e.logger.WithError(err).WithField("cache_key", cacheKey).Warn("failed to unmarshal cached rules")
		// 删除损坏的缓存数据
		go func() {
			if delErr := e.redis.Del(context.Background(), cacheKey).Err(); delErr != nil {
				e.logger.WithError(delErr).WithField("cache_key", cacheKey).Error("failed to delete corrupted cache")
			}
		}()
		return nil
	}

	return rules
}

func (e *PermissionRuleEngine) setCachedRules(ctx context.Context, cacheKey string, rules []*DataScopeRule) {
	if e.redis == nil {
		return
	}

	// 限制缓存数据大小，避免内存问题
	if len(rules) > 100 {
		e.logger.WithField("rules_count", len(rules)).Warn("too many rules for cache, skipping cache")
		return
	}

	data, err := json.Marshal(rules)
	if err != nil {
		e.logger.WithError(err).Warn("failed to marshal rules for cache")
		return
	}

	// 限制缓存数据大小（1MB限制）
	if len(data) > 1024*1024 {
		e.logger.WithField("data_size", len(data)).Warn("cache data too large, skipping cache")
		return
	}

	// 添加超时控制
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if err := e.redis.Set(ctxWithTimeout, cacheKey, data, e.cacheExpiry).Err(); err != nil {
		e.logger.WithError(err).WithField("cache_key", cacheKey).Warn("failed to cache rules")
	}
}

// initDefaultRuleTemplates 初始化默认规则模板
func (e *PermissionRuleEngine) initDefaultRuleTemplates() error {
	// CMDB服务规则模板（使用安全的参数化SQL）
	cmdbTemplates := []*RuleTemplate{
		{
			ServiceName:  "cmdb",
			ResourceType: "configuration_item",
			Action:       "read",
			SQLTemplate:  "department_id IN (SELECT id FROM departments WHERE parent_path LIKE CONCAT('%', '{{department_id}}', '%')) AND tenant_id = '{{tenant_id}}'",
			FieldRules: []FieldRule{
				{FieldName: "password", AccessLevels: []string{"admin"}, MaskType: "full"},
				{FieldName: "secret_key", AccessLevels: []string{"admin"}, MaskType: "encrypt"},
				{FieldName: "private_info", AccessLevels: []string{"admin", "manager"}, MaskType: "partial"},
			},
			Priority: 80,
		},
		{
			ServiceName:  "cmdb",
			ResourceType: "asset",
			Action:       "list",
			SQLTemplate:  "status = 'active' AND tenant_id = '{{tenant_id}}'",
			Priority:     70,
		},
	}

	// 工作流服务规则模板
	workflowTemplates := []*RuleTemplate{
		{
			ServiceName:  "workflow",
			ResourceType: "process_instance",
			Action:       "approve",
			SQLTemplate:  "current_approver = '{{user_id}}' AND tenant_id = '{{tenant_id}}'",
			Priority:     90,
		},
	}

	// 注册所有模板
	allTemplates := append(cmdbTemplates, workflowTemplates...)
	for _, template := range allTemplates {
		key := fmt.Sprintf("%s:%s:%s", template.ServiceName, template.ResourceType, template.Action)
		e.ruleTemplates[key] = template
	}

	e.logger.WithField("templates_count", len(allTemplates)).Info("default rule templates initialized")
	return nil
}

// isValidID 验证ID格式是否安全，防止SQL注入
func (e *PermissionRuleEngine) isValidID(id string) bool {
	if id == "" {
		return false
	}

	// 只允许字母数字、下划线和连字符，长度在1-64之间
	validIDPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
	return validIDPattern.MatchString(id)
}

// sanitizeID 清理ID值，移除潜在的危险字符
func (e *PermissionRuleEngine) sanitizeID(id string) string {
	// 移除所有可能的SQL注入字符
	dangerousChars := []string{
		"'", "\"", ";", "--", "/*", "*/", "\\", "\n", "\r", "\t",
		"DROP", "DELETE", "UPDATE", "INSERT", "EXEC", "EXECUTE",
		"UNION", "SELECT", "FROM", "WHERE", "OR", "AND",
	}

	result := id
	for _, char := range dangerousChars {
		result = strings.ReplaceAll(result, char, "")
		result = strings.ReplaceAll(result, strings.ToUpper(char), "")
		result = strings.ReplaceAll(result, strings.ToLower(char), "")
	}

	// 限制长度
	if len(result) > 64 {
		result = result[:64]
	}

	return result
}
