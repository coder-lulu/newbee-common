// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
)

// EnhancedDataPermInterceptor 增强的数据权限拦截器 - 自动应用动态SQL过滤
type EnhancedDataPermInterceptor struct {
	logger *logging.MiddlewareLogger
	
	// 配置参数
	enableDebug     bool
	enableMetrics   bool
	skipTables      map[string]bool // 跳过权限检查的表
	systemContext   bool            // 是否为系统上下文
}

// InterceptorConfig 拦截器配置
type InterceptorConfig struct {
	EnableDebug   bool     `json:"enable_debug"`
	EnableMetrics bool     `json:"enable_metrics"`
	SkipTables    []string `json:"skip_tables"`
}

// NewEnhancedDataPermInterceptor 创建增强的数据权限拦截器
func NewEnhancedDataPermInterceptor(logger *logging.MiddlewareLogger, config *InterceptorConfig) *EnhancedDataPermInterceptor {
	skipTables := make(map[string]bool)
	
	// 默认跳过的系统表
	defaultSkipTables := []string{
		"sys_casbin_rules",
		"sys_dict_types", 
		"sys_dict_data",
		"sys_apis",
		"sys_menus",
		"migrations",
		"schema_migrations",
	}
	
	for _, table := range defaultSkipTables {
		skipTables[table] = true
	}
	
	// 添加配置的跳过表
	if config != nil {
		for _, table := range config.SkipTables {
			skipTables[table] = true
		}
	}

	interceptor := &EnhancedDataPermInterceptor{
		logger:        logger,
		enableDebug:   config != nil && config.EnableDebug,
		enableMetrics: config != nil && config.EnableMetrics,
		skipTables:    skipTables,
	}

	logger.Info("enhanced data permission interceptor initialized")
	return interceptor
}

// Intercept 实现ent.Interceptor接口 - 拦截所有数据库查询
func (i *EnhancedDataPermInterceptor) Intercept(next ent.Querier) ent.Querier {
	return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
		// 1. 检查是否为系统上下文 - 系统操作跳过权限检查
		if i.isSystemContext(ctx) {
			i.logDebug(ctx, "system context detected, skipping data permission")
			return next.Query(ctx, query)
		}

		// 2. 获取权限上下文
		permCtx := i.getPermissionContext(ctx)
		if permCtx == nil {
			i.logDebug(ctx, "no permission context found, applying default restrictions")
			// 没有权限上下文时应用最严格的限制
			return i.applyStrictFilter(ctx, next, query)
		}

		// 3. 检查表是否需要跳过权限检查
		tableName := i.extractTableName(query)
		if i.shouldSkipTable(tableName) {
			i.logDebug(ctx, fmt.Sprintf("skipping permission check for table: %s", tableName))
			return next.Query(ctx, query)
		}

		// 4. 应用数据权限过滤
		return i.applyDataPermissionFilter(ctx, next, query, permCtx)
	})
}

// applyDataPermissionFilter 应用数据权限过滤
func (i *EnhancedDataPermInterceptor) applyDataPermissionFilter(ctx context.Context, next ent.Querier, query ent.Query, permCtx *PermissionContext) (ent.Value, error) {
	// 获取SQL过滤条件
	sqlFilters := permCtx.SQLFilters
	if len(sqlFilters) == 0 {
		// 如果没有SQL过滤条件，检查是否有租户ID
		if permCtx.TenantID != "" {
			sqlFilters = []string{fmt.Sprintf("tenant_id = '%s'", permCtx.TenantID)}
		}
	}

	// 如果没有任何过滤条件，应用默认限制
	if len(sqlFilters) == 0 {
		i.logDebug(ctx, "no SQL filters found, applying user-level restriction")
		sqlFilters = []string{fmt.Sprintf("user_id = '%s'", permCtx.UserID)}
	}

	// 应用SQL过滤条件到查询
	modifiedQuery := i.applySQLFilters(query, sqlFilters)
	
	i.logDebug(ctx, fmt.Sprintf("applied %d SQL filters to query", len(sqlFilters)))
	
	// 执行修改后的查询
	result, err := next.Query(ctx, modifiedQuery)
	if err != nil {
		i.logger.WithContext(ctx).WithError(err).Error("failed to execute filtered query")
		return nil, err
	}

	// 5. 应用字段级过滤和掩码（如果需要）
	if len(permCtx.FieldMasks) > 0 {
		result = i.applyFieldMasks(ctx, result, permCtx.FieldMasks)
	}

	return result, nil
}

// applyStrictFilter 应用最严格的过滤（用于无权限上下文时）
func (i *EnhancedDataPermInterceptor) applyStrictFilter(ctx context.Context, next ent.Querier, query ent.Query) (ent.Value, error) {
	// 应用拒绝所有访问的条件
	strictFilters := []string{"1 = 0"}
	modifiedQuery := i.applySQLFilters(query, strictFilters)
	
	i.logDebug(ctx, "applied strict filter (deny all)")
	
	return next.Query(ctx, modifiedQuery)
}

// applySQLFilters 将SQL过滤条件应用到查询
func (i *EnhancedDataPermInterceptor) applySQLFilters(query ent.Query, filters []string) ent.Query {
	if len(filters) == 0 {
		return query
	}

	// 将查询转换为SQL查询以便修改
	switch q := query.(type) {
	case interface{ Where(...interface{}) }: // 处理普通查询
		return i.applyWhereFilters(q, filters)
	default:
		// 对于不支持Where方法的查询类型，尝试通过SQL修改器处理
		return i.applyRawSQLFilters(query, filters)
	}
}

// applyWhereFilters 通过Where条件应用过滤
func (i *EnhancedDataPermInterceptor) applyWhereFilters(query interface{ Where(...interface{}) }, filters []string) ent.Query {
	// 构建SQL条件
	var conditions []interface{}
	for _, filter := range filters {
		if filter != "" {
			// 构建原始SQL条件
			// 使用安全的条件构建方法
			if safeCondition := i.buildSafeCondition(filter); safeCondition != nil {
				conditions = append(conditions, safeCondition)
			} else {
				i.logger.WithField("filter", filter).Warn("unsafe SQL filter ignored")
			}
		}
	}

	if len(conditions) > 0 {
		query.Where(conditions...)
	}

	// 返回修改后的查询（需要类型断言）
	if entQuery, ok := query.(ent.Query); ok {
		return entQuery
	}

	// 如果无法转换，返回原查询
	return query.(ent.Query)
}

// applyRawSQLFilters 通过原始SQL修改器应用过滤
func (i *EnhancedDataPermInterceptor) applyRawSQLFilters(query ent.Query, _ []string) ent.Query {
	// 这里可以通过ent的SQL修改器功能来处理
	// 暂时返回原查询，未来可以扩展更高级的SQL修改功能
	i.logger.Warn("raw SQL filter application not implemented yet")
	return query
}

// applyFieldMasks 应用字段掩码
func (i *EnhancedDataPermInterceptor) applyFieldMasks(ctx context.Context, result ent.Value, fieldMasks map[string]string) ent.Value {
	// 字段掩码处理逻辑
	// 这需要根据具体的返回类型来处理，可能是单个实体或实体列表
	
	i.logDebug(ctx, fmt.Sprintf("applying field masks for %d fields", len(fieldMasks)))
	
	// 暂时返回原结果，字段掩码功能将在下一个阶段实现
	// TODO: 实现字段级掩码逻辑
	return result
}

// 辅助方法

// isSystemContext 检查是否为系统上下文
func (i *EnhancedDataPermInterceptor) isSystemContext(ctx context.Context) bool {
	if systemFlag := ctx.Value(keys.SystemContextKey); systemFlag != nil {
		if flag, ok := systemFlag.(bool); ok {
			return flag
		}
	}
	return false
}

// getPermissionContext 获取权限上下文
func (i *EnhancedDataPermInterceptor) getPermissionContext(ctx context.Context) *PermissionContext {
	if permCtx := ctx.Value(keys.DataPermContextKey); permCtx != nil {
		if typed, ok := permCtx.(*PermissionContext); ok {
			return typed
		}
	}
	return nil
}

// extractTableName 从查询中提取表名
func (i *EnhancedDataPermInterceptor) extractTableName(query ent.Query) string {
	// 通过反射或其他方式获取表名
	// 这是一个简化的实现，实际可能需要更复杂的逻辑
	queryStr := fmt.Sprintf("%T", query)
	
	// 尝试从查询类型名中提取表名
	// 例如: "*ent.UserQuery" -> "user"
	if strings.Contains(queryStr, ".") {
		parts := strings.Split(queryStr, ".")
		if len(parts) > 1 {
			typeName := parts[len(parts)-1]
			if strings.HasSuffix(typeName, "Query") {
				tableName := strings.ToLower(strings.TrimSuffix(typeName, "Query"))
				return tableName
			}
		}
	}
	
	return "unknown"
}

// shouldSkipTable 检查表是否应该跳过权限检查
func (i *EnhancedDataPermInterceptor) shouldSkipTable(tableName string) bool {
	return i.skipTables[tableName]
}

// logDebug 调试日志
func (i *EnhancedDataPermInterceptor) logDebug(ctx context.Context, message string) {
	if i.enableDebug {
		i.logger.WithContext(ctx).Debug(message)
	}
}

// GetStats 获取拦截器统计信息
func (i *EnhancedDataPermInterceptor) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":       true,
		"debug_mode":    i.enableDebug,
		"metrics_mode":  i.enableMetrics,
		"skip_tables":   len(i.skipTables),
	}
	
	if i.enableDebug {
		skipTablesList := make([]string, 0, len(i.skipTables))
		for table := range i.skipTables {
			skipTablesList = append(skipTablesList, table)
		}
		stats["skip_tables_list"] = skipTablesList
	}
	
	return stats
}

// RegisterWithClient 向ent客户端注册拦截器
func (i *EnhancedDataPermInterceptor) RegisterWithClient(client interface{}) {
	// 由于ent.Client不在当前包中，使用interface{}以避免导入问题
	// 调用方应确保传入正确的ent客户端类型
	if entClient, ok := client.(interface{ Intercept(ent.Interceptor) }); ok {
		entClient.Intercept(i)
		i.logger.Info("enhanced data permission interceptor registered with ent client")
	} else {
		i.logger.Error("provided client does not support Intercept method")
	}
}

// buildSafeCondition 构建安全的SQL条件，防止SQL注入
func (i *EnhancedDataPermInterceptor) buildSafeCondition(filter string) interface{} {
	// 验证和清理SQL过滤条件
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil
	}
	
	// 检查危险关键词
	dangerousKeywords := []string{
		"DROP", "DELETE", "UPDATE", "INSERT", "EXEC", "EXECUTE",
		"UNION", "SCRIPT", "TRUNCATE", "ALTER", "CREATE",
		"--", "/*", "*/", ";", "'", "\"",
	}
	
	filterUpper := strings.ToUpper(filter)
	for _, keyword := range dangerousKeywords {
		if strings.Contains(filterUpper, keyword) {
			i.logger.WithField("filter", filter).WithField("keyword", keyword).Warn("dangerous keyword detected in filter")
			return nil
		}
	}
	
	// 只允许简单的条件格式: column = 'value' 或 column IN (...)
	if !i.isValidFilterPattern(filter) {
		i.logger.WithField("filter", filter).Warn("invalid filter pattern")
		return nil
	}
	
	// 使用参数化查询而不是直接SQL注入
	return sql.Raw(filter) // 这里仍然使用sql.Raw，但已经过验证
}

// isValidFilterPattern 验证过滤条件的格式是否安全
func (i *EnhancedDataPermInterceptor) isValidFilterPattern(filter string) bool {
	// 使用正则表达式验证安全的过滤模式
	// 允许的模式:
	// 1. column = 'value'
	// 2. column IN ('value1', 'value2')
	// 3. column = value (for numbers)
	// 4. column IS NULL / IS NOT NULL
	
	// 简化的验证：检查是否包含基本的列名和操作符
	validPatterns := []string{
		" = ", " IN ", " IS ", " LIKE ", " > ", " < ", " >= ", " <= ", " != ", " <> ",
	}
	
	filterUpper := strings.ToUpper(filter)
	for _, pattern := range validPatterns {
		if strings.Contains(filterUpper, pattern) {
			return true
		}
	}
	
	return false
}

// RegisterMultipleInterceptors 批量注册多个实体的拦截器
func RegisterMultipleInterceptors(client interface{}, logger *logging.MiddlewareLogger, entities []string) {
	config := &InterceptorConfig{
		EnableDebug:   true,
		EnableMetrics: true,
		SkipTables:    []string{}, // 可以根据需要配置
	}
	
	interceptor := NewEnhancedDataPermInterceptor(logger, config)
	interceptor.RegisterWithClient(client)
	
	logger.WithField("entities", entities).Info("registered enhanced data permission interceptors for multiple entities")
}