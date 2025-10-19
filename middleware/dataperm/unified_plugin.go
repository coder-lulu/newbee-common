// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
)

// CasbinProvider 提供Casbin权限检查服务的接口
type CasbinProvider interface {
	// CheckPermissionWithRoles 检查权限（包含角色支持）
	CheckPermissionWithRoles(ctx context.Context, subject, object, action, serviceName string) (*PermissionResult, error)
	// GetUserRolesWithCache 获取用户角色（带缓存）
	GetUserRolesWithCache(ctx context.Context, user string) ([]string, error)
}

// PermissionResult Casbin权限检查结果
type PermissionResult struct {
	Allowed      bool     `json:"allowed"`
	Reason       string   `json:"reason"`
	AppliedRules []string `json:"applied_rules"`
	FromCache    bool     `json:"from_cache"`
}

// DataScopeRule 数据范围规则定义
type DataScopeRule struct {
	Resource   string            `json:"resource"`    // 资源类型
	Action     string            `json:"action"`      // 操作类型
	Conditions []string          `json:"conditions"`  // SQL过滤条件
	Fields     []string          `json:"fields"`      // 可访问字段
	FieldMasks map[string]string `json:"field_masks"` // 字段掩码规则
	Priority   int               `json:"priority"`    // 规则优先级
	Metadata   map[string]string `json:"metadata"`    // 扩展元数据
}

// FieldPermission 字段级权限定义
type FieldPermission struct {
	FieldName   string `json:"field_name"`   // 字段名称
	AccessType  string `json:"access_type"`  // 访问类型: read, write, none
	MaskType    string `json:"mask_type"`    // 掩码类型: hide, partial, encrypt
	MaskPattern string `json:"mask_pattern"` // 掩码模式
}

// ConditionalPermission 条件权限定义
type ConditionalPermission struct {
	Condition  string                 `json:"condition"`  // 权限条件表达式
	SQLFilter  string                 `json:"sql_filter"` // 生成的SQL过滤条件
	Parameters map[string]interface{} `json:"parameters"` // 动态参数
}

// UnifiedDataPermPlugin 统一数据权限插件 - 集成Casbin的高级数据权限控制
type UnifiedDataPermPlugin struct {
	core           *framework.CoreServices
	config         *framework.DataPermConfig
	casbinProvider CasbinProvider
	ruleEngine     *PermissionRuleEngine
	contextManager *EnhancedContextManager
	logger         *logging.MiddlewareLogger

	// 缓存管理（已弃用占位）
	ruleCache map[string]*DataScopeRule

	// 统计信息（使用原子操作）
	checkCount        int64
	cacheHitCount     int64
	avgResponseTimeMs atomic.Uint64
	statsLock         sync.Mutex
}

const superAdminRoleCode = "superadmin"

// NewUnifiedDataPermPlugin 创建统一数据权限插件
func NewUnifiedDataPermPlugin(casbinProvider CasbinProvider) framework.MiddlewarePlugin {
	return &UnifiedDataPermPlugin{
		casbinProvider: casbinProvider,
		// ruleCache 保留以兼容旧接口，暂无内部使用
		ruleCache: make(map[string]*DataScopeRule),
	}
}

func (p *UnifiedDataPermPlugin) Name() string {
	return "UnifiedDataPermission"
}

func (p *UnifiedDataPermPlugin) Priority() int {
	return 25 // 在Auth(10)、TenantCheck(15)、Permission(18)之后执行
}

func (p *UnifiedDataPermPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.config = core.Config.DataPerm
	p.logger = logging.NewMiddlewareLogger("unified-dataperm")

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("unified dataperm config is missing or disabled").
			Build()
		p.logger.WithError(err).Error("unified data permission plugin initialization failed")
		return err
	}

	// 初始化权限规则引擎
	var err error
	// 创建Redis客户端适配器
	var redisClient RedisClient
	if core.Redis != nil {
		redisClient = &RedisClientAdapter{client: core.Redis}
	}
	p.ruleEngine, err = NewPermissionRuleEngine(p.casbinProvider, redisClient, p.logger)
	if err != nil {
		p.logger.WithError(err).Error("failed to initialize permission rule engine")
		return err
	}

	// 初始化增强的上下文管理器
	p.contextManager = NewEnhancedContextManager(p.logger)

	p.logger.WithField("casbin_enabled", p.config.CasbinEnabled).
		Info("unified data permission plugin initialized successfully")

	return nil
}

func (p *UnifiedDataPermPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		logger := p.logger.WithContext(r.Context()).WithRequest(r)

		// 检查是否跳过
		if p.shouldSkip(r.URL.Path) {
			logger.WithField("skipped", true).Debug("unified data permission check skipped for path")
			next(w, r)
			return
		}

		ctx := r.Context()
		cm := p.core.ContextManager

		// 验证用户认证
		userID := cm.GetUserID(ctx)
		if userID == "" {
			err := errors.NewDataPermError(errors.CodeDataPermDenied, "", "")
			logger.WithError(err).WithDuration(startTime).Error("cannot process data permissions, user not authenticated")
			next(w, r)
			return
		}

		// 获取租户信息
		tenantID := cm.GetTenantID(ctx)
		if tenantID == "" {
			logger.WithField("user_id", userID).WithDuration(startTime).Warn("no tenant ID found for user")
		}

		// 超级管理员直接放行，附带审计标记，避免误触发数据权限拒绝
		roleCodes := cm.GetRoleCodes(ctx)
		isSuperAdmin := false
		for _, code := range strings.Split(roleCodes, ",") {
			if strings.TrimSpace(code) == superAdminRoleCode {
				isSuperAdmin = true
				break
			}
		}

		if isSuperAdmin {
			originalTenant := cm.GetOriginalTenantID(ctx)
			bypassRule := &DataScopeRule{
				Resource:   "*",
				Action:     "bypass",
				Conditions: []string{},
				Fields:     []string{"*"},
				FieldMasks: map[string]string{},
				Priority:   100,
				Metadata: map[string]string{
					"source":     "superadmin_bypass",
					"data_scope": string(DataPermAll),
				},
			}

			bypassCtx := p.contextManager.SetEnhancedPermissions(ctx, userID, tenantID, []*DataScopeRule{bypassRule})
			timestamp := time.Now().Format(time.RFC3339Nano)
			if permCtx := p.contextManager.GetPermissionContext(bypassCtx); permCtx != nil {
				if permCtx.Metadata == nil {
					permCtx.Metadata = make(map[string]interface{})
				}
				permCtx.DataScope = string(DataPermAll)
				permCtx.Metadata["bypass"] = true
				permCtx.Metadata["bypass_reason"] = "superadmin_impersonation"
				permCtx.Metadata["bypass_timestamp"] = timestamp
				if originalTenant != "" {
					permCtx.Metadata["original_tenant_id"] = originalTenant
				}
			}
			bypassCtx = cm.SetDataScope(bypassCtx, string(DataPermAll))
			auditTags := map[string]string{
				"dataperm_bypass":           "superadmin",
				"dataperm_bypass_reason":    "superadmin_impersonation",
				"dataperm_bypass_timestamp": timestamp,
			}
			if originalTenant != "" {
				auditTags["dataperm_original_tenant"] = originalTenant
			}
			auditTags["active_tenant_id"] = tenantID
			bypassCtx = attachAuditMetadata(bypassCtx, auditTags)
			logger.WithField("user_id", userID).
				WithField("tenant_id", tenantID).
				WithField("original_tenant_id", originalTenant).
				WithField("role_codes", roleCodes).
				Info("superadmin bypass applied, data permission skipped")

			next(w, r.WithContext(bypassCtx))
			return
		}

		// 🔥 核心功能：基于Casbin的动态权限检查和数据过滤
		enhancedCtx, err := p.processDataPermissions(ctx, userID, tenantID, r.URL.Path, r.Method)
		if err != nil {
			logger.WithError(err).WithField("user_id", userID).Error("data permission check failed")

			// 检查是否为权限拒绝错误（通过错误消息判断）
			if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "access denied") {
				// 权限被拒绝，返回HTTP 403
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Access denied: %s", err.Error())))
				return
			}

			// 其他错误，使用默认权限
			enhancedCtx = p.contextManager.SetDefaultPermissions(ctx, userID, tenantID)
		}

		// 更新统计信息
		p.updateStats(time.Since(startTime))

		logger.WithField("user_id", userID).
			WithField("tenant_id", tenantID).
			WithField("path", r.URL.Path).
			WithField("method", r.Method).
			WithDuration(startTime).
			Info("unified data permission applied successfully")

		next(w, r.WithContext(enhancedCtx))
	}
}

func attachAuditMetadata(ctx context.Context, tags map[string]string) context.Context {
	if len(tags) == 0 {
		return ctx
	}
	merged := make(map[string]string, len(tags))
	if existing, ok := ctx.Value(keys.AuditMetadataKey).(map[string]string); ok {
		for k, v := range existing {
			merged[k] = v
		}
	}
	for k, v := range tags {
		if v == "" {
			continue
		}
		merged[k] = v
	}
	return context.WithValue(ctx, keys.AuditMetadataKey, merged)
}

// processDataPermissions 处理数据权限的核心逻辑
func (p *UnifiedDataPermPlugin) processDataPermissions(ctx context.Context, userID, tenantID, path, method string) (context.Context, error) {
	// 1. 解析资源和操作类型
	resource, action := p.parseResourceAndAction(path, method)

	// 2. 使用Casbin进行权限检查
	permResult, err := p.casbinProvider.CheckPermissionWithRoles(ctx, userID, resource, action, p.getServiceName(path))
	if err != nil {
		return nil, fmt.Errorf("casbin permission check failed: %w", err)
	}

	// 3. 如果权限被拒绝，返回错误而不是继续执行
	if !permResult.Allowed {
		p.logger.WithField("user_id", userID).
			WithField("resource", resource).
			WithField("action", action).
			WithField("reason", permResult.Reason).
			Warn("permission denied by Casbin")

		// 返回权限拒绝错误，不应该继续执行请求
		return nil, errors.NewDataPermError(errors.CodeDataPermDenied, resource, action)
	}

	// 4. 基于Casbin规则生成数据过滤条件
	dataRules, err := p.ruleEngine.GenerateDataRules(ctx, userID, resource, action, permResult.AppliedRules)
	if err != nil {
		p.logger.WithError(err).Warn("failed to generate data rules, using default permissions")
		return p.contextManager.SetDefaultPermissions(ctx, userID, tenantID), nil
	}

	// 5. 注入增强的权限上下文
	enhancedCtx := p.contextManager.SetEnhancedPermissions(ctx, userID, tenantID, dataRules)

	return enhancedCtx, nil
}

// parseResourceAndAction 解析HTTP请求中的资源和操作类型
func (p *UnifiedDataPermPlugin) parseResourceAndAction(path, method string) (string, string) {
	// 移除查询参数
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}

	// 解析路径段
	pathParts := strings.Split(strings.Trim(path, "/"), "/")

	var resource string
	if len(pathParts) >= 1 {
		resource = pathParts[0]
		// 如果有第二个路径段，可能是具体的资源类型
		if len(pathParts) >= 2 && pathParts[1] != "" {
			resource = pathParts[0] + ":" + pathParts[1]
		}
	} else {
		resource = "unknown"
	}

	// 基于HTTP方法确定操作类型
	var action string
	switch strings.ToUpper(method) {
	case "GET":
		if strings.Contains(path, "/list") || strings.HasSuffix(path, "s") {
			action = "list"
		} else {
			action = "read"
		}
	case "POST":
		if strings.Contains(path, "/list") || strings.Contains(path, "search") {
			action = "list"
		} else {
			action = "create"
		}
	case "PUT", "PATCH":
		action = "update"
	case "DELETE":
		action = "delete"
	default:
		action = "access"
	}

	return resource, action
}

// getServiceName 从路径中提取服务名称
func (p *UnifiedDataPermPlugin) getServiceName(path string) string {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathParts) > 0 {
		// 通常第一个路径段是服务名称
		serviceName := pathParts[0]

		// 映射常见的服务名称
		serviceMap := map[string]string{
			"api":      "core",
			"v1":       "core",
			"user":     "core",
			"role":     "core",
			"menu":     "core",
			"cmdb":     "cmdb",
			"workflow": "workflow",
			"ops":      "ops",
		}

		if mappedName, exists := serviceMap[serviceName]; exists {
			return mappedName
		}

		return serviceName
	}

	return "unknown"
}

// shouldSkip 检查路径是否应跳过数据权限检查
func (p *UnifiedDataPermPlugin) shouldSkip(path string) bool {
	if p.config == nil || len(p.config.SkipPaths) == 0 {
		return false
	}

	for _, skipPath := range p.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

// updateStats 更新统计信息
func (p *UnifiedDataPermPlugin) updateStats(duration time.Duration) {
	if p == nil {
		return
	}
	atomic.AddInt64(&p.checkCount, 1)
	durationMicros := duration.Microseconds()
	if durationMicros < 0 {
		durationMicros = 0
	}
	// 平滑移动平均（单位毫秒，放大 1000 倍存储）
	const smoothing = 9
	for {
		old := p.avgResponseTimeMs.Load()
		currentMs := durationMicros / 1000
		if currentMs == 0 && durationMicros > 0 {
			currentMs = 1
		}
		var updated uint64
		if old == 0 {
			updated = uint64(currentMs)
		} else {
			updated = uint64((int64(old)*smoothing + int64(currentMs)) / (smoothing + 1))
		}
		if p.avgResponseTimeMs.CompareAndSwap(old, updated) {
			break
		}
	}
}

// GetStats 获取插件统计信息
func (p *UnifiedDataPermPlugin) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	checkCount := atomic.LoadInt64(&p.checkCount)
	cacheHits := atomic.LoadInt64(&p.cacheHitCount)
	avgMs := p.avgResponseTimeMs.Load()

	stats["check_count"] = checkCount
	stats["cache_hit_count"] = cacheHits
	stats["avg_response_time_ms"] = avgMs

	if checkCount > 0 {
		stats["cache_hit_rate"] = float64(cacheHits) / float64(checkCount)
	} else {
		stats["cache_hit_rate"] = 0.0
	}

	stats["rule_cache_size"] = len(p.ruleCache)

	return stats
}
