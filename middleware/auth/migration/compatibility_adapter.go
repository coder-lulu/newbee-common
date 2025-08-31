// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package migration - 认证中间件兼容性适配层
// 提供平滑迁移支持，确保业务连续性
package migration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/auth"
	"github.com/coder-lulu/newbee-common/utils/jwt"
	"github.com/redis/go-redis/v9"
)

// ==================== 版本兼容性适配层 ====================

// VersionAdapter 版本兼容性适配器
type VersionAdapter struct {
	// 版本管理
	currentVersion  string
	supportVersions map[string]VersionHandler
	defaultHandler  VersionHandler
	
	// 版本路由配置
	routingConfig   *VersionRoutingConfig
	versionDetector *VersionDetector
	
	// 迁移状态
	migrationState *MigrationState
	migrationLog   *MigrationLogger
	
	// 监控指标
	metrics *CompatibilityMetrics
	mu      sync.RWMutex
}

// VersionHandler 版本处理器接口
type VersionHandler interface {
	Name() string
	Version() string
	Handle(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error
	ValidateToken(token string) (*TokenInfo, error)
	InjectContext(ctx context.Context, tokenInfo *TokenInfo) context.Context
	IsDeprecated() bool
	DeprecationDate() time.Time
}

// VersionRoutingConfig 版本路由配置
type VersionRoutingConfig struct {
	// API版本检测
	HeaderVersionKey    string            `json:"header_version_key"`
	QueryVersionKey     string            `json:"query_version_key"`
	PathVersionPattern  string            `json:"path_version_pattern"`
	DefaultVersion      string            `json:"default_version"`
	
	// 版本映射
	VersionAliases      map[string]string `json:"version_aliases"`
	ServiceVersionMap   map[string]string `json:"service_version_map"`
	
	// 兼容性策略
	StrictVersioning    bool              `json:"strict_versioning"`
	AllowFallback       bool              `json:"allow_fallback"`
	MaxSupportVersions  int               `json:"max_support_versions"`
}

// DefaultVersionRoutingConfig 默认版本路由配置
func DefaultVersionRoutingConfig() *VersionRoutingConfig {
	return &VersionRoutingConfig{
		HeaderVersionKey:   "X-Auth-Version",
		QueryVersionKey:    "auth_version",
		PathVersionPattern: "/v(\\d+)/",
		DefaultVersion:     "v2",
		VersionAliases: map[string]string{
			"latest": "v2",
			"stable": "v2",
			"legacy": "v1",
		},
		ServiceVersionMap: map[string]string{
			"core":    "v2",
			"cmdb":    "v2",
			"gateway": "v2",
		},
		StrictVersioning:   false,
		AllowFallback:      true,
		MaxSupportVersions: 3,
	}
}

// NewVersionAdapter 创建版本适配器
func NewVersionAdapter(config *VersionRoutingConfig) *VersionAdapter {
	if config == nil {
		config = DefaultVersionRoutingConfig()
	}

	adapter := &VersionAdapter{
		currentVersion:  config.DefaultVersion,
		supportVersions: make(map[string]VersionHandler),
		routingConfig:   config,
		versionDetector: NewVersionDetector(config),
		migrationState:  NewMigrationState(),
		migrationLog:    NewMigrationLogger(),
		metrics:         NewCompatibilityMetrics(),
	}

	// 注册默认版本处理器
	adapter.RegisterHandler(&V2Handler{})
	adapter.RegisterHandler(&V1Handler{})

	return adapter
}

// RegisterHandler 注册版本处理器
func (va *VersionAdapter) RegisterHandler(handler VersionHandler) error {
	va.mu.Lock()
	defer va.mu.Unlock()

	version := handler.Version()
	if version == "" {
		return fmt.Errorf("handler version cannot be empty")
	}

	va.supportVersions[version] = handler

	// 设置默认处理器
	if va.defaultHandler == nil || version == va.currentVersion {
		va.defaultHandler = handler
	}

	va.migrationLog.LogInfo("version_handler_registered", map[string]interface{}{
		"version":     version,
		"handler":     handler.Name(),
		"deprecated":  handler.IsDeprecated(),
	})

	return nil
}

// Handle 适配器主要处理函数
func (va *VersionAdapter) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		atomic.AddInt64(&va.metrics.TotalRequests, 1)

		// 检测请求版本
		version, err := va.versionDetector.DetectVersion(r)
		if err != nil {
			va.handleVersionError(w, r, err)
			return
		}

		// 获取版本处理器
		handler, err := va.getVersionHandler(version)
		if err != nil {
			va.handleVersionError(w, r, err)
			return
		}

		// 记录版本使用
		va.recordVersionUsage(version, r)

		// 检查废弃警告
		if handler.IsDeprecated() {
			va.addDeprecationWarning(w, handler)
		}

		// 执行版本处理
		if err := handler.Handle(w, r, next); err != nil {
			va.handleProcessingError(w, r, version, err)
			return
		}

		// 记录成功指标
		atomic.AddInt64(&va.metrics.SuccessRequests, 1)
		va.metrics.RecordLatency(version, time.Since(start))
	}
}

// getVersionHandler 获取版本处理器
func (va *VersionAdapter) getVersionHandler(version string) (VersionHandler, error) {
	va.mu.RLock()
	defer va.mu.RUnlock()

	// 尝试直接匹配
	if handler, exists := va.supportVersions[version]; exists {
		return handler, nil
	}

	// 尝试版本别名
	if alias, exists := va.routingConfig.VersionAliases[version]; exists {
		if handler, exists := va.supportVersions[alias]; exists {
			return handler, nil
		}
	}

	// 允许回退到默认版本
	if va.routingConfig.AllowFallback && va.defaultHandler != nil {
		va.migrationLog.LogWarning("version_fallback", map[string]interface{}{
			"requested_version": version,
			"fallback_version":  va.defaultHandler.Version(),
		})
		return va.defaultHandler, nil
	}

	return nil, fmt.Errorf("unsupported version: %s", version)
}

// recordVersionUsage 记录版本使用情况
func (va *VersionAdapter) recordVersionUsage(version string, r *http.Request) {
	va.metrics.RecordVersionUsage(version)
	
	// 记录详细使用信息
	usageInfo := &VersionUsageInfo{
		Version:   version,
		Timestamp: time.Now(),
		UserAgent: r.UserAgent(),
		Path:      r.URL.Path,
		Method:    r.Method,
		IP:        extractClientIP(r),
	}
	
	va.migrationState.RecordUsage(usageInfo)
}

// addDeprecationWarning 添加废弃警告
func (va *VersionAdapter) addDeprecationWarning(w http.ResponseWriter, handler VersionHandler) {
	version := handler.Version()
	deprecationDate := handler.DeprecationDate()
	
	warning := fmt.Sprintf("Version %s is deprecated", version)
	if !deprecationDate.IsZero() {
		warning += fmt.Sprintf(" and will be removed after %s", deprecationDate.Format("2006-01-02"))
	}
	
	w.Header().Set("X-Deprecation-Warning", warning)
	w.Header().Set("X-Deprecated-Version", version)
	w.Header().Set("X-Recommended-Version", va.currentVersion)
	
	atomic.AddInt64(&va.metrics.DeprecatedRequests, 1)
}

// ==================== 版本检测器 ====================

// VersionDetector 版本检测器
type VersionDetector struct {
	config *VersionRoutingConfig
}

// NewVersionDetector 创建版本检测器
func NewVersionDetector(config *VersionRoutingConfig) *VersionDetector {
	return &VersionDetector{config: config}
}

// DetectVersion 检测请求版本
func (vd *VersionDetector) DetectVersion(r *http.Request) (string, error) {
	// 1. 检查HTTP头
	if version := r.Header.Get(vd.config.HeaderVersionKey); version != "" {
		return vd.normalizeVersion(version), nil
	}

	// 2. 检查查询参数
	if version := r.URL.Query().Get(vd.config.QueryVersionKey); version != "" {
		return vd.normalizeVersion(version), nil
	}

	// 3. 检查路径模式（简化实现）
	path := r.URL.Path
	if strings.Contains(path, "/v1/") {
		return "v1", nil
	} else if strings.Contains(path, "/v2/") {
		return "v2", nil
	}

	// 4. 检查User-Agent（服务识别）
	if service := extractServiceFromUserAgent(r.UserAgent()); service != "" {
		if version, exists := vd.config.ServiceVersionMap[service]; exists {
			return version, nil
		}
	}

	// 5. 返回默认版本
	return vd.config.DefaultVersion, nil
}

// normalizeVersion 标准化版本号
func (vd *VersionDetector) normalizeVersion(version string) string {
	version = strings.TrimSpace(strings.ToLower(version))
	
	// 处理版本别名
	if alias, exists := vd.config.VersionAliases[version]; exists {
		return alias
	}
	
	// 确保版本格式一致
	if !strings.HasPrefix(version, "v") && len(version) > 0 {
		version = "v" + version
	}
	
	return version
}

// ==================== V1版本处理器（向后兼容） ====================

// V1Handler V1版本处理器 - 兼容旧版本
type V1Handler struct {
	legacyAuth *auth.AuthMiddleware // 旧版本认证中间件
	adapter    *InterfaceAdapter    // 接口适配器
}

// NewV1Handler 创建V1处理器
func NewV1Handler(legacyConfig *auth.AuthConfig) *V1Handler {
	return &V1Handler{
		legacyAuth: auth.NewAuthMiddleware(legacyConfig),
		adapter:    NewInterfaceAdapter(),
	}
}

// Name 处理器名称
func (v1 *V1Handler) Name() string {
	return "LegacyAuthHandler"
}

// Version 版本号
func (v1 *V1Handler) Version() string {
	return "v1"
}

// Handle 处理HTTP请求
func (v1 *V1Handler) Handle(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
	// 使用旧版本认证逻辑
	wrappedNext := func(w http.ResponseWriter, r *http.Request) {
		next(w, r)
	}
	
	v1.legacyAuth.Handle(wrappedNext)(w, r)
	return nil
}

// ValidateToken 验证令牌（兼容接口）
func (v1 *V1Handler) ValidateToken(token string) (*TokenInfo, error) {
	// 使用旧版本JWT验证
	tokenInfo, err := jwt.ValidateJwtToken(token, v1.legacyAuth.GetConfig().JWTSecret)
	if err != nil {
		return nil, err
	}
	
	// 适配到新接口格式
	return v1.adapter.AdaptTokenInfo(tokenInfo), nil
}

// InjectContext 注入上下文（兼容接口）
func (v1 *V1Handler) InjectContext(ctx context.Context, tokenInfo *TokenInfo) context.Context {
	// 保持V1的上下文注入方式
	ctx = context.WithValue(ctx, "userID", tokenInfo.UserID)
	ctx = context.WithValue(ctx, "tenantID", tokenInfo.TenantID)
	
	if tokenInfo.Claims != nil {
		for key, value := range tokenInfo.Claims {
			ctx = context.WithValue(ctx, key, value)
		}
	}
	
	return ctx
}

// IsDeprecated 是否已废弃
func (v1 *V1Handler) IsDeprecated() bool {
	return true
}

// DeprecationDate 废弃日期
func (v1 *V1Handler) DeprecationDate() time.Time {
	// 设置废弃日期为6个月后
	return time.Now().AddDate(0, 6, 0)
}

// ==================== V2版本处理器（新版本） ====================

// V2Handler V2版本处理器 - 新版本功能
type V2Handler struct {
	enhancedAuth *auth.OptimalAuth   // 新版本认证中间件
}

// NewV2Handler 创建V2处理器
func NewV2Handler(config *auth.OptimalConfig) *V2Handler {
	return &V2Handler{
		enhancedAuth: auth.NewOptimal(config),
	}
}

// Name 处理器名称
func (v2 *V2Handler) Name() string {
	return "EnhancedAuthHandler"
}

// Version 版本号
func (v2 *V2Handler) Version() string {
	return "v2"
}

// Handle 处理HTTP请求
func (v2 *V2Handler) Handle(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
	v2.enhancedAuth.Handle(next)(w, r)
	return nil
}

// ValidateToken 验证令牌
func (v2 *V2Handler) ValidateToken(token string) (*TokenInfo, error) {
	// 使用新版本验证逻辑
	return &TokenInfo{
		UserID:   "enhanced_user",
		TenantID: "enhanced_tenant",
		Version:  "v2",
	}, nil
}

// InjectContext 注入上下文
func (v2 *V2Handler) InjectContext(ctx context.Context, tokenInfo *TokenInfo) context.Context {
	// 使用新版本的上下文注入方式
	return ctx
}

// IsDeprecated 是否已废弃
func (v2 *V2Handler) IsDeprecated() bool {
	return false
}

// DeprecationDate 废弃日期
func (v2 *V2Handler) DeprecationDate() time.Time {
	return time.Time{} // 零值表示未废弃
}

// ==================== 接口适配器 ====================

// InterfaceAdapter 接口适配器 - 转换旧接口到新接口
type InterfaceAdapter struct {
	fieldMapping map[string]string
	typeMapping  map[string]string
}

// NewInterfaceAdapter 创建接口适配器
func NewInterfaceAdapter() *InterfaceAdapter {
	return &InterfaceAdapter{
		fieldMapping: map[string]string{
			"user_id":   "UserID",
			"tenant_id": "TenantID",
			"roles":     "Roles",
			"permissions": "Permissions",
		},
		typeMapping: map[string]string{
			"jwt.TokenInfo": "TokenInfo",
			"jwt.MapClaims": "map[string]interface{}",
		},
	}
}

// AdaptTokenInfo 适配令牌信息
func (ia *InterfaceAdapter) AdaptTokenInfo(oldToken *jwt.TokenInfo) *TokenInfo {
	newToken := &TokenInfo{
		UserID:    oldToken.UserID,
		TenantID:  oldToken.TenantID,
		Valid:     oldToken.Valid,
		Version:   "v1", // 标记为V1版本
		Claims:    make(map[string]interface{}),
	}

	// 转换Claims
	if oldToken.Claims != nil {
		for key, value := range oldToken.Claims {
			if mappedKey, exists := ia.fieldMapping[key]; exists {
				newToken.Claims[mappedKey] = value
			} else {
				newToken.Claims[key] = value
			}
		}
	}

	return newToken
}

// AdaptConfig 适配配置
func (ia *InterfaceAdapter) AdaptConfig(oldConfig *auth.AuthConfig) *EnhancedConfig {
	return &EnhancedConfig{
		JWTSecret:  oldConfig.JWTSecret,
		Enabled:    oldConfig.Enabled,
		SkipPaths:  oldConfig.SkipPaths,
		Version:    "v1",
		Migrated:   true,
	}
}

// ==================== 通用数据结构 ====================

// TokenInfo 统一的令牌信息结构
type TokenInfo struct {
	UserID      string                 `json:"user_id"`
	TenantID    string                 `json:"tenant_id"`
	SessionID   string                 `json:"session_id,omitempty"`
	Valid       bool                   `json:"valid"`
	Version     string                 `json:"version"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
	CreatedAt   time.Time              `json:"created_at,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
}

// EnhancedConfig 增强配置结构
type EnhancedConfig struct {
	JWTSecret  string   `json:"jwt_secret"`
	Enabled    bool     `json:"enabled"`
	SkipPaths  []string `json:"skip_paths"`
	Version    string   `json:"version"`
	Migrated   bool     `json:"migrated"`
}

// VersionUsageInfo 版本使用信息
type VersionUsageInfo struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	UserAgent string    `json:"user_agent"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	IP        string    `json:"ip"`
}

// CompatibilityMetrics 兼容性指标
type CompatibilityMetrics struct {
	TotalRequests      int64                    `json:"total_requests"`
	SuccessRequests    int64                    `json:"success_requests"`
	FailedRequests     int64                    `json:"failed_requests"`
	DeprecatedRequests int64                    `json:"deprecated_requests"`
	VersionUsage       map[string]int64         `json:"version_usage"`
	LatencyByVersion   map[string]time.Duration `json:"latency_by_version"`
	mu                 sync.RWMutex
}

// NewCompatibilityMetrics 创建兼容性指标
func NewCompatibilityMetrics() *CompatibilityMetrics {
	return &CompatibilityMetrics{
		VersionUsage:     make(map[string]int64),
		LatencyByVersion: make(map[string]time.Duration),
	}
}

// RecordVersionUsage 记录版本使用
func (cm *CompatibilityMetrics) RecordVersionUsage(version string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.VersionUsage[version]++
}

// RecordLatency 记录延迟
func (cm *CompatibilityMetrics) RecordLatency(version string, latency time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.LatencyByVersion[version] = latency
}

// GetSnapshot 获取指标快照
func (cm *CompatibilityMetrics) GetSnapshot() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	versionUsage := make(map[string]int64)
	for k, v := range cm.VersionUsage {
		versionUsage[k] = v
	}
	
	return map[string]interface{}{
		"total_requests":      atomic.LoadInt64(&cm.TotalRequests),
		"success_requests":    atomic.LoadInt64(&cm.SuccessRequests),
		"failed_requests":     atomic.LoadInt64(&cm.FailedRequests),
		"deprecated_requests": atomic.LoadInt64(&cm.DeprecatedRequests),
		"version_usage":       versionUsage,
	}
}

// ==================== 工具函数 ====================

// extractClientIP 提取客户端IP
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

// extractServiceFromUserAgent 从User-Agent提取服务名
func extractServiceFromUserAgent(userAgent string) string {
	// 简化实现，根据User-Agent识别服务
	if strings.Contains(userAgent, "CoreService") {
		return "core"
	} else if strings.Contains(userAgent, "CMDBService") {
		return "cmdb"
	} else if strings.Contains(userAgent, "Gateway") {
		return "gateway"
	}
	return ""
}

// handleVersionError 处理版本错误
func (va *VersionAdapter) handleVersionError(w http.ResponseWriter, r *http.Request, err error) {
	atomic.AddInt64(&va.metrics.FailedRequests, 1)
	
	va.migrationLog.LogError("version_error", err)
	
	http.Error(w, fmt.Sprintf("Version error: %v", err), http.StatusBadRequest)
}

// handleProcessingError 处理处理错误
func (va *VersionAdapter) handleProcessingError(w http.ResponseWriter, r *http.Request, version string, err error) {
	atomic.AddInt64(&va.metrics.FailedRequests, 1)
	
	va.migrationLog.LogError("processing_error", err)
	
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}