// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/logging"
)

// DefaultCasbinProvider 默认的Casbin提供者实现
// 这个实现将与现有的core RPC服务中的Casbin逻辑集成
type DefaultCasbinProvider struct {
	coreRPCClient CoreRPCClient // RPC客户端接口
	logger        *logging.MiddlewareLogger
	
	// 缓存配置
	enableCache   bool
	cacheExpiry   time.Duration
	
	// 性能统计
	checkCount    int64
	cacheHitCount int64
}

// CoreRPCClient 定义与core RPC服务通信的接口
type CoreRPCClient interface {
	// CheckPermissionWithRoles 检查权限（包含角色支持）
	CheckPermissionWithRoles(ctx context.Context, req *PermissionCheckRequest) (*PermissionResult, error)
	
	// GetUserRolesWithCache 获取用户角色（带缓存）
	GetUserRolesWithCache(ctx context.Context, req *UserRolesRequest) (*UserRolesResponse, error)
}

// RPC请求/响应结构体
type PermissionCheckRequest struct {
	Subject     string `json:"subject"`
	Object      string `json:"object"`
	Action      string `json:"action"`
	ServiceName string `json:"service_name"`
}

type UserRolesRequest struct {
	UserID string `json:"user_id"`
}

type UserRolesResponse struct {
	Roles []string `json:"roles"`
}

// NewDefaultCasbinProvider 创建默认的Casbin提供者
func NewDefaultCasbinProvider(coreRPCClient CoreRPCClient, logger *logging.MiddlewareLogger) *DefaultCasbinProvider {
	return &DefaultCasbinProvider{
		coreRPCClient: coreRPCClient,
		logger:        logger,
		enableCache:   true,
		cacheExpiry:   10 * time.Minute,
		checkCount:    0,
		cacheHitCount: 0,
	}
}

// CheckPermissionWithRoles 实现CasbinProvider接口 - 检查权限（包含角色支持）
func (p *DefaultCasbinProvider) CheckPermissionWithRoles(ctx context.Context, subject, object, action, serviceName string) (*PermissionResult, error) {
	startTime := time.Now()
	p.checkCount++
	
	// 构建请求
	req := &PermissionCheckRequest{
		Subject:     subject,
		Object:      object,
		Action:      action,
		ServiceName: serviceName,
	}
	
	// 调用core RPC服务
	result, err := p.coreRPCClient.CheckPermissionWithRoles(ctx, req)
	if err != nil {
		p.logger.WithContext(ctx).
			WithError(err).
			WithFields(map[string]interface{}{
				"subject":      subject,
				"object":       object,
				"action":       action,
				"service_name": serviceName,
			}).
			Error("failed to check permission via core RPC")
		return nil, fmt.Errorf("permission check failed: %w", err)
	}
	
	// 记录性能指标
	duration := time.Since(startTime)
	p.logger.WithContext(ctx).
		WithFields(map[string]interface{}{
			"subject":      subject,
			"object":       object,
			"action":       action,
			"service_name": serviceName,
			"allowed":      result.Allowed,
			"duration_ms":  duration.Milliseconds(),
			"from_cache":   result.FromCache,
		}).
		Debug("permission check completed")
	
	if result.FromCache {
		p.cacheHitCount++
	}
	
	return result, nil
}

// GetUserRolesWithCache 实现CasbinProvider接口 - 获取用户角色（带缓存）
func (p *DefaultCasbinProvider) GetUserRolesWithCache(ctx context.Context, user string) ([]string, error) {
	req := &UserRolesRequest{
		UserID: user,
	}
	
	resp, err := p.coreRPCClient.GetUserRolesWithCache(ctx, req)
	if err != nil {
		p.logger.WithContext(ctx).
			WithError(err).
			WithField("user_id", user).
			Error("failed to get user roles via core RPC")
		return nil, fmt.Errorf("get user roles failed: %w", err)
	}
	
	p.logger.WithContext(ctx).
		WithField("user_id", user).
		WithField("roles", resp.Roles).
		Debug("user roles retrieved")
	
	return resp.Roles, nil
}

// GetStats 获取统计信息
func (p *DefaultCasbinProvider) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"check_count":     p.checkCount,
		"cache_hit_count": p.cacheHitCount,
		"enable_cache":    p.enableCache,
		"cache_expiry":    p.cacheExpiry.String(),
	}
	
	if p.checkCount > 0 {
		stats["cache_hit_rate"] = float64(p.cacheHitCount) / float64(p.checkCount)
	} else {
		stats["cache_hit_rate"] = 0.0
	}
	
	return stats
}

// MockCasbinProvider Mock实现，用于测试和开发环境
type MockCasbinProvider struct {
	logger          *logging.MiddlewareLogger
	mockPermissions map[string]bool // key: "subject:object:action", value: allowed
	mockRoles       map[string][]string // key: userID, value: roles
}

// NewMockCasbinProvider 创建Mock Casbin提供者
func NewMockCasbinProvider(logger *logging.MiddlewareLogger) *MockCasbinProvider {
	provider := &MockCasbinProvider{
		logger:          logger,
		mockPermissions: make(map[string]bool),
		mockRoles:       make(map[string][]string),
	}
	
	// 初始化一些默认的Mock数据
	provider.initMockData()
	
	return provider
}

// initMockData 初始化Mock数据
func (p *MockCasbinProvider) initMockData() {
	// Mock权限数据
	permissions := map[string]bool{
		"admin:*:*":                    true,
		"manager:user:read":            true,
		"manager:user:list":            true,
		"manager:department:*":         true,
		"user:profile:read":            true,
		"user:profile:update":          true,
		"readonly:*:read":              true,
		"readonly:*:list":              true,
	}
	
	for key, allowed := range permissions {
		p.mockPermissions[key] = allowed
	}
	
	// Mock角色数据
	p.mockRoles["1"] = []string{"admin", "manager"}
	p.mockRoles["2"] = []string{"manager"}
	p.mockRoles["3"] = []string{"user"}
	p.mockRoles["4"] = []string{"readonly"}
}

// CheckPermissionWithRoles Mock实现 - 检查权限
func (p *MockCasbinProvider) CheckPermissionWithRoles(ctx context.Context, subject, object, action, serviceName string) (*PermissionResult, error) {
	// 构建权限键
	keys := []string{
		fmt.Sprintf("%s:%s:%s", subject, object, action),
		fmt.Sprintf("%s:*:%s", subject, action),
		fmt.Sprintf("%s:%s:*", subject, object),
		fmt.Sprintf("%s:*:*", subject),
	}
	
	// 检查直接权限
	for _, key := range keys {
		if allowed, exists := p.mockPermissions[key]; exists {
			result := &PermissionResult{
				Allowed:      allowed,
				Reason:       fmt.Sprintf("Direct permission match: %s", key),
				AppliedRules: []string{key},
				FromCache:    false,
			}
			
			p.logger.WithContext(ctx).
				WithFields(map[string]interface{}{
					"subject": subject,
					"object":  object,
					"action":  action,
					"allowed": allowed,
					"rule":    key,
				}).
				Debug("mock permission check result")
			
			return result, nil
		}
	}
	
	// 检查角色权限
	if roles, exists := p.mockRoles[subject]; exists {
		for _, role := range roles {
			roleKeys := []string{
				fmt.Sprintf("%s:%s:%s", role, object, action),
				fmt.Sprintf("%s:*:%s", role, action),
				fmt.Sprintf("%s:%s:*", role, object),
				fmt.Sprintf("%s:*:*", role),
			}
			
			for _, key := range roleKeys {
				if allowed, exists := p.mockPermissions[key]; exists && allowed {
					result := &PermissionResult{
						Allowed:      true,
						Reason:       fmt.Sprintf("Role permission match: %s (role: %s)", key, role),
						AppliedRules: []string{key},
						FromCache:    false,
					}
					
					p.logger.WithContext(ctx).
						WithFields(map[string]interface{}{
							"subject": subject,
							"object":  object,
							"action":  action,
							"role":    role,
							"rule":    key,
						}).
						Debug("mock role permission check result")
					
					return result, nil
				}
			}
		}
	}
	
	// 默认拒绝
	result := &PermissionResult{
		Allowed:      false,
		Reason:       "No matching permission found",
		AppliedRules: []string{},
		FromCache:    false,
	}
	
	p.logger.WithContext(ctx).
		WithFields(map[string]interface{}{
			"subject": subject,
			"object":  object,
			"action":  action,
		}).
		Debug("mock permission denied")
	
	return result, nil
}

// GetUserRolesWithCache Mock实现 - 获取用户角色
func (p *MockCasbinProvider) GetUserRolesWithCache(ctx context.Context, user string) ([]string, error) {
	if roles, exists := p.mockRoles[user]; exists {
		p.logger.WithContext(ctx).
			WithField("user_id", user).
			WithField("roles", roles).
			Debug("mock user roles retrieved")
		return roles, nil
	}
	
	// 默认返回空角色列表
	p.logger.WithContext(ctx).
		WithField("user_id", user).
		Debug("no mock roles found for user")
	
	return []string{}, nil
}

// AddMockPermission 添加Mock权限
func (p *MockCasbinProvider) AddMockPermission(subject, object, action string, allowed bool) {
	key := fmt.Sprintf("%s:%s:%s", subject, object, action)
	p.mockPermissions[key] = allowed
	
	p.logger.WithFields(map[string]interface{}{
		"key":     key,
		"allowed": allowed,
	}).Debug("mock permission added")
}

// AddMockRole 添加Mock角色
func (p *MockCasbinProvider) AddMockRole(userID string, roles []string) {
	p.mockRoles[userID] = roles
	
	p.logger.WithFields(map[string]interface{}{
		"user_id": userID,
		"roles":   roles,
	}).Debug("mock roles added")
}

// CasbinProviderFactory Casbin提供者工厂
type CasbinProviderFactory struct {
	logger *logging.MiddlewareLogger
}

// NewCasbinProviderFactory 创建Casbin提供者工厂
func NewCasbinProviderFactory(logger *logging.MiddlewareLogger) *CasbinProviderFactory {
	return &CasbinProviderFactory{
		logger: logger,
	}
}

// CreateProvider 创建Casbin提供者
func (f *CasbinProviderFactory) CreateProvider(providerType string, config interface{}) (CasbinProvider, error) {
	switch strings.ToLower(providerType) {
	case "rpc", "default":
		// 生产环境使用RPC提供者
		if rpcClient, ok := config.(CoreRPCClient); ok {
			return NewDefaultCasbinProvider(rpcClient, f.logger), nil
		}
		return nil, fmt.Errorf("invalid config for RPC provider, expected CoreRPCClient")
		
	case "mock", "test":
		// 测试环境使用Mock提供者
		return NewMockCasbinProvider(f.logger), nil
		
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}