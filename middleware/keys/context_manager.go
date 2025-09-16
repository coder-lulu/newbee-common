// Copyright 2024 The NewBee Authors. All Rights Reserved.

package keys

import (
	"context"
	"fmt"
)

// ContextManager provides a simplified and consistent API for reading and writing
// canonical values to the request context.
type ContextManager struct{}

// NewContextManager creates a new, clean context manager.
func NewContextManager() *ContextManager {
	return &ContextManager{}
}

// Setters

// SetTenantID sets the canonical tenant ID in the context.
func (cm *ContextManager) SetTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// SetUserID sets the canonical user ID in the context.
func (cm *ContextManager) SetUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// SetDataScope sets the canonical data permission scope in the context.
func (cm *ContextManager) SetDataScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, DataScopeKey, scope)
}

// SetDeptID sets the canonical department ID in the context.
func (cm *ContextManager) SetDeptID(ctx context.Context, deptID string) context.Context {
	return context.WithValue(ctx, DeptIDKey, deptID)
}

// Getters

// GetTenantID retrieves the canonical tenant ID from the context.
func (cm *ContextManager) GetTenantID(ctx context.Context) string {
	if val, ok := ctx.Value(TenantIDKey).(string); ok {
		return val
	}
	return ""
}

// GetUserID retrieves the canonical user ID from the context.
func (cm *ContextManager) GetUserID(ctx context.Context) string {
	if val, ok := ctx.Value(UserIDKey).(string); ok {
		return val
	}
	return ""
}

// GetDataScope retrieves the canonical data permission scope from the context.
func (cm *ContextManager) GetDataScope(ctx context.Context) string {
	if val, ok := ctx.Value(DataScopeKey).(string); ok {
		return val
	}
	return ""
}

// GetDeptID retrieves the canonical department ID from the context.
func (cm *ContextManager) GetDeptID(ctx context.Context) string {
	if val, ok := ctx.Value(DeptIDKey).(string); ok {
		return val
	}
	return ""
}

// SetFullAuthContext is a convenience function to set all standard auth values.
// 支持新旧两种JWT token格式以确保向后兼容
func (cm *ContextManager) SetFullAuthContext(ctx context.Context, claims map[string]interface{}) (context.Context, error) {
	// 提取和转换claims - 优先使用新的短字段名，回退到旧字段名
	var tenantID, userID, username, roleCodes, nickname, avatar string
	var deptID string

	// 1. 提取TenantID - 支持新旧字段名和多种类型
	if val, ok := claims[JWTTenantID]; ok { // 新字段名 "tid"
		tenantID = cm.extractStringValue(val)
	} else if val, ok := claims["tenantId"]; ok { // 旧字段名 "tenantId"
		tenantID = cm.extractStringValue(val)
	}

	// 2. 提取UserID - 支持新旧字段名
	if val, ok := claims[JWTUserID].(string); ok { // 新字段名 "uid"
		userID = val
	} else if val, ok := claims["userId"].(string); ok { // 旧字段名 "userId"
		userID = val
	}

	// 验证必需的字段
	if userID == "" || tenantID == "" {
		return nil, fmt.Errorf("missing essential claims: userId or tenantId")
	}

	// 3. 提取Username - 支持新旧字段名
	if val, ok := claims[JWTUsername].(string); ok { // 新字段名 "un"
		username = val
	} else if val, ok := claims["username"].(string); ok { // 旧字段名 "username"
		username = val
	}

	// 4. 提取DeptID - 支持新旧字段名和多种类型
	if val, ok := claims[JWTDeptID]; ok { // 新字段名 "did"
		deptID = cm.extractStringValue(val)
	} else if val, ok := claims["deptId"]; ok { // 旧字段名 "deptId"
		deptID = cm.extractStringValue(val)
	}

	// 5. 提取RoleCodes - 支持新旧字段名
	if val, ok := claims[JWTRoleCodes].(string); ok { // 新字段名 "rc"
		roleCodes = val
	} else if val, ok := claims["roleCodes"].(string); ok { // 旧字段名 "roleCodes"
		roleCodes = val
	}

	// 6. 提取可选的用户信息字段
	if val, ok := claims[JWTNickname].(string); ok { // 新字段名 "nn"
		nickname = val
	}
	if val, ok := claims[JWTAvatar].(string); ok { // 新字段名 "av"
		avatar = val
	}

	// 使用标准context key设置值
	ctx = context.WithValue(ctx, TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, UserIDKey, userID)
	ctx = context.WithValue(ctx, UsernameKey, username)
	ctx = context.WithValue(ctx, DeptIDKey, deptID)
	ctx = context.WithValue(ctx, RoleCodesKey, roleCodes)

	// 设置用户信息字段（如果存在）
	if nickname != "" {
		ctx = context.WithValue(ctx, NicknameKey, nickname)
	}
	if avatar != "" {
		ctx = context.WithValue(ctx, AvatarKey, avatar)
	}

	return ctx, nil
}

// extractStringValue 从interface{}中提取字符串值，支持多种类型
func (cm *ContextManager) extractStringValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case int:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	default:
		return ""
	}
}
