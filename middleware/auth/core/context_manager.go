// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package core

import (
	"context"
	"sync"
)

// ContextKey represents a type-safe context key to prevent collisions (Fix #4)
type ContextKey string

// Pre-defined context keys to prevent string collisions
const (
	UserIDKey        ContextKey = "auth_user_id"
	TenantIDKey      ContextKey = "auth_tenant_id"
	RoleKey          ContextKey = "auth_role"
	RolesKey         ContextKey = "auth_roles"
	PermissionsKey   ContextKey = "auth_permissions"
	SessionIDKey     ContextKey = "auth_session_id"
	ClaimsKey        ContextKey = "auth_claims"
	TokenIDKey       ContextKey = "auth_token_id"
)

// SafeContextManager implements thread-safe context management with type safety
type SafeContextManager struct {
	mu sync.RWMutex
}

// NewSafeContextManager creates a new context manager with security fixes
func NewSafeContextManager() *SafeContextManager {
	return &SafeContextManager{}
}

// InjectContext safely injects authentication claims into the request context (Fix #4: Type-safe keys)
func (scm *SafeContextManager) InjectContext(ctx context.Context, claims *Claims) context.Context {
	if claims == nil {
		return ctx
	}

	scm.mu.RLock()
	defer scm.mu.RUnlock()

	// Inject standard claims with type-safe keys
	ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
	ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
	ctx = context.WithValue(ctx, RoleKey, claims.Role)
	ctx = context.WithValue(ctx, SessionIDKey, claims.SessionID)

	// Inject arrays if present
	if len(claims.Roles) > 0 {
		ctx = context.WithValue(ctx, RolesKey, claims.Roles)
	}
	if len(claims.Permissions) > 0 {
		ctx = context.WithValue(ctx, PermissionsKey, claims.Permissions)
	}

	// Store the full claims object for advanced use cases
	ctx = context.WithValue(ctx, ClaimsKey, claims)

	return ctx
}

// ExtractUserID safely extracts user ID from context with type checking
func (scm *SafeContextManager) ExtractUserID(ctx context.Context) (string, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		return userID, true
	}
	return "", false
}

// ExtractTenantID safely extracts tenant ID from context with type checking
func (scm *SafeContextManager) ExtractTenantID(ctx context.Context) (string, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if tenantID, ok := ctx.Value(TenantIDKey).(string); ok && tenantID != "" {
		return tenantID, true
	}
	return "", false
}

// ExtractRole safely extracts user role from context
func (scm *SafeContextManager) ExtractRole(ctx context.Context) (string, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if role, ok := ctx.Value(RoleKey).(string); ok && role != "" {
		return role, true
	}
	return "", false
}

// ExtractRoles safely extracts user roles array from context
func (scm *SafeContextManager) ExtractRoles(ctx context.Context) ([]string, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if roles, ok := ctx.Value(RolesKey).([]string); ok && len(roles) > 0 {
		return roles, true
	}
	return nil, false
}

// ExtractPermissions safely extracts user permissions from context
func (scm *SafeContextManager) ExtractPermissions(ctx context.Context) ([]string, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if permissions, ok := ctx.Value(PermissionsKey).([]string); ok && len(permissions) > 0 {
		return permissions, true
	}
	return nil, false
}

// ExtractSessionID safely extracts session ID from context
func (scm *SafeContextManager) ExtractSessionID(ctx context.Context) (string, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if sessionID, ok := ctx.Value(SessionIDKey).(string); ok && sessionID != "" {
		return sessionID, true
	}
	return "", false
}

// ExtractClaims safely extracts the full claims object from context
func (scm *SafeContextManager) ExtractClaims(ctx context.Context) (*Claims, bool) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	if claims, ok := ctx.Value(ClaimsKey).(*Claims); ok && claims != nil {
		return claims, true
	}
	return nil, false
}

// HasPermission checks if the current user has a specific permission
func (scm *SafeContextManager) HasPermission(ctx context.Context, permission string) bool {
	permissions, ok := scm.ExtractPermissions(ctx)
	if !ok {
		return false
	}

	for _, perm := range permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// HasRole checks if the current user has a specific role
func (scm *SafeContextManager) HasRole(ctx context.Context, role string) bool {
	// Check primary role
	if currentRole, ok := scm.ExtractRole(ctx); ok && currentRole == role {
		return true
	}

	// Check roles array
	if roles, ok := scm.ExtractRoles(ctx); ok {
		for _, r := range roles {
			if r == role {
				return true
			}
		}
	}

	return false
}

// IsValidTenant checks if the request is from the expected tenant (Fix #5: Tenant isolation)
func (scm *SafeContextManager) IsValidTenant(ctx context.Context, expectedTenant string) bool {
	if expectedTenant == "" {
		return true // Skip validation if no tenant expected
	}

	actualTenant, ok := scm.ExtractTenantID(ctx)
	if !ok {
		return false // No tenant in context
	}

	return SecureCompare(actualTenant, expectedTenant)
}

// ValidateTenantAccess performs strict tenant access validation (Fix #5)
func (scm *SafeContextManager) ValidateTenantAccess(ctx context.Context, requestedTenant string) error {
	if requestedTenant == "" {
		return &AuthError{
			Code:    ErrCodeTenantViolation,
			Message: "Requested tenant cannot be empty",
		}
	}

	tokenTenant, ok := scm.ExtractTenantID(ctx)
	if !ok {
		return &AuthError{
			Code:    ErrCodeTenantViolation,
			Message: "No tenant information in token",
		}
	}

	// Strict tenant validation with secure comparison
	if !SecureCompare(tokenTenant, requestedTenant) {
		return &AuthError{
			Code:    ErrCodeTenantViolation,
			Message: "Tenant access violation detected",
		}
	}

	return nil
}

// CreateAuthenticatedContext creates a new authenticated context with claims
func (scm *SafeContextManager) CreateAuthenticatedContext(baseCtx context.Context, claims *Claims) context.Context {
	return scm.InjectContext(baseCtx, claims)
}

// IsAuthenticated checks if the context contains valid authentication information
func (scm *SafeContextManager) IsAuthenticated(ctx context.Context) bool {
	userID, hasUser := scm.ExtractUserID(ctx)
	return hasUser && userID != ""
}

// GetAuthenticationSummary returns a summary of the current authentication state
func (scm *SafeContextManager) GetAuthenticationSummary(ctx context.Context) map[string]interface{} {
	summary := make(map[string]interface{})

	if userID, ok := scm.ExtractUserID(ctx); ok {
		summary["user_id"] = userID
	}
	if tenantID, ok := scm.ExtractTenantID(ctx); ok {
		summary["tenant_id"] = tenantID
	}
	if role, ok := scm.ExtractRole(ctx); ok {
		summary["role"] = role
	}
	if roles, ok := scm.ExtractRoles(ctx); ok {
		summary["roles"] = roles
	}
	if sessionID, ok := scm.ExtractSessionID(ctx); ok {
		summary["session_id"] = sessionID
	}

	summary["authenticated"] = scm.IsAuthenticated(ctx)

	return summary
}

// CleanContext removes all authentication-related values from context (for testing)
func (scm *SafeContextManager) CleanContext(ctx context.Context) context.Context {
	// Note: You cannot actually remove values from context in Go
	// This is primarily for documentation and testing purposes
	// In practice, you would create a new context without the auth values
	return context.Background()
}