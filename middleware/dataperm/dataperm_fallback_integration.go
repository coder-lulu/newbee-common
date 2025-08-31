// Copyright 2024 Newbee Team. All Rights Reserved.
//
// Fallback Integration for DataPerm Middleware
// Provides fallback execution logic when primary data permission services fail

package dataperm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
	"github.com/zeromicro/go-zero/core/logx"
)

// Local type definitions to avoid circular imports
type FallbackLevel int

const (
	FallbackLevelNone FallbackLevel = iota
	FallbackLevelCache
	FallbackLevelBasic
	FallbackLevelEmergency
	FallbackLevelDeny
)

func (fl FallbackLevel) String() string {
	switch fl {
	case FallbackLevelNone:
		return "none"
	case FallbackLevelCache:
		return "cache"
	case FallbackLevelBasic:
		return "basic"
	case FallbackLevelEmergency:
		return "emergency"
	case FallbackLevelDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// PermissionRequest defines a permission request for fallback execution
type PermissionRequest struct {
	UserID    string `json:"user_id"`
	TenantID  string `json:"tenant_id"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
}

// DataPermFallbackResult represents the result of a fallback operation
type DataPermFallbackResult struct {
	DataScope     string                 `json:"data_scope"`
	SubDept       string                 `json:"sub_dept,omitempty"`
	CustomDept    string                 `json:"custom_dept,omitempty"`
	Level         string                 `json:"level"`
	Source        string                 `json:"source"`
	ExecutionTime time.Duration          `json:"execution_time"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// executeFallback executes the appropriate fallback strategy for DataPerm operations
func (m *DataPermMiddleware) executeFallback(ctx context.Context, roleCodes []string, tenantId uint64, operation string) (*DataPermFallbackResult, error) {
	if m.fallbackStrategy == nil {
		return nil, fmt.Errorf("fallback strategy not available")
	}

	startTime := time.Now()

	// Create permission request for fallback strategy
	req := &PermissionRequest{
		UserID:    fmt.Sprintf("tenant_%d", tenantId),
		TenantID:  fmt.Sprintf("%d", tenantId),
		Operation: operation,
		Resource:  "dataperm",
	}

	// Execute fallback strategy
	result, err := m.fallbackStrategy.ExecuteFallback(ctx, req)
	if err != nil {
		m.metricsCollector.RecordError("dataperm", "fallback_execution", "strategy_error")
		return nil, fmt.Errorf("fallback execution failed: %w", err)
	}

	// Convert fallback result to DataPerm-specific result
	fallbackResult := &DataPermFallbackResult{
		Level:         result.Level,
		Source:        result.Source,
		ExecutionTime: time.Since(startTime),
		Metadata:      result.Metadata,
	}

	// Determine appropriate data scope based on fallback level
	currentLevel := m.fallbackStrategy.GetCurrentLevel()
	switch currentLevel {
	case FallbackLevelCache:
		fallbackResult.DataScope = m.getCachedDataScope(roleCodes, tenantId)
		fallbackResult.SubDept = m.getCachedSubDept(tenantId)
		fallbackResult.CustomDept = m.getCachedCustomDept(roleCodes, tenantId)
	case FallbackLevelBasic:
		fallbackResult.DataScope = entenum.DataPermOwnStr // Basic: own data only
		fallbackResult.SubDept = ""
		fallbackResult.CustomDept = ""
	case FallbackLevelEmergency:
		fallbackResult.DataScope = entenum.DataPermOwnStr // Emergency: own data only
		fallbackResult.SubDept = ""
		fallbackResult.CustomDept = ""
	case FallbackLevelDeny:
		return nil, fmt.Errorf("access denied due to fallback level: %s", currentLevel.String())
	default:
		fallbackResult.DataScope = entenum.DataPermOwnStr // Default to safe option
	}

	// Record fallback usage metrics
	m.metricsCollector.RecordCustomMetric("dataperm_fallback_execution", 1.0, map[string]string{
		"level":     result.Level,
		"operation": operation,
		"source":    result.Source,
	})

	logx.Infow("DataPerm fallback executed",
		logx.Field("operation", operation),
		logx.Field("level", result.Level),
		logx.Field("dataScope", fallbackResult.DataScope),
		logx.Field("executionTime", fallbackResult.ExecutionTime))

	return fallbackResult, nil
}

// getCachedDataScope attempts to get data scope from emergency cache or provides safe default
func (m *DataPermMiddleware) getCachedDataScope(roleCodes []string, tenantId uint64) string {
	// Try to get from emergency permission cache
	if m.fallbackStrategy != nil {
		cacheKey := fmt.Sprintf("emergency:%d:roles:%s", tenantId, strings.Join(roleCodes, ","))

		// This would ideally check the emergency cache, but for now we provide safe defaults
		// based on role patterns
		for _, roleCode := range roleCodes {
			roleCode = strings.ToLower(roleCode)

			// Admin roles get department and sub-department access
			if strings.Contains(roleCode, "admin") || strings.Contains(roleCode, "manager") {
				return entenum.DataPermOwnDeptAndSubStr
			}

			// Department roles get department access
			if strings.Contains(roleCode, "dept") || strings.Contains(roleCode, "department") {
				return entenum.DataPermOwnDeptStr
			}
		}
	}

	// Default to safest option - own data only
	return entenum.DataPermOwnStr
}

// getCachedSubDept provides cached or safe default sub-department data
func (m *DataPermMiddleware) getCachedSubDept(tenantId uint64) string {
	// In emergency situations, provide empty sub-department to be safe
	// This prevents unauthorized access to sub-department data
	return ""
}

// getCachedCustomDept provides cached or safe default custom department data
func (m *DataPermMiddleware) getCachedCustomDept(roleCodes []string, tenantId uint64) string {
	// In emergency situations, provide empty custom department to be safe
	// This prevents unauthorized access to custom department data
	return ""
}

// TriggerFallbackEscalation manually triggers fallback level escalation
func (m *DataPermMiddleware) TriggerFallbackEscalation(reason string) error {
	if m.fallbackStrategy == nil {
		return fmt.Errorf("fallback strategy not available")
	}

	return m.fallbackStrategy.EscalateLevel(reason)
}

// TriggerFallbackDeescalation manually triggers fallback level de-escalation
func (m *DataPermMiddleware) TriggerFallbackDeescalation(reason string) error {
	if m.fallbackStrategy == nil {
		return fmt.Errorf("fallback strategy not available")
	}

	return m.fallbackStrategy.DeescalateLevel(reason)
}

// GetFallbackStatus returns current fallback strategy status
func (m *DataPermMiddleware) GetFallbackStatus() map[string]interface{} {
	if m.fallbackStrategy == nil {
		return map[string]interface{}{
			"enabled": false,
			"status":  "not_configured",
		}
	}

	stats := m.fallbackStrategy.GetStats()
	healthStats := m.healthRegistry.GetAllStats()

	return map[string]interface{}{
		"enabled":         true,
		"current_level":   stats.CurrentLevel,
		"cache_size":      stats.EmergencyCacheSize,
		"fallback_usage":  stats.FallbackUsage,
		"health_checkers": healthStats,
		"uptime_seconds":  stats.UptimeSeconds,
	}
}

// CacheEmergencyDataPerm caches emergency data permissions for a tenant
func (m *DataPermMiddleware) CacheEmergencyDataPerm(tenantId uint64, userID string, permissions map[string]interface{}, ttl time.Duration) {
	if m.fallbackStrategy == nil {
		logx.Warn("Cannot cache emergency data permission: fallback strategy not available")
		return
	}

	// Convert permissions to string slice for compatibility
	permissionsList := make([]string, 0)
	if dataScope, ok := permissions["data_scope"].(string); ok {
		permissionsList = append(permissionsList, fmt.Sprintf("data_scope:%s", dataScope))
	}
	if subDept, ok := permissions["sub_dept"].(string); ok && subDept != "" {
		permissionsList = append(permissionsList, fmt.Sprintf("sub_dept:%s", subDept))
	}
	if customDept, ok := permissions["custom_dept"].(string); ok && customDept != "" {
		permissionsList = append(permissionsList, fmt.Sprintf("custom_dept:%s", customDept))
	}

	m.fallbackStrategy.CacheEmergencyPermission(
		userID,
		fmt.Sprintf("%d", tenantId),
		permissionsList,
		ttl,
	)

	logx.Infow("Emergency data permission cached",
		logx.Field("tenantId", tenantId),
		logx.Field("userID", userID),
		logx.Field("permissions", len(permissionsList)),
		logx.Field("ttl", ttl))
}

// RegisterDataPermHealthChecker registers a custom health checker for DataPerm
func (m *DataPermMiddleware) RegisterDataPermHealthChecker(name string, checker HealthChecker) {
	if m.healthRegistry == nil {
		logx.Warn("Cannot register health checker: health registry not available")
		return
	}

	m.healthRegistry.Register(checker)

	if m.fallbackStrategy != nil {
		m.fallbackStrategy.AddHealthChecker(checker)
	}

	logx.Infow("DataPerm health checker registered", logx.Field("name", name))
}
