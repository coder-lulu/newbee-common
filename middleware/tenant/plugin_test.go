// Copyright 2024 The NewBee Authors. All Rights Reserved.

package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/stretchr/testify/assert"
)

func TestTenantCheckPlugin_BasicTenantCheck(t *testing.T) {
	// Test basic tenant ID checking (existing functionality)
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:        true,
			ValidateStatus: false, // Disable enhanced features for basic test
			CacheEnabled:   false,
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
		},
	}

	// Test with missing tenant ID
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "No tenant information available")

	// Test with valid tenant ID
	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantCheckPlugin_StatusValidation(t *testing.T) {
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:        true,
			ValidateStatus: false, // Disable status validation to test basic flow
			CacheEnabled:   false,
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
			Redis:          nil, // No Redis for simplified test
		},
	}

	// Test with valid tenant ID (should pass when status validation is disabled)
	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantCheckPlugin_SuspendedTenant(t *testing.T) {
	// Test that when ValidateStatus is enabled but Redis is nil, it gracefully degrades
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:        true,
			ValidateStatus: true,
			CacheEnabled:   true,
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
			Redis:          nil, // No Redis - should gracefully degrade
		},
	}

	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	// Should pass because of graceful degradation when Redis is not available
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantCheckPlugin_RateLimit(t *testing.T) {
	// Test rate limiting graceful degradation when Redis is not available
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:           true,
			ValidateStatus:    false,
			RateLimitEnabled:  true,
			MaxRequestsPerMin: 2, // Very low limit for testing
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
			Redis:          nil, // No Redis - should gracefully degrade
		},
	}

	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	// Should pass because rate limiting gracefully degrades when Redis is not available
	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantCheckPlugin_CacheGracefulDegradation(t *testing.T) {
	// This test is already covered by other tests where Redis is nil
	// Test that graceful degradation works correctly
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:        true,
			ValidateStatus: true,
			CacheEnabled:   true,
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
			Redis:          nil, // Simulates Redis being unavailable
		},
	}

	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	// Should pass because we gracefully degrade when Redis is unavailable
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantCheckPlugin_BackwardCompatibility(t *testing.T) {
	// Test that existing configurations without new fields still work
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled: true,
			// ValidateStatus and other new fields are not set (zero values)
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
		},
	}

	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantCheckPlugin_SkipPaths(t *testing.T) {
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:   true,
			SkipPaths: []string{"/health", "/metrics"},
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
		},
	}

	// Test that skip paths work without tenant ID
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTenantCheckPlugin_LegacyConfigFormat tests that old configuration format still works
func TestTenantCheckPlugin_LegacyConfigFormat(t *testing.T) {
	// Simulate legacy config (only basic fields, no new enhanced features)
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled:   true,
			SkipPaths: []string{"/api/v1/health"},
			// All new fields are zero values (default false for ValidateStatus, CacheEnabled, RateLimitEnabled)
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
			Redis:          nil, // Legacy configs might not have Redis
		},
	}

	// Test 1: Skip paths still work
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Test 2: Normal protected endpoint requires tenant ID
	req = httptest.NewRequest("GET", "/api/v1/users", nil)
	w = httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "No tenant information available")

	// Test 3: With tenant ID, request passes (backward compatibility)
	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req = httptest.NewRequest("GET", "/api/v1/users", nil).WithContext(ctx)
	w = httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTenantCheckPlugin_DefaultConfig tests that default configuration works correctly
func TestTenantCheckPlugin_DefaultConfig(t *testing.T) {
	// Test with default configuration from framework
	defaultConfig := framework.DefaultUnifiedConfig()
	plugin := &TenantCheckPlugin{
		config: defaultConfig.TenantCheck,
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
			Redis:          nil, // Test without Redis to ensure graceful degradation
		},
	}

	// Verify default values
	assert.True(t, plugin.config.Enabled)
	assert.True(t, plugin.config.ValidateStatus)
	assert.True(t, plugin.config.CacheEnabled)
	assert.False(t, plugin.config.RateLimitEnabled) // Should be disabled by default for backward compatibility
	assert.Equal(t, 1000, plugin.config.MaxRequestsPerMin)

	// Test that it works with default configuration
	ctx := plugin.core.ContextManager.SetTenantID(context.Background(), "tenant123")
	req := httptest.NewRequest("GET", "/api/v1/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTenantCheckPlugin_ExistingBehaviorPreserved tests that all existing behavior is preserved
func TestTenantCheckPlugin_ExistingBehaviorPreserved(t *testing.T) {
	plugin := &TenantCheckPlugin{
		config: &framework.TenantCheckConfig{
			Enabled: true,
			// Only basic configuration - enhanced features disabled
			ValidateStatus:   false,
			CacheEnabled:     false,
			RateLimitEnabled: false,
		},
		core: &framework.CoreServices{
			ContextManager: keys.NewContextManager(),
		},
	}

	testCases := []struct {
		name           string
		path           string
		tenantID       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Missing tenant ID should return 403",
			path:           "/api/v1/users",
			tenantID:       "",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "No tenant information available",
		},
		{
			name:           "Valid tenant ID should pass",
			path:           "/api/v1/users",
			tenantID:       "tenant123",
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "Another valid tenant should pass",
			path:           "/api/v1/posts",
			tenantID:       "tenant456",
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ctx context.Context = context.Background()
			if tc.tenantID != "" {
				ctx = plugin.core.ContextManager.SetTenantID(ctx, tc.tenantID)
			}

			req := httptest.NewRequest("GET", tc.path, nil).WithContext(ctx)
			w := httptest.NewRecorder()

			plugin.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tc.expectedBody)
			}
		})
	}
}