package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
)

type tenantPluginOptions struct {
	config   *framework.TenantCheckConfig
	provider framework.TenantInfoProvider
}

type tenantPluginOption func(*tenantPluginOptions)

func withTenantConfig(cfg *framework.TenantCheckConfig) tenantPluginOption {
	return func(o *tenantPluginOptions) {
		o.config = cfg
	}
}

func withTenantProvider(provider framework.TenantInfoProvider) tenantPluginOption {
	return func(o *tenantPluginOptions) {
		o.provider = provider
	}
}

func newTestTenantPlugin(t *testing.T, opts ...tenantPluginOption) *TenantCheckPlugin {
	t.Helper()

	options := tenantPluginOptions{
		config: &framework.TenantCheckConfig{
			Enabled:        true,
			ValidateStatus: false,
			CacheEnabled:   false,
		},
	}
	for _, opt := range opts {
		opt(&options)
	}

	plg := &TenantCheckPlugin{}
	services := &framework.CoreServices{
		Config: &framework.UnifiedConfig{
			TenantCheck: options.config,
		},
		ContextManager: keys.NewContextManager(),
		TenantProvider: options.provider,
	}

	if err := plg.Init(services); err != nil {
		t.Fatalf("failed to init tenant plugin: %v", err)
	}

	return plg
}

func TestTenantCheckPluginRejectsMissingTenant(t *testing.T) {
	plugin := newTestTenantPlugin(t)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	resp := httptest.NewRecorder()
	called := false

	plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.Code)
	}

	if called {
		t.Fatalf("next handler should not be called when tenant ID is missing")
	}
}

func TestTenantCheckPluginRejectsZeroTenant(t *testing.T) {
	plugin := newTestTenantPlugin(t)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	ctxWithZero := plugin.core.ContextManager.SetTenantID(req.Context(), "0")
	req = req.WithContext(ctxWithZero)
	resp := httptest.NewRecorder()
	called := false

	plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.Code)
	}

	if called {
		t.Fatalf("next handler should not be called when tenant ID is zero")
	}
}

func TestTenantCheckPluginRejectsSuspendedTenant(t *testing.T) {
	provider := &stubTenantProvider{status: framework.TenantStatusSuspended}
	plugin := newTestTenantPlugin(t,
		withTenantConfig(&framework.TenantCheckConfig{Enabled: true, ValidateStatus: true, CacheEnabled: false}),
		withTenantProvider(provider),
	)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	ctx := plugin.core.ContextManager.SetTenantID(req.Context(), "42")
	req = req.WithContext(ctx)
	resp := httptest.NewRecorder()
	called := false

	plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})(resp, req)

	if provider.calls != 1 {
		t.Fatalf("expected provider to be called once, got %d", provider.calls)
	}

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.Code)
	}

	if called {
		t.Fatalf("next handler should not execute for suspended tenant")
	}
}

func TestTenantCheckPluginAllowsActiveTenant(t *testing.T) {
	provider := &stubTenantProvider{status: framework.TenantStatusActive}
	plugin := newTestTenantPlugin(t,
		withTenantConfig(&framework.TenantCheckConfig{Enabled: true, ValidateStatus: true, CacheEnabled: false}),
		withTenantProvider(provider),
	)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	ctx := plugin.core.ContextManager.SetTenantID(req.Context(), "123")
	req = req.WithContext(ctx)
	resp := httptest.NewRecorder()
	called := false

	plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.Code)
	}

	if !called {
		t.Fatalf("expected next handler to run for active tenant")
	}

	if provider.calls != 1 {
		t.Fatalf("expected provider to be called once, got %d", provider.calls)
	}
}

func TestTenantCheckPluginInitFailsWithoutProvider(t *testing.T) {
	plugin := &TenantCheckPlugin{}
	services := &framework.CoreServices{
		Config: &framework.UnifiedConfig{
			TenantCheck: &framework.TenantCheckConfig{Enabled: true, ValidateStatus: true},
		},
		ContextManager: keys.NewContextManager(),
	}

	if err := plugin.Init(services); err == nil {
		t.Fatalf("expected error when tenant provider is missing with validation enabled")
	}
}

type stubTenantProvider struct {
	status framework.TenantStatus
	calls  int
}

func (s *stubTenantProvider) GetTenantInfo(_ context.Context, tenantID string) (*framework.TenantInfo, error) {
	s.calls++
	if s.status == "" {
		s.status = framework.TenantStatusActive
	}
	return &framework.TenantInfo{
		ID:        tenantID,
		Status:    s.status,
		UpdatedAt: time.Now(),
	}, nil
}

func TestTenantCheckShouldSkip(t *testing.T) {
	cfg := &framework.TenantCheckConfig{
		Enabled:        true,
		ValidateStatus: false,
		CacheEnabled:   false,
		SkipPaths:      []string{"/exact", "/prefix/*", "  /trim  "},
	}
	plugin := newTestTenantPlugin(t, withTenantConfig(cfg))

	testCases := []struct {
		name string
		path string
		want bool
	}{
		{name: "exact match", path: "/exact", want: true},
		{name: "non exact", path: "/exact/path", want: false},
		{name: "wildcard child", path: "/prefix/child", want: true},
		{name: "wildcard base", path: "/prefix", want: false},
		{name: "trimmed", path: "/trim", want: true},
		{name: "no match", path: "/other", want: false},
	}

	for _, tc := range testCases {
		if got := plugin.shouldSkip(tc.path); got != tc.want {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, got)
		}
	}
}
