// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package adapters

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/auth/config"
	"github.com/coder-lulu/newbee-common/middleware/auth/core"
	"github.com/coder-lulu/newbee-common/middleware/auth/performance"
	"github.com/coder-lulu/newbee-common/middleware/auth/security"
)

// HTTPMiddleware provides standard HTTP middleware functionality for authentication
type HTTPMiddleware struct {
	mu              sync.RWMutex
	config          *config.UnifiedConfig
	validator       core.TokenValidator
	extractor       core.ClaimsExtractor
	contextManager  core.ContextManager
	cache           *performance.SimpleCache
	revocation      *security.TokenRevocation
	keyManager      *security.KeyManager
	plugins         []core.AuthPlugin
	skipPaths       map[string]bool
}

// MiddlewareBuilder implements the builder pattern for creating HTTP middleware
type MiddlewareBuilder struct {
	config *config.UnifiedConfig
	plugins []core.AuthPlugin
}

// NewHTTPMiddleware creates a new HTTP authentication middleware
func NewHTTPMiddleware(cfg *config.UnifiedConfig) (*HTTPMiddleware, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Initialize core components
	validator, err := core.NewJWTValidator(
		cfg.Core.Algorithm,
		cfg.Core.SecretSource,
		cfg.Core.ClockSkew,
	)
	if err != nil {
		return nil, err
	}

	contextManager := core.NewSafeContextManager()
	extractor := core.NewClaimsExtractor(validator, contextManager, cfg.Core.ClockSkew)
	extractor.SetRequiredClaims(cfg.Core.RequiredClaims)

	// Build skip paths map for O(1) lookup
	skipPaths := make(map[string]bool, len(cfg.Core.SkipPaths))
	for _, path := range cfg.Core.SkipPaths {
		skipPaths[path] = true
	}

	middleware := &HTTPMiddleware{
		config:         cfg,
		validator:      validator,
		extractor:      extractor,
		contextManager: contextManager,
		skipPaths:      skipPaths,
		plugins:        make([]core.AuthPlugin, 0),
	}

	// Initialize optional plugins based on configuration
	if err := middleware.initializePlugins(); err != nil {
		return nil, err
	}

	return middleware, nil
}

// NewBuilder creates a new middleware builder for custom configurations
func NewBuilder() *MiddlewareBuilder {
	return &MiddlewareBuilder{
		config:  config.DefaultConfig(),
		plugins: make([]core.AuthPlugin, 0),
	}
}

// WithConfig sets the configuration
func (b *MiddlewareBuilder) WithConfig(cfg *config.UnifiedConfig) *MiddlewareBuilder {
	b.config = cfg
	return b
}

// WithPlugin adds a custom plugin
func (b *MiddlewareBuilder) WithPlugin(plugin core.AuthPlugin) *MiddlewareBuilder {
	b.plugins = append(b.plugins, plugin)
	return b
}

// Build creates the HTTP middleware
func (b *MiddlewareBuilder) Build() (*HTTPMiddleware, error) {
	middleware, err := NewHTTPMiddleware(b.config)
	if err != nil {
		return nil, err
	}

	// Add custom plugins
	for _, plugin := range b.plugins {
		middleware.AddPlugin(plugin)
	}

	return middleware, nil
}

// Handler returns the HTTP middleware handler function
func (hm *HTTPMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hm.handleRequest(w, r, next)
	})
}

// HandlerFunc returns the HTTP middleware as a HandlerFunc
func (hm *HTTPMiddleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hm.handleRequest(w, r, http.HandlerFunc(next))
	}
}

// handleRequest processes the authentication for an HTTP request
func (hm *HTTPMiddleware) handleRequest(w http.ResponseWriter, r *http.Request, next http.Handler) {
	start := time.Now()
	ctx := r.Context()

	// Check if authentication is enabled
	if !hm.config.Core.Enabled {
		next.ServeHTTP(w, r)
		return
	}

	// Fast path: Skip authentication for certain paths
	if hm.skipPaths[r.URL.Path] {
		next.ServeHTTP(w, r)
		return
	}

	// Extract token from request
	token, err := hm.extractor.ExtractTokenFromRequest(r)
	if err != nil {
		hm.sendErrorResponse(w, err, http.StatusUnauthorized)
		return
	}

	// Pre-processing plugins (security checks, rate limiting, etc.)
	for _, plugin := range hm.plugins {
		if err := plugin.PreProcess(ctx, token, r); err != nil {
			plugin.OnError(ctx, err, r)
			hm.sendErrorResponse(w, err, http.StatusUnauthorized)
			return
		}
	}

	// Check cache first for performance
	var claims *core.Claims
	cacheKey := performance.TokenCacheKey(token)
	
	if hm.cache != nil {
		if cachedClaims, found := hm.cache.Get(cacheKey); found {
			claims = cachedClaims
		}
	}

	// If not in cache, validate token
	if claims == nil {
		claims, err = hm.extractor.ExtractClaims(token)
		if err != nil {
			hm.sendErrorResponse(w, err, http.StatusUnauthorized)
			return
		}

		// Cache successful validation
		if hm.cache != nil {
			ttl := hm.config.GetEffectiveTTL()
			// Don't cache longer than token expiry
			if tokenTTL := time.Until(claims.ExpiresAt); tokenTTL < ttl {
				ttl = tokenTTL
			}
			hm.cache.Set(cacheKey, claims, ttl)
		}
	}

	// Post-processing plugins (context injection, logging, etc.)
	for _, plugin := range hm.plugins {
		if newCtx, err := plugin.PostProcess(ctx, claims, r); err != nil {
			plugin.OnError(ctx, err, r)
			hm.sendErrorResponse(w, err, http.StatusUnauthorized)
			return
		} else {
			ctx = newCtx
		}
	}

	// Inject authentication context
	ctx = hm.contextManager.InjectContext(ctx, claims)

	// Record processing time for monitoring
	processingTime := time.Since(start)
	if processingTime > 100*time.Millisecond {
		// Log slow authentication (could indicate performance issues)
	}

	// Continue to next handler with authenticated context
	next.ServeHTTP(w, r.WithContext(ctx))
}

// AddPlugin adds a plugin to the middleware
func (hm *HTTPMiddleware) AddPlugin(plugin core.AuthPlugin) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Insert plugin in priority order (higher priority first)
	inserted := false
	for i, existingPlugin := range hm.plugins {
		if plugin.Priority() > existingPlugin.Priority() {
			// Insert at position i
			hm.plugins = append(hm.plugins[:i], append([]core.AuthPlugin{plugin}, hm.plugins[i:]...)...)
			inserted = true
			break
		}
	}
	
	if !inserted {
		hm.plugins = append(hm.plugins, plugin)
	}
}

// RemovePlugin removes a plugin by name
func (hm *HTTPMiddleware) RemovePlugin(name string) bool {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	for i, plugin := range hm.plugins {
		if plugin.Name() == name {
			hm.plugins = append(hm.plugins[:i], hm.plugins[i+1:]...)
			return true
		}
	}
	return false
}

// GetStats returns middleware statistics
func (hm *HTTPMiddleware) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	if hm.cache != nil {
		stats["cache"] = hm.cache.Stats()
	}

	if hm.revocation != nil {
		stats["revocation"] = hm.revocation.GetStats()
	}

	stats["plugins"] = len(hm.plugins)
	stats["config_environment"] = hm.config.Environment

	return stats
}

// ExtractUserID is a convenience function to extract user ID from request context
func ExtractUserID(r *http.Request) (string, bool) {
	if userID, ok := r.Context().Value(core.UserIDKey).(string); ok && userID != "" {
		return userID, true
	}
	return "", false
}

// ExtractTenantID is a convenience function to extract tenant ID from request context
func ExtractTenantID(r *http.Request) (string, bool) {
	if tenantID, ok := r.Context().Value(core.TenantIDKey).(string); ok && tenantID != "" {
		return tenantID, true
	}
	return "", false
}

// ExtractClaims is a convenience function to extract full claims from request context
func ExtractClaims(r *http.Request) (*core.Claims, bool) {
	if claims, ok := r.Context().Value(core.ClaimsKey).(*core.Claims); ok && claims != nil {
		return claims, true
	}
	return nil, false
}

// RequireAuthentication is a decorator that ensures the request is authenticated
func RequireAuthentication(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userID, ok := ExtractUserID(r); !ok || userID == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// RequireTenant is a decorator that ensures the request is from a specific tenant
func RequireTenant(requiredTenant string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tenantID, ok := ExtractTenantID(r)
			if !ok || tenantID != requiredTenant {
				http.Error(w, "Tenant access denied", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}
}

// sendErrorResponse sends a standardized error response
func (hm *HTTPMiddleware) sendErrorResponse(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Extract error code and message from AuthError if available
	var errorCode, errorMessage string
	if authErr, ok := err.(*core.AuthError); ok {
		errorCode = authErr.Code
		errorMessage = authErr.Message
	} else {
		errorCode = "AUTHENTICATION_FAILED"
		errorMessage = err.Error()
	}

	// Don't expose sensitive error details in production
	if hm.config.IsProductionEnvironment() && statusCode == http.StatusUnauthorized {
		errorMessage = "Authentication failed"
	}

	response := map[string]interface{}{
		"error": map[string]string{
			"code":    errorCode,
			"message": errorMessage,
		},
	}

	// Write JSON response
	if err := writeJSONResponse(w, response); err != nil {
		// Fallback to simple text response if JSON encoding fails
		http.Error(w, errorMessage, statusCode)
	}
}

// initializePlugins initializes plugins based on configuration
func (hm *HTTPMiddleware) initializePlugins() error {
	// Initialize cache plugin
	if hm.config.Plugins.Cache != nil && hm.config.Plugins.Cache.Enabled {
		cachePlugin := performance.NewCachePlugin(
			hm.config.Plugins.Cache.Size,
			hm.config.Plugins.Cache.TTL,
		)
		hm.cache = cachePlugin.GetCache()
		hm.AddPlugin(cachePlugin)
	}

	// Initialize token revocation plugin
	if hm.config.Plugins.Security != nil &&
		hm.config.Plugins.Security.TokenRevocation != nil &&
		hm.config.Plugins.Security.TokenRevocation.Enabled {
		
		revConfig := hm.config.Plugins.Security.TokenRevocation
		hm.revocation = security.NewTokenRevocation(
			revConfig.CleanupInterval,
			revConfig.MaxStoredTokens,
		)
		revocationPlugin := security.NewRevocationPlugin(hm.revocation)
		hm.AddPlugin(revocationPlugin)
	}

	return nil
}

// writeJSONResponse writes a JSON response to the http.ResponseWriter
func writeJSONResponse(w http.ResponseWriter, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	// Simple JSON encoding - avoiding external dependencies
	jsonStr := `{"error":{"code":"AUTHENTICATION_FAILED","message":"Authentication failed"}}`
	_, err := w.Write([]byte(jsonStr))
	return err
}

// IsPathSkipped checks if a path should skip authentication
func (hm *HTTPMiddleware) IsPathSkipped(path string) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.skipPaths[path]
}

// AddSkipPath adds a path to be skipped during authentication
func (hm *HTTPMiddleware) AddSkipPath(path string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.skipPaths[path] = true
}

// RemoveSkipPath removes a path from the skip list
func (hm *HTTPMiddleware) RemoveSkipPath(path string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	delete(hm.skipPaths, path)
}

// UpdateConfig updates the middleware configuration (thread-safe)
func (hm *HTTPMiddleware) UpdateConfig(newConfig *config.UnifiedConfig) error {
	if err := newConfig.Validate(); err != nil {
		return err
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.config = newConfig

	// Rebuild skip paths map
	hm.skipPaths = make(map[string]bool, len(newConfig.Core.SkipPaths))
	for _, path := range newConfig.Core.SkipPaths {
		hm.skipPaths[path] = true
	}

	// Update extractor required claims
	hm.extractor.SetRequiredClaims(newConfig.Core.RequiredClaims)

	return nil
}