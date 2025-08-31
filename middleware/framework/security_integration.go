// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package framework

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SecurityIntegrationPlugin demonstrates security system integration
type SecurityIntegrationPlugin struct {
	name            string
	version         string
	enabled         bool
	securityManager *SecurityManager
	config          *SecurityIntegrationConfig
	stats           *SecurityIntegrationStats
	mutex           sync.RWMutex
}

// SecurityIntegrationConfig defines security integration configuration
type SecurityIntegrationConfig struct {
	Enabled               bool                   `json:"enabled" yaml:"enabled"`
	EnforceHTTPS          bool                   `json:"enforce_https" yaml:"enforce_https"`
	RequireAuthentication bool                   `json:"require_authentication" yaml:"require_authentication"`
	CSRFProtection        bool                   `json:"csrf_protection" yaml:"csrf_protection"`
	CORSConfig            *CORSConfig            `json:"cors" yaml:"cors"`
	SecurityHeaders       *SecurityHeadersConfig `json:"security_headers" yaml:"security_headers"`
	AuditSecurity         bool                   `json:"audit_security" yaml:"audit_security"`
	ThreatResponse        *ThreatResponseConfig  `json:"threat_response" yaml:"threat_response"`
}

// CORSConfig defines CORS configuration
type CORSConfig struct {
	Enabled          bool     `json:"enabled" yaml:"enabled"`
	AllowedOrigins   []string `json:"allowed_origins" yaml:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods" yaml:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers" yaml:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers" yaml:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials" yaml:"allow_credentials"`
	MaxAge           int      `json:"max_age" yaml:"max_age"`
}

// SecurityHeadersConfig defines security headers configuration
type SecurityHeadersConfig struct {
	Enabled                 bool   `json:"enabled" yaml:"enabled"`
	ContentSecurityPolicy   string `json:"content_security_policy" yaml:"content_security_policy"`
	StrictTransportSecurity string `json:"strict_transport_security" yaml:"strict_transport_security"`
	XContentTypeOptions     string `json:"x_content_type_options" yaml:"x_content_type_options"`
	XFrameOptions           string `json:"x_frame_options" yaml:"x_frame_options"`
	XSSProtection           string `json:"xss_protection" yaml:"xss_protection"`
	ReferrerPolicy          string `json:"referrer_policy" yaml:"referrer_policy"`
	PermissionsPolicy       string `json:"permissions_policy" yaml:"permissions_policy"`
}

// ThreatResponseConfig defines threat response configuration
type ThreatResponseConfig struct {
	Enabled          bool          `json:"enabled" yaml:"enabled"`
	AutoBlock        bool          `json:"auto_block" yaml:"auto_block"`
	BlockDuration    time.Duration `json:"block_duration" yaml:"block_duration"`
	AlertThreshold   int           `json:"alert_threshold" yaml:"alert_threshold"`
	EscalationLevel  string        `json:"escalation_level" yaml:"escalation_level"`
	NotificationURLs []string      `json:"notification_urls" yaml:"notification_urls"`
}

// SecurityIntegrationStats tracks security integration statistics
type SecurityIntegrationStats struct {
	TotalRequests          int64 `json:"total_requests"`
	SecurityChecks         int64 `json:"security_checks"`
	ThreatsBlocked         int64 `json:"threats_blocked"`
	HTTPSEnforced          int64 `json:"https_enforced"`
	CSRFBlocked            int64 `json:"csrf_blocked"`
	CORSBlocked            int64 `json:"cors_blocked"`
	SecurityHeadersAdded   int64 `json:"security_headers_added"`
	AuthenticationRequired int64 `json:"authentication_required"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestInfo *Request               `json:"request_info,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// SecurityPlugin creates a comprehensive security plugin
type SecurityPlugin struct {
	*SecurityIntegrationPlugin
}

// NewSecurityIntegrationPlugin creates a new security integration plugin
func NewSecurityIntegrationPlugin(securityManager *SecurityManager, config *SecurityIntegrationConfig) *SecurityIntegrationPlugin {
	if config == nil {
		config = DefaultSecurityIntegrationConfig()
	}

	return &SecurityIntegrationPlugin{
		name:            "security-integration",
		version:         "1.0.0",
		enabled:         config.Enabled,
		securityManager: securityManager,
		config:          config,
		stats:           &SecurityIntegrationStats{},
	}
}

// DefaultSecurityIntegrationConfig returns default security integration configuration
func DefaultSecurityIntegrationConfig() *SecurityIntegrationConfig {
	return &SecurityIntegrationConfig{
		Enabled:               true,
		EnforceHTTPS:          true,
		RequireAuthentication: false,
		CSRFProtection:        true,
		CORSConfig: &CORSConfig{
			Enabled:          true,
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization"},
			AllowCredentials: false,
			MaxAge:           86400,
		},
		SecurityHeaders: &SecurityHeadersConfig{
			Enabled:                 true,
			ContentSecurityPolicy:   "default-src 'self'",
			StrictTransportSecurity: "max-age=31536000; includeSubDomains",
			XContentTypeOptions:     "nosniff",
			XFrameOptions:           "DENY",
			XSSProtection:           "1; mode=block",
			ReferrerPolicy:          "strict-origin-when-cross-origin",
			PermissionsPolicy:       "geolocation=(), microphone=(), camera=()",
		},
		AuditSecurity: true,
		ThreatResponse: &ThreatResponseConfig{
			Enabled:         true,
			AutoBlock:       true,
			BlockDuration:   15 * time.Minute,
			AlertThreshold:  5,
			EscalationLevel: "medium",
		},
	}
}

// Name returns the plugin name
func (sip *SecurityIntegrationPlugin) Name() string {
	return sip.name
}

// Version returns the plugin version
func (sip *SecurityIntegrationPlugin) Version() string {
	return sip.version
}

// Description returns the plugin description
func (sip *SecurityIntegrationPlugin) Description() string {
	return "Comprehensive security integration plugin with HTTPS enforcement, CORS, CSRF protection, and security headers"
}

// Dependencies returns plugin dependencies
func (sip *SecurityIntegrationPlugin) Dependencies() []string {
	return []string{}
}

// Priority returns the plugin priority
func (sip *SecurityIntegrationPlugin) Priority() int {
	return 100 // High priority for security
}

// Metadata returns plugin metadata
func (sip *SecurityIntegrationPlugin) Metadata() *PluginMetadata {
	return &PluginMetadata{
		Name:        sip.name,
		Version:     sip.version,
		Author:      "NewBee Framework",
		Description: sip.Description(),
		Tags:        []string{"security", "https", "cors", "csrf", "headers"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// Initialize initializes the plugin
func (sip *SecurityIntegrationPlugin) Initialize(config PluginConfig) error {
	sip.mutex.Lock()
	defer sip.mutex.Unlock()

	sip.enabled = config.Enabled
	return nil
}

// Start starts the plugin
func (sip *SecurityIntegrationPlugin) Start() error {
	sip.mutex.Lock()
	defer sip.mutex.Unlock()

	if !sip.enabled {
		return fmt.Errorf("security integration plugin is disabled")
	}

	return nil
}

// Stop stops the plugin
func (sip *SecurityIntegrationPlugin) Stop() error {
	sip.mutex.Lock()
	defer sip.mutex.Unlock()

	sip.enabled = false
	return nil
}

// Health returns plugin health status
func (sip *SecurityIntegrationPlugin) Health() HealthStatus {
	if sip.enabled {
		return HealthStatusHealthy
	}
	return HealthStatusUnhealthy
}

// Handle handles incoming requests with comprehensive security
func (sip *SecurityIntegrationPlugin) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	if !sip.enabled {
		return next(ctx, req)
	}

	sip.mutex.Lock()
	sip.stats.TotalRequests++
	sip.mutex.Unlock()

	// 1. HTTPS Enforcement
	if sip.config.EnforceHTTPS {
		if err := sip.enforceHTTPS(req); err != nil {
			sip.incrementCounter(&sip.stats.HTTPSEnforced)
			return sip.createSecurityResponse(400, "HTTPS Required", err), nil
		}
	}

	// 2. CORS Handling
	if sip.config.CORSConfig != nil && sip.config.CORSConfig.Enabled {
		if corsResp := sip.handleCORS(req); corsResp != nil {
			if corsResp.StatusCode != 200 {
				sip.incrementCounter(&sip.stats.CORSBlocked)
			}
			return corsResp, nil
		}
	}

	// 3. CSRF Protection
	if sip.config.CSRFProtection {
		if err := sip.validateCSRF(req); err != nil {
			sip.incrementCounter(&sip.stats.CSRFBlocked)
			return sip.createSecurityResponse(403, "CSRF Protection Failed", err), nil
		}
	}

	// 4. Authentication Check
	if sip.config.RequireAuthentication {
		if err := sip.validateAuthentication(req); err != nil {
			sip.incrementCounter(&sip.stats.AuthenticationRequired)
			return sip.createSecurityResponse(401, "Authentication Required", err), nil
		}
	}

	// 5. Execute security manager checks
	if sip.securityManager != nil {
		securityMiddleware := NewSecurityMiddleware(sip.securityManager)
		resp, err := securityMiddleware.Handle(ctx, req, next)

		// If security middleware blocked the request, handle it
		if resp != nil && (resp.StatusCode == 400 || resp.StatusCode == 429 || resp.StatusCode == 500) {
			sip.incrementCounter(&sip.stats.ThreatsBlocked)
			sip.handleThreatDetection(req, string(resp.Body))
		}

		// Add security headers to successful responses
		if resp != nil && resp.StatusCode == 200 {
			sip.addSecurityHeaders(resp)
			sip.incrementCounter(&sip.stats.SecurityHeadersAdded)
		}

		return resp, err
	}

	// 6. Process request normally
	resp, err := next(ctx, req)

	// 7. Add security headers to response
	if resp != nil && sip.config.SecurityHeaders != nil && sip.config.SecurityHeaders.Enabled {
		sip.addSecurityHeaders(resp)
		sip.incrementCounter(&sip.stats.SecurityHeadersAdded)
	}

	sip.incrementCounter(&sip.stats.SecurityChecks)
	return resp, err
}

// enforceHTTPS enforces HTTPS for requests
func (sip *SecurityIntegrationPlugin) enforceHTTPS(req *Request) error {
	// Check if request is HTTPS (simplified check)
	if headers, exists := req.Headers["X-Forwarded-Proto"]; exists {
		for _, header := range headers {
			if header == "https" {
				return nil
			}
		}
		return fmt.Errorf("HTTPS required but request is HTTP")
	}

	// Default to allowing if we can't determine protocol
	return nil
}

// handleCORS handles CORS preflight and actual requests
func (sip *SecurityIntegrationPlugin) handleCORS(req *Request) *Response {
	cors := sip.config.CORSConfig

	// Get origin header
	origin := ""
	if origins, exists := req.Headers["Origin"]; exists && len(origins) > 0 {
		origin = origins[0]
	}

	// Check if origin is allowed
	originAllowed := false
	for _, allowedOrigin := range cors.AllowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			originAllowed = true
			break
		}
	}

	if !originAllowed && origin != "" {
		return &Response{
			StatusCode: 403,
			Body:       []byte("CORS: Origin not allowed"),
			Headers:    make(map[string][]string),
		}
	}

	// Handle preflight request
	if req.Method == "OPTIONS" {
		headers := make(map[string][]string)

		if originAllowed {
			headers["Access-Control-Allow-Origin"] = []string{origin}
		}

		headers["Access-Control-Allow-Methods"] = cors.AllowedMethods
		headers["Access-Control-Allow-Headers"] = cors.AllowedHeaders

		if cors.AllowCredentials {
			headers["Access-Control-Allow-Credentials"] = []string{"true"}
		}

		if cors.MaxAge > 0 {
			headers["Access-Control-Max-Age"] = []string{fmt.Sprintf("%d", cors.MaxAge)}
		}

		return &Response{
			StatusCode: 200,
			Headers:    headers,
			Body:       []byte{},
		}
	}

	// For actual requests, CORS headers will be added to the response later
	return nil
}

// validateCSRF validates CSRF tokens
func (sip *SecurityIntegrationPlugin) validateCSRF(req *Request) error {
	// Skip CSRF validation for GET requests
	if req.Method == "GET" || req.Method == "HEAD" || req.Method == "OPTIONS" {
		return nil
	}

	// Check for CSRF token in headers
	if csrfHeaders, exists := req.Headers["X-CSRF-Token"]; exists && len(csrfHeaders) > 0 {
		token := csrfHeaders[0]
		// Simplified CSRF validation - in production, verify against session
		if len(token) >= 16 {
			return nil
		}
	}

	// Check for CSRF token in form data (simplified)
	if req.ContentType == "application/x-www-form-urlencoded" {
		bodyStr := string(req.Body)
		if strings.Contains(bodyStr, "csrf_token=") {
			return nil
		}
	}

	return fmt.Errorf("CSRF token missing or invalid")
}

// validateAuthentication validates request authentication
func (sip *SecurityIntegrationPlugin) validateAuthentication(req *Request) error {
	// Check for Authorization header
	if authHeaders, exists := req.Headers["Authorization"]; exists && len(authHeaders) > 0 {
		auth := authHeaders[0]
		// Simplified authentication check
		if len(auth) > 7 && (auth[:7] == "Bearer " || auth[:6] == "Basic ") {
			return nil
		}
	}

	return fmt.Errorf("authentication required")
}

// addSecurityHeaders adds security headers to response
func (sip *SecurityIntegrationPlugin) addSecurityHeaders(resp *Response) {
	if resp.Headers == nil {
		resp.Headers = make(map[string][]string)
	}

	headers := sip.config.SecurityHeaders

	if headers.ContentSecurityPolicy != "" {
		resp.Headers["Content-Security-Policy"] = []string{headers.ContentSecurityPolicy}
	}

	if headers.StrictTransportSecurity != "" {
		resp.Headers["Strict-Transport-Security"] = []string{headers.StrictTransportSecurity}
	}

	if headers.XContentTypeOptions != "" {
		resp.Headers["X-Content-Type-Options"] = []string{headers.XContentTypeOptions}
	}

	if headers.XFrameOptions != "" {
		resp.Headers["X-Frame-Options"] = []string{headers.XFrameOptions}
	}

	if headers.XSSProtection != "" {
		resp.Headers["X-XSS-Protection"] = []string{headers.XSSProtection}
	}

	if headers.ReferrerPolicy != "" {
		resp.Headers["Referrer-Policy"] = []string{headers.ReferrerPolicy}
	}

	if headers.PermissionsPolicy != "" {
		resp.Headers["Permissions-Policy"] = []string{headers.PermissionsPolicy}
	}

	// Add CORS headers if configured
	if sip.config.CORSConfig != nil && sip.config.CORSConfig.Enabled {
		cors := sip.config.CORSConfig

		if len(cors.AllowedOrigins) > 0 {
			resp.Headers["Access-Control-Allow-Origin"] = []string{cors.AllowedOrigins[0]}
		}

		if len(cors.ExposedHeaders) > 0 {
			resp.Headers["Access-Control-Expose-Headers"] = cors.ExposedHeaders
		}

		if cors.AllowCredentials {
			resp.Headers["Access-Control-Allow-Credentials"] = []string{"true"}
		}
	}
}

// handleThreatDetection handles detected threats
func (sip *SecurityIntegrationPlugin) handleThreatDetection(req *Request, reason string) {
	if !sip.config.ThreatResponse.Enabled {
		return
	}

	// Create security alert
	alert := &SecurityAlert{
		ID:          fmt.Sprintf("alert_%d", time.Now().UnixNano()),
		Type:        "threat_detected",
		Severity:    sip.config.ThreatResponse.EscalationLevel,
		Message:     reason,
		Source:      extractClientIP(req),
		Timestamp:   time.Now(),
		RequestInfo: req,
		Details: map[string]interface{}{
			"user_agent": req.UserAgent,
			"path":       req.Path,
			"method":     req.Method,
		},
	}

	// Log security event
	if sip.config.AuditSecurity {
		// In production, this would integrate with logging system
		fmt.Printf("SECURITY ALERT: %+v\n", alert)
	}

	// Auto-block if configured
	if sip.config.ThreatResponse.AutoBlock {
		// In production, this would add to blacklist or firewall rules
		fmt.Printf("AUTO-BLOCKING IP: %s for %v\n", extractClientIP(req), sip.config.ThreatResponse.BlockDuration)
	}
}

// createSecurityResponse creates a standardized security response
func (sip *SecurityIntegrationPlugin) createSecurityResponse(statusCode int, message string, err error) *Response {
	return &Response{
		StatusCode: statusCode,
		Body:       []byte(fmt.Sprintf("%s: %v", message, err)),
		Headers:    make(map[string][]string),
	}
}

// incrementCounter safely increments a counter
func (sip *SecurityIntegrationPlugin) incrementCounter(counter *int64) {
	sip.mutex.Lock()
	*counter++
	sip.mutex.Unlock()
}

// GetSecurityStats returns security integration statistics
func (sip *SecurityIntegrationPlugin) GetSecurityStats() *SecurityIntegrationStats {
	sip.mutex.RLock()
	defer sip.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &SecurityIntegrationStats{
		TotalRequests:          sip.stats.TotalRequests,
		SecurityChecks:         sip.stats.SecurityChecks,
		ThreatsBlocked:         sip.stats.ThreatsBlocked,
		HTTPSEnforced:          sip.stats.HTTPSEnforced,
		CSRFBlocked:            sip.stats.CSRFBlocked,
		CORSBlocked:            sip.stats.CORSBlocked,
		SecurityHeadersAdded:   sip.stats.SecurityHeadersAdded,
		AuthenticationRequired: sip.stats.AuthenticationRequired,
	}
}

// NewSecurityPlugin creates a comprehensive security plugin
func NewSecurityPlugin(securityConfig *SecurityConfig, integrationConfig *SecurityIntegrationConfig) *SecurityPlugin {
	securityManager := NewSecurityManager(securityConfig)
	integrationPlugin := NewSecurityIntegrationPlugin(securityManager, integrationConfig)

	return &SecurityPlugin{
		SecurityIntegrationPlugin: integrationPlugin,
	}
}

// SecurityPluginFactory creates security plugins with different configurations
type SecurityPluginFactory struct{}

// CreateBasicSecurityPlugin creates a basic security plugin
func (spf *SecurityPluginFactory) CreateBasicSecurityPlugin() *SecurityPlugin {
	securityConfig := &SecurityConfig{
		Enabled: true,
		ValidationConfig: &ValidationConfig{
			Enabled:        true,
			MaxRequestSize: 1024 * 1024, // 1MB
		},
		RateLimitConfig: &RateLimitConfig{
			Enabled: true,
			GlobalLimit: &RateLimitRule{
				RequestsPerSecond: 100,
				BurstSize:         10,
			},
		},
	}

	integrationConfig := &SecurityIntegrationConfig{
		Enabled:        true,
		EnforceHTTPS:   false,
		CSRFProtection: false,
		SecurityHeaders: &SecurityHeadersConfig{
			Enabled:             true,
			XContentTypeOptions: "nosniff",
			XFrameOptions:       "SAMEORIGIN",
		},
	}

	return NewSecurityPlugin(securityConfig, integrationConfig)
}

// CreateProductionSecurityPlugin creates a production-grade security plugin
func (spf *SecurityPluginFactory) CreateProductionSecurityPlugin() *SecurityPlugin {
	return NewSecurityPlugin(DefaultSecurityConfig(), DefaultSecurityIntegrationConfig())
}

// CreateCustomSecurityPlugin creates a custom security plugin
func (spf *SecurityPluginFactory) CreateCustomSecurityPlugin(securityConfig *SecurityConfig, integrationConfig *SecurityIntegrationConfig) *SecurityPlugin {
	return NewSecurityPlugin(securityConfig, integrationConfig)
}
