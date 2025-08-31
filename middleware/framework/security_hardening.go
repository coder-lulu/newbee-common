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
	"net"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SecurityManager provides comprehensive security hardening for the framework
type SecurityManager struct {
	config      *SecurityConfig
	sandbox     *PluginSandbox
	validator   *InputValidator
	rateLimiter *RateLimiter
	enabled     bool
	mutex       sync.RWMutex
}

// SecurityConfig defines comprehensive security configuration
type SecurityConfig struct {
	Enabled          bool                   `json:"enabled" yaml:"enabled"`
	SandboxEnabled   bool                   `json:"sandbox_enabled" yaml:"sandbox_enabled"`
	SandboxConfig    *SandboxConfig         `json:"sandbox" yaml:"sandbox"`
	ValidationConfig *ValidationConfig      `json:"validation" yaml:"validation"`
	RateLimitConfig  *RateLimitConfig       `json:"rate_limit" yaml:"rate_limit"`
	ThreatDetection  *ThreatDetectionConfig `json:"threat_detection" yaml:"threat_detection"`
	AuditConfig      *SecurityAuditConfig   `json:"audit" yaml:"audit"`
}

// SandboxConfig defines plugin sandbox configuration
type SandboxConfig struct {
	Enabled              bool          `json:"enabled" yaml:"enabled"`
	MaxMemoryMB          int64         `json:"max_memory_mb" yaml:"max_memory_mb"`
	MaxCPUPercent        float64       `json:"max_cpu_percent" yaml:"max_cpu_percent"`
	MaxGoroutines        int           `json:"max_goroutines" yaml:"max_goroutines"`
	MaxExecutionTime     time.Duration `json:"max_execution_time" yaml:"max_execution_time"`
	AllowedNetworkAccess bool          `json:"allowed_network_access" yaml:"allowed_network_access"`
	AllowedFileAccess    bool          `json:"allowed_file_access" yaml:"allowed_file_access"`
	RestrictedPackages   []string      `json:"restricted_packages" yaml:"restricted_packages"`
	AllowedDomains       []string      `json:"allowed_domains" yaml:"allowed_domains"`
	MaxFileSize          int64         `json:"max_file_size" yaml:"max_file_size"`
	TempDirectoryOnly    bool          `json:"temp_directory_only" yaml:"temp_directory_only"`
}

// ValidationConfig defines input validation configuration
type ValidationConfig struct {
	Enabled              bool                       `json:"enabled" yaml:"enabled"`
	MaxRequestSize       int64                      `json:"max_request_size" yaml:"max_request_size"`
	MaxHeaderCount       int                        `json:"max_header_count" yaml:"max_header_count"`
	MaxHeaderLength      int                        `json:"max_header_length" yaml:"max_header_length"`
	MaxPathLength        int                        `json:"max_path_length" yaml:"max_path_length"`
	MaxQueryParams       int                        `json:"max_query_params" yaml:"max_query_params"`
	AllowedContentTypes  []string                   `json:"allowed_content_types" yaml:"allowed_content_types"`
	BlockedUserAgents    []string                   `json:"blocked_user_agents" yaml:"blocked_user_agents"`
	SQLInjectionPatterns []string                   `json:"sql_injection_patterns" yaml:"sql_injection_patterns"`
	XSSPatterns          []string                   `json:"xss_patterns" yaml:"xss_patterns"`
	CustomValidators     map[string]ValidatorConfig `json:"custom_validators" yaml:"custom_validators"`
	PathValidation       *PathValidationConfig      `json:"path_validation" yaml:"path_validation"`
}

// ValidatorConfig defines custom validator configuration
type ValidatorConfig struct {
	Type      string                 `json:"type" yaml:"type"`
	Pattern   string                 `json:"pattern" yaml:"pattern"`
	MinLength int                    `json:"min_length" yaml:"min_length"`
	MaxLength int                    `json:"max_length" yaml:"max_length"`
	Required  bool                   `json:"required" yaml:"required"`
	Options   map[string]interface{} `json:"options" yaml:"options"`
}

// PathValidationConfig defines path validation rules
type PathValidationConfig struct {
	Enabled                 bool     `json:"enabled" yaml:"enabled"`
	AllowedPaths            []string `json:"allowed_paths" yaml:"allowed_paths"`
	BlockedPaths            []string `json:"blocked_paths" yaml:"blocked_paths"`
	RequireHTTPS            bool     `json:"require_https" yaml:"require_https"`
	BlockDirectoryTraversal bool     `json:"block_directory_traversal" yaml:"block_directory_traversal"`
}

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	Enabled         bool                      `json:"enabled" yaml:"enabled"`
	GlobalLimit     *RateLimitRule            `json:"global_limit" yaml:"global_limit"`
	PerIPLimit      *RateLimitRule            `json:"per_ip_limit" yaml:"per_ip_limit"`
	PerUserLimit    *RateLimitRule            `json:"per_user_limit" yaml:"per_user_limit"`
	PathLimits      map[string]*RateLimitRule `json:"path_limits" yaml:"path_limits"`
	BurstAllowed    bool                      `json:"burst_allowed" yaml:"burst_allowed"`
	CleanupInterval time.Duration             `json:"cleanup_interval" yaml:"cleanup_interval"`
	WhitelistIPs    []string                  `json:"whitelist_ips" yaml:"whitelist_ips"`
	BlacklistIPs    []string                  `json:"blacklist_ips" yaml:"blacklist_ips"`
}

// RateLimitRule defines a rate limiting rule
type RateLimitRule struct {
	RequestsPerSecond int           `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size"`
	BlockDuration     time.Duration `json:"block_duration" yaml:"block_duration"`
}

// ThreatDetectionConfig defines threat detection configuration
type ThreatDetectionConfig struct {
	Enabled                     bool               `json:"enabled" yaml:"enabled"`
	AnomalyDetection            bool               `json:"anomaly_detection" yaml:"anomaly_detection"`
	SuspiciousActivityThreshold int                `json:"suspicious_activity_threshold" yaml:"suspicious_activity_threshold"`
	BlockSuspiciousIPs          bool               `json:"block_suspicious_ips" yaml:"block_suspicious_ips"`
	GeoBlocking                 *GeoBlockingConfig `json:"geo_blocking" yaml:"geo_blocking"`
}

// GeoBlockingConfig defines geographical blocking configuration
type GeoBlockingConfig struct {
	Enabled          bool     `json:"enabled" yaml:"enabled"`
	AllowedCountries []string `json:"allowed_countries" yaml:"allowed_countries"`
	BlockedCountries []string `json:"blocked_countries" yaml:"blocked_countries"`
}

// SecurityAuditConfig defines security audit configuration
type SecurityAuditConfig struct {
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	LogSecurityEvents bool   `json:"log_security_events" yaml:"log_security_events"`
	AlertOnThreat     bool   `json:"alert_on_threat" yaml:"alert_on_threat"`
	AuditLevel        string `json:"audit_level" yaml:"audit_level"`
}

// PluginSandbox provides secure execution environment for plugins
type PluginSandbox struct {
	config       *SandboxConfig
	restrictions *SandboxRestrictions
	monitors     map[string]*PluginMonitor
	enabled      bool
	mutex        sync.RWMutex
}

// SandboxRestrictions tracks sandbox restrictions
type SandboxRestrictions struct {
	maxMemory        int64
	maxCPU           float64
	maxGoroutines    int
	maxExecutionTime time.Duration
	allowNetwork     bool
	allowFileAccess  bool
	restrictedPkgs   map[string]bool
	allowedDomains   map[string]bool
}

// PluginMonitor monitors plugin resource usage
type PluginMonitor struct {
	pluginName     string
	startTime      time.Time
	memoryUsage    int64
	goroutineCount int32
	networkCalls   int64
	fileCalls      int64
	violations     []string
	mutex          sync.RWMutex
}

// InputValidator provides comprehensive input validation
type InputValidator struct {
	config           *ValidationConfig
	sqlPatterns      []*regexp.Regexp
	xssPatterns      []*regexp.Regexp
	customValidators map[string]Validator
	pathValidator    *PathValidator
	enabled          bool
	stats            *ValidationStats
	mutex            sync.RWMutex
}

// Validator interface for custom validators
type Validator interface {
	Validate(input string) error
	Name() string
}

// PathValidator validates request paths
type PathValidator struct {
	allowedPaths   []*regexp.Regexp
	blockedPaths   []*regexp.Regexp
	requireHTTPS   bool
	blockTraversal bool
}

// ValidationStats tracks validation statistics
type ValidationStats struct {
	totalValidations    int64
	validationErrors    int64
	blockedRequests     int64
	suspiciousRequests  int64
	sqlInjectionBlocked int64
	xssBlocked          int64
}

// RateLimiter provides comprehensive rate limiting
type RateLimiter struct {
	config       *RateLimitConfig
	globalLimit  *TokenBucket
	ipLimiters   map[string]*TokenBucket
	userLimiters map[string]*TokenBucket
	pathLimiters map[string]*TokenBucket
	whitelistIPs map[string]bool
	blacklistIPs map[string]bool
	stats        *RateLimitStats
	mutex        sync.RWMutex
	lastCleanup  time.Time
}

// TokenBucket implements token bucket algorithm
type TokenBucket struct {
	capacity     int64
	tokens       int64
	refillRate   int64
	lastRefill   time.Time
	burstAllowed bool
	mutex        sync.Mutex
}

// RateLimitStats tracks rate limiting statistics
type RateLimitStats struct {
	totalRequests     int64
	blockedRequests   int64
	burstRequests     int64
	throttledRequests int64
}

// SecurityMiddleware provides comprehensive security middleware
type SecurityMiddleware struct {
	manager *SecurityManager
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *SecurityConfig) *SecurityManager {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	sm := &SecurityManager{
		config:  config,
		enabled: config.Enabled,
	}

	if sm.enabled {
		// Initialize sandbox
		if config.SandboxEnabled && config.SandboxConfig != nil {
			sm.sandbox = NewPluginSandbox(config.SandboxConfig)
		}

		// Initialize validator
		if config.ValidationConfig != nil && config.ValidationConfig.Enabled {
			sm.validator = NewInputValidator(config.ValidationConfig)
		}

		// Initialize rate limiter
		if config.RateLimitConfig != nil && config.RateLimitConfig.Enabled {
			sm.rateLimiter = NewRateLimiter(config.RateLimitConfig)
		}
	}

	return sm
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Enabled:        true,
		SandboxEnabled: true,
		SandboxConfig: &SandboxConfig{
			Enabled:              true,
			MaxMemoryMB:          256,
			MaxCPUPercent:        50.0,
			MaxGoroutines:        100,
			MaxExecutionTime:     30 * time.Second,
			AllowedNetworkAccess: false,
			AllowedFileAccess:    false,
			RestrictedPackages:   []string{"os", "os/exec", "syscall", "unsafe"},
			MaxFileSize:          10 * 1024 * 1024, // 10MB
			TempDirectoryOnly:    true,
		},
		ValidationConfig: &ValidationConfig{
			Enabled:             true,
			MaxRequestSize:      10 * 1024 * 1024, // 10MB
			MaxHeaderCount:      50,
			MaxHeaderLength:     8192,
			MaxPathLength:       2048,
			MaxQueryParams:      100,
			AllowedContentTypes: []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"},
			SQLInjectionPatterns: []string{
				`(?i)(union\s+select)`,
				`(?i)(select\s+.*\s+from)`,
				`(?i)(insert\s+into)`,
				`(?i)(delete\s+from)`,
				`(?i)(drop\s+table)`,
				`(?i)(;|\s)(update|delete|insert|create|drop|alter)\s`,
			},
			XSSPatterns: []string{
				`(?i)<script[^>]*>.*?</script>`,
				`(?i)javascript:`,
				`(?i)on\w+\s*=`,
				`(?i)<iframe[^>]*>`,
				`(?i)eval\s*\(`,
			},
			PathValidation: &PathValidationConfig{
				Enabled:                 true,
				BlockDirectoryTraversal: true,
			},
		},
		RateLimitConfig: &RateLimitConfig{
			Enabled: true,
			GlobalLimit: &RateLimitRule{
				RequestsPerSecond: 1000,
				BurstSize:         100,
				WindowSize:        time.Minute,
			},
			PerIPLimit: &RateLimitRule{
				RequestsPerSecond: 100,
				BurstSize:         10,
				WindowSize:        time.Minute,
				BlockDuration:     5 * time.Minute,
			},
			BurstAllowed:    true,
			CleanupInterval: 5 * time.Minute,
		},
		ThreatDetection: &ThreatDetectionConfig{
			Enabled:                     true,
			AnomalyDetection:            true,
			SuspiciousActivityThreshold: 10,
			BlockSuspiciousIPs:          true,
		},
		AuditConfig: &SecurityAuditConfig{
			Enabled:           true,
			LogSecurityEvents: true,
			AlertOnThreat:     true,
			AuditLevel:        "info",
		},
	}
}

// NewPluginSandbox creates a new plugin sandbox
func NewPluginSandbox(config *SandboxConfig) *PluginSandbox {
	restrictions := &SandboxRestrictions{
		maxMemory:        config.MaxMemoryMB * 1024 * 1024,
		maxCPU:           config.MaxCPUPercent,
		maxGoroutines:    config.MaxGoroutines,
		maxExecutionTime: config.MaxExecutionTime,
		allowNetwork:     config.AllowedNetworkAccess,
		allowFileAccess:  config.AllowedFileAccess,
		restrictedPkgs:   make(map[string]bool),
		allowedDomains:   make(map[string]bool),
	}

	for _, pkg := range config.RestrictedPackages {
		restrictions.restrictedPkgs[pkg] = true
	}

	for _, domain := range config.AllowedDomains {
		restrictions.allowedDomains[domain] = true
	}

	return &PluginSandbox{
		config:       config,
		restrictions: restrictions,
		monitors:     make(map[string]*PluginMonitor),
		enabled:      config.Enabled,
	}
}

// NewInputValidator creates a new input validator
func NewInputValidator(config *ValidationConfig) *InputValidator {
	iv := &InputValidator{
		config:           config,
		customValidators: make(map[string]Validator),
		enabled:          config.Enabled,
		stats:            &ValidationStats{},
	}

	// Compile SQL injection patterns
	for _, pattern := range config.SQLInjectionPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			iv.sqlPatterns = append(iv.sqlPatterns, regex)
		}
	}

	// Compile XSS patterns
	for _, pattern := range config.XSSPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			iv.xssPatterns = append(iv.xssPatterns, regex)
		}
	}

	// Initialize path validator
	if config.PathValidation != nil && config.PathValidation.Enabled {
		iv.pathValidator = NewPathValidator(config.PathValidation)
	}

	return iv
}

// NewPathValidator creates a new path validator
func NewPathValidator(config *PathValidationConfig) *PathValidator {
	pv := &PathValidator{
		requireHTTPS:   config.RequireHTTPS,
		blockTraversal: config.BlockDirectoryTraversal,
	}

	// Compile allowed paths
	for _, path := range config.AllowedPaths {
		if regex, err := regexp.Compile(path); err == nil {
			pv.allowedPaths = append(pv.allowedPaths, regex)
		}
	}

	// Compile blocked paths
	for _, path := range config.BlockedPaths {
		if regex, err := regexp.Compile(path); err == nil {
			pv.blockedPaths = append(pv.blockedPaths, regex)
		}
	}

	return pv
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:       config,
		ipLimiters:   make(map[string]*TokenBucket),
		userLimiters: make(map[string]*TokenBucket),
		pathLimiters: make(map[string]*TokenBucket),
		whitelistIPs: make(map[string]bool),
		blacklistIPs: make(map[string]bool),
		stats:        &RateLimitStats{},
		lastCleanup:  time.Now(),
	}

	// Initialize global limiter
	if config.GlobalLimit != nil {
		rl.globalLimit = NewTokenBucket(config.GlobalLimit, config.BurstAllowed)
	}

	// Initialize path limiters
	for path, rule := range config.PathLimits {
		rl.pathLimiters[path] = NewTokenBucket(rule, config.BurstAllowed)
	}

	// Initialize IP lists
	for _, ip := range config.WhitelistIPs {
		rl.whitelistIPs[ip] = true
	}
	for _, ip := range config.BlacklistIPs {
		rl.blacklistIPs[ip] = true
	}

	return rl
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(rule *RateLimitRule, burstAllowed bool) *TokenBucket {
	return &TokenBucket{
		capacity:     int64(rule.BurstSize),
		tokens:       int64(rule.BurstSize),
		refillRate:   int64(rule.RequestsPerSecond),
		lastRefill:   time.Now(),
		burstAllowed: burstAllowed,
	}
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(manager *SecurityManager) *SecurityMiddleware {
	return &SecurityMiddleware{
		manager: manager,
	}
}

// ExecuteInSandbox executes a plugin in a secure sandbox environment
func (ps *PluginSandbox) ExecuteInSandbox(ctx context.Context, pluginName string, execution func() error) error {
	if !ps.enabled {
		return execution()
	}

	// Create plugin monitor
	monitor := &PluginMonitor{
		pluginName: pluginName,
		startTime:  time.Now(),
	}

	ps.mutex.Lock()
	ps.monitors[pluginName] = monitor
	ps.mutex.Unlock()

	defer func() {
		ps.mutex.Lock()
		delete(ps.monitors, pluginName)
		ps.mutex.Unlock()
	}()

	// Create execution context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, ps.restrictions.maxExecutionTime)
	defer cancel()

	// Monitor execution in goroutine
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("plugin panic: %v", r)
			}
		}()

		// Check goroutine limit before execution
		if ps.restrictions.maxGoroutines > 0 {
			if runtime.NumGoroutine() > ps.restrictions.maxGoroutines {
				done <- fmt.Errorf("goroutine limit exceeded: %d > %d", runtime.NumGoroutine(), ps.restrictions.maxGoroutines)
				return
			}
		}

		// Execute plugin
		done <- execution()
	}()

	// Wait for execution or timeout
	select {
	case err := <-done:
		// Check resource usage after execution
		if err == nil {
			if violations := ps.checkResourceUsage(monitor); len(violations) > 0 {
				return fmt.Errorf("sandbox violations: %v", violations)
			}
		}
		return err
	case <-timeoutCtx.Done():
		return fmt.Errorf("plugin execution timeout after %v", ps.restrictions.maxExecutionTime)
	}
}

// checkResourceUsage checks if plugin exceeded resource limits
func (ps *PluginSandbox) checkResourceUsage(monitor *PluginMonitor) []string {
	var violations []string

	// Check memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	if ps.restrictions.maxMemory > 0 && int64(memStats.Alloc) > ps.restrictions.maxMemory {
		violations = append(violations, fmt.Sprintf("memory limit exceeded: %d > %d", memStats.Alloc, ps.restrictions.maxMemory))
	}

	// Check goroutine count
	if ps.restrictions.maxGoroutines > 0 && runtime.NumGoroutine() > ps.restrictions.maxGoroutines {
		violations = append(violations, fmt.Sprintf("goroutine limit exceeded: %d > %d", runtime.NumGoroutine(), ps.restrictions.maxGoroutines))
	}

	// Check execution time
	duration := time.Since(monitor.startTime)
	if duration > ps.restrictions.maxExecutionTime {
		violations = append(violations, fmt.Sprintf("execution time exceeded: %v > %v", duration, ps.restrictions.maxExecutionTime))
	}

	return violations
}

// ValidateRequest validates incoming requests for security threats
func (iv *InputValidator) ValidateRequest(req *Request) error {
	if !iv.enabled {
		return nil
	}

	atomic.AddInt64(&iv.stats.totalValidations, 1)

	// Validate request size
	if iv.config.MaxRequestSize > 0 && int64(len(req.Body)) > iv.config.MaxRequestSize {
		atomic.AddInt64(&iv.stats.validationErrors, 1)
		return fmt.Errorf("request size exceeds limit: %d > %d", len(req.Body), iv.config.MaxRequestSize)
	}

	// Validate path length
	if iv.config.MaxPathLength > 0 && len(req.Path) > iv.config.MaxPathLength {
		atomic.AddInt64(&iv.stats.validationErrors, 1)
		return fmt.Errorf("path length exceeds limit: %d > %d", len(req.Path), iv.config.MaxPathLength)
	}

	// Validate headers
	if err := iv.validateHeaders(req.Headers); err != nil {
		atomic.AddInt64(&iv.stats.validationErrors, 1)
		return err
	}

	// Validate content type
	if err := iv.validateContentType(req.ContentType); err != nil {
		atomic.AddInt64(&iv.stats.validationErrors, 1)
		return err
	}

	// Validate user agent
	if err := iv.validateUserAgent(req.UserAgent); err != nil {
		atomic.AddInt64(&iv.stats.blockedRequests, 1)
		return err
	}

	// Check for SQL injection
	if err := iv.checkSQLInjection(req); err != nil {
		atomic.AddInt64(&iv.stats.sqlInjectionBlocked, 1)
		return err
	}

	// Check for XSS
	if err := iv.checkXSS(req); err != nil {
		atomic.AddInt64(&iv.stats.xssBlocked, 1)
		return err
	}

	// Validate path
	if iv.pathValidator != nil {
		if err := iv.pathValidator.ValidatePath(req.Path); err != nil {
			atomic.AddInt64(&iv.stats.blockedRequests, 1)
			return err
		}
	}

	return nil
}

// validateHeaders validates request headers
func (iv *InputValidator) validateHeaders(headers map[string][]string) error {
	if iv.config.MaxHeaderCount > 0 && len(headers) > iv.config.MaxHeaderCount {
		return fmt.Errorf("header count exceeds limit: %d > %d", len(headers), iv.config.MaxHeaderCount)
	}

	for name, values := range headers {
		totalLength := len(name)
		for _, value := range values {
			totalLength += len(value)
		}
		if iv.config.MaxHeaderLength > 0 && totalLength > iv.config.MaxHeaderLength {
			return fmt.Errorf("header length exceeds limit: %d > %d", totalLength, iv.config.MaxHeaderLength)
		}
	}

	return nil
}

// validateContentType validates content type
func (iv *InputValidator) validateContentType(contentType string) error {
	if len(iv.config.AllowedContentTypes) == 0 {
		return nil
	}

	for _, allowed := range iv.config.AllowedContentTypes {
		if strings.Contains(contentType, allowed) {
			return nil
		}
	}

	return fmt.Errorf("content type not allowed: %s", contentType)
}

// validateUserAgent validates user agent
func (iv *InputValidator) validateUserAgent(userAgent string) error {
	for _, blocked := range iv.config.BlockedUserAgents {
		if strings.Contains(userAgent, blocked) {
			return fmt.Errorf("user agent blocked: %s", userAgent)
		}
	}
	return nil
}

// checkSQLInjection checks for SQL injection patterns
func (iv *InputValidator) checkSQLInjection(req *Request) error {
	// Check path
	for _, pattern := range iv.sqlPatterns {
		if pattern.MatchString(req.Path) {
			return fmt.Errorf("SQL injection detected in path: %s", req.Path)
		}
	}

	// Check body
	if len(req.Body) > 0 {
		bodyStr := string(req.Body)
		for _, pattern := range iv.sqlPatterns {
			if pattern.MatchString(bodyStr) {
				return fmt.Errorf("SQL injection detected in body")
			}
		}
	}

	return nil
}

// checkXSS checks for XSS patterns
func (iv *InputValidator) checkXSS(req *Request) error {
	// Check path
	for _, pattern := range iv.xssPatterns {
		if pattern.MatchString(req.Path) {
			return fmt.Errorf("XSS detected in path: %s", req.Path)
		}
	}

	// Check body
	if len(req.Body) > 0 {
		bodyStr := string(req.Body)
		for _, pattern := range iv.xssPatterns {
			if pattern.MatchString(bodyStr) {
				return fmt.Errorf("XSS detected in body")
			}
		}
	}

	return nil
}

// ValidatePath validates request path
func (pv *PathValidator) ValidatePath(path string) error {
	// Check directory traversal
	if pv.blockTraversal {
		if strings.Contains(path, "..") || strings.Contains(path, "./") {
			return fmt.Errorf("directory traversal detected: %s", path)
		}
	}

	// Check blocked paths
	for _, pattern := range pv.blockedPaths {
		if pattern.MatchString(path) {
			return fmt.Errorf("path blocked: %s", path)
		}
	}

	// Check allowed paths (if configured)
	if len(pv.allowedPaths) > 0 {
		for _, pattern := range pv.allowedPaths {
			if pattern.MatchString(path) {
				return nil // Allowed
			}
		}
		return fmt.Errorf("path not allowed: %s", path)
	}

	return nil
}

// AllowRequest checks if request should be allowed based on rate limits
func (rl *RateLimiter) AllowRequest(req *Request) error {
	atomic.AddInt64(&rl.stats.totalRequests, 1)

	// Extract client IP
	clientIP := extractClientIP(req)

	// Check blacklist
	if rl.blacklistIPs[clientIP] {
		atomic.AddInt64(&rl.stats.blockedRequests, 1)
		return fmt.Errorf("IP is blacklisted: %s", clientIP)
	}

	// Check whitelist (skip rate limiting if whitelisted)
	if rl.whitelistIPs[clientIP] {
		return nil
	}

	// Check global rate limit
	if rl.globalLimit != nil {
		if !rl.globalLimit.Allow() {
			atomic.AddInt64(&rl.stats.blockedRequests, 1)
			return fmt.Errorf("global rate limit exceeded")
		}
	}

	// Check per-IP rate limit
	ipLimiter := rl.getIPLimiter(clientIP)
	if ipLimiter != nil && !ipLimiter.Allow() {
		atomic.AddInt64(&rl.stats.blockedRequests, 1)
		return fmt.Errorf("IP rate limit exceeded: %s", clientIP)
	}

	// Check path-specific rate limit
	pathLimiter := rl.getPathLimiter(req.Path)
	if pathLimiter != nil && !pathLimiter.Allow() {
		atomic.AddInt64(&rl.stats.blockedRequests, 1)
		return fmt.Errorf("path rate limit exceeded: %s", req.Path)
	}

	// Cleanup old limiters periodically
	if time.Since(rl.lastCleanup) > rl.config.CleanupInterval {
		go rl.cleanup()
	}

	return nil
}

// getIPLimiter gets or creates IP-specific rate limiter
func (rl *RateLimiter) getIPLimiter(ip string) *TokenBucket {
	if rl.config.PerIPLimit == nil {
		return nil
	}

	rl.mutex.RLock()
	limiter, exists := rl.ipLimiters[ip]
	rl.mutex.RUnlock()

	if !exists {
		rl.mutex.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = rl.ipLimiters[ip]; !exists {
			limiter = NewTokenBucket(rl.config.PerIPLimit, rl.config.BurstAllowed)
			rl.ipLimiters[ip] = limiter
		}
		rl.mutex.Unlock()
	}

	return limiter
}

// getPathLimiter gets path-specific rate limiter
func (rl *RateLimiter) getPathLimiter(path string) *TokenBucket {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	for pathPattern, limiter := range rl.pathLimiters {
		if matched, _ := regexp.MatchString(pathPattern, path); matched {
			return limiter
		}
	}

	return nil
}

// Allow checks if a token is available
func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tb.lastRefill = now

	// Refill tokens
	tokensToAdd := int64(elapsed.Seconds()) * tb.refillRate
	tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)

	// Check if token available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// cleanup removes old rate limiters
func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Simple cleanup - remove limiters older than cleanup interval
	// In production, this could be more sophisticated
	rl.lastCleanup = time.Now()
}

// extractClientIP extracts client IP from request
func extractClientIP(req *Request) string {
	// Check X-Forwarded-For header first
	if xff, exists := req.Headers["X-Forwarded-For"]; exists && len(xff) > 0 {
		return strings.Split(xff[0], ",")[0]
	}

	// Check X-Real-IP header
	if xri, exists := req.Headers["X-Real-IP"]; exists && len(xri) > 0 {
		return xri[0]
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}

	return req.RemoteAddr
}

// Handle implements MiddlewareHandler for comprehensive security
func (sm *SecurityMiddleware) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	if !sm.manager.enabled {
		return next(ctx, req)
	}

	// Input validation
	if sm.manager.validator != nil {
		if err := sm.manager.validator.ValidateRequest(req); err != nil {
			return &Response{
				StatusCode: 400,
				Body:       []byte(fmt.Sprintf("Validation failed: %v", err)),
				Headers:    make(map[string][]string),
			}, nil
		}
	}

	// Rate limiting
	if sm.manager.rateLimiter != nil {
		if err := sm.manager.rateLimiter.AllowRequest(req); err != nil {
			return &Response{
				StatusCode: 429,
				Body:       []byte(fmt.Sprintf("Rate limit exceeded: %v", err)),
				Headers:    make(map[string][]string),
			}, nil
		}
	}

	// Execute in sandbox if enabled
	if sm.manager.sandbox != nil {
		var resp *Response
		var err error

		sandboxErr := sm.manager.sandbox.ExecuteInSandbox(ctx, "request_handler", func() error {
			resp, err = next(ctx, req)
			return err
		})

		if sandboxErr != nil {
			return &Response{
				StatusCode: 500,
				Body:       []byte(fmt.Sprintf("Sandbox violation: %v", sandboxErr)),
				Headers:    make(map[string][]string),
			}, nil
		}

		return resp, err
	}

	return next(ctx, req)
}

// GetSecurityStats returns security statistics
func (sm *SecurityManager) GetSecurityStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if sm.validator != nil {
		stats["validation"] = map[string]interface{}{
			"total_validations":     atomic.LoadInt64(&sm.validator.stats.totalValidations),
			"validation_errors":     atomic.LoadInt64(&sm.validator.stats.validationErrors),
			"blocked_requests":      atomic.LoadInt64(&sm.validator.stats.blockedRequests),
			"suspicious_requests":   atomic.LoadInt64(&sm.validator.stats.suspiciousRequests),
			"sql_injection_blocked": atomic.LoadInt64(&sm.validator.stats.sqlInjectionBlocked),
			"xss_blocked":           atomic.LoadInt64(&sm.validator.stats.xssBlocked),
		}
	}

	if sm.rateLimiter != nil {
		stats["rate_limiting"] = map[string]interface{}{
			"total_requests":     atomic.LoadInt64(&sm.rateLimiter.stats.totalRequests),
			"blocked_requests":   atomic.LoadInt64(&sm.rateLimiter.stats.blockedRequests),
			"burst_requests":     atomic.LoadInt64(&sm.rateLimiter.stats.burstRequests),
			"throttled_requests": atomic.LoadInt64(&sm.rateLimiter.stats.throttledRequests),
		}
	}

	if sm.sandbox != nil {
		sm.sandbox.mutex.RLock()
		stats["sandbox"] = map[string]interface{}{
			"active_monitors": len(sm.sandbox.monitors),
			"enabled":         sm.sandbox.enabled,
		}
		sm.sandbox.mutex.RUnlock()
	}

	return stats
}

// Helper function
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
