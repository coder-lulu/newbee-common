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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest"
)

// HTTPAdapter provides seamless integration with go-zero REST framework
type HTTPAdapter struct {
	framework FrameworkCore
	config    *HTTPAdapterConfig
	logger    logx.Logger
}

// HTTPAdapterConfig defines configuration for HTTP adapter
type HTTPAdapterConfig struct {
	// Request processing
	MaxBodySize     int64         `json:"max_body_size" yaml:"max_body_size"`       // Maximum request body size (bytes)
	RequestTimeout  time.Duration `json:"request_timeout" yaml:"request_timeout"`   // Request processing timeout
	EnableBuffering bool          `json:"enable_buffering" yaml:"enable_buffering"` // Enable request/response buffering
	BufferSize      int           `json:"buffer_size" yaml:"buffer_size"`           // Buffer size for streaming

	// Framework integration
	EnableFramework bool     `json:"enable_framework" yaml:"enable_framework"` // Enable framework processing
	SkipPaths       []string `json:"skip_paths" yaml:"skip_paths"`             // Paths to skip framework processing
	SkipMethods     []string `json:"skip_methods" yaml:"skip_methods"`         // HTTP methods to skip

	// Error handling
	HandlePanics       bool `json:"handle_panics" yaml:"handle_panics"`               // Enable panic recovery
	ReturnErrorDetails bool `json:"return_error_details" yaml:"return_error_details"` // Include error details in response

	// Headers
	PreserveHeaders []string          `json:"preserve_headers" yaml:"preserve_headers"` // Headers to preserve from original request
	AddHeaders      map[string]string `json:"add_headers" yaml:"add_headers"`           // Headers to add to framework request

	// Performance
	EnablePooling bool        `json:"enable_pooling" yaml:"enable_pooling"` // Enable object pooling
	PoolConfig    *PoolConfig `json:"pool_config" yaml:"pool_config"`       // Pool configuration
}

// PoolConfig defines object pool settings
type PoolConfig struct {
	RequestPoolSize  int `json:"request_pool_size" yaml:"request_pool_size"`   // Request pool size
	ResponsePoolSize int `json:"response_pool_size" yaml:"response_pool_size"` // Response pool size
	BufferPoolSize   int `json:"buffer_pool_size" yaml:"buffer_pool_size"`     // Buffer pool size
}

// NewHTTPAdapter creates a new HTTP adapter
func NewHTTPAdapter(framework FrameworkCore, config *HTTPAdapterConfig) *HTTPAdapter {
	if config == nil {
		config = DefaultHTTPAdapterConfig()
	}

	return &HTTPAdapter{
		framework: framework,
		config:    config,
		logger:    logx.WithContext(context.Background()),
	}
}

// DefaultHTTPAdapterConfig returns default configuration
func DefaultHTTPAdapterConfig() *HTTPAdapterConfig {
	return &HTTPAdapterConfig{
		MaxBodySize:        10 * 1024 * 1024, // 10MB
		RequestTimeout:     30 * time.Second,
		EnableBuffering:    true,
		BufferSize:         64 * 1024, // 64KB
		EnableFramework:    true,
		SkipPaths:          []string{"/health", "/metrics", "/ping"},
		SkipMethods:        []string{"OPTIONS"},
		HandlePanics:       true,
		ReturnErrorDetails: false,
		PreserveHeaders:    []string{"Authorization", "Content-Type", "Accept", "User-Agent"},
		AddHeaders:         make(map[string]string),
		EnablePooling:      true,
		PoolConfig: &PoolConfig{
			RequestPoolSize:  1000,
			ResponsePoolSize: 1000,
			BufferPoolSize:   500,
		},
	}
}

// Middleware returns a go-zero compatible middleware function
func (ha *HTTPAdapter) Middleware() rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return ha.handleHTTPRequest(next)
	}
}

// MiddlewareFunc returns a standard HTTP middleware function
func (ha *HTTPAdapter) MiddlewareFunc() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(ha.handleHTTPRequest(next.ServeHTTP))
	}
}

// handleHTTPRequest processes HTTP requests through the framework
func (ha *HTTPAdapter) handleHTTPRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Add panic recovery if enabled
		if ha.config.HandlePanics {
			defer ha.recoverPanic(w, r)
		}

		// Check if request should be skipped
		if ha.shouldSkipRequest(r) {
			next(w, r)
			return
		}

		// Check if framework is enabled
		if !ha.config.EnableFramework {
			next(w, r)
			return
		}

		// Check if framework is running
		if !ha.framework.IsRunning() {
			ha.logger.Error("Framework is not running, skipping request processing")
			next(w, r)
			return
		}

		// Create context with timeout
		ctx := r.Context()
		if ha.config.RequestTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, ha.config.RequestTimeout)
			defer cancel()
		}

		// Convert HTTP request to framework request
		frameworkReq, err := ha.convertHTTPToFrameworkRequest(r)
		if err != nil {
			ha.handleError(w, r, fmt.Errorf("failed to convert request: %w", err))
			return
		}

		// Process request through framework
		frameworkResp, err := ha.framework.ProcessRequest(ctx, frameworkReq)
		if err != nil {
			// If framework processing fails, fall back to original handler
			ha.logger.Errorf("Framework processing failed: %v", err)
			if ha.config.ReturnErrorDetails {
				ha.handleError(w, r, err)
				return
			}
			next(w, r)
			return
		}

		// Convert framework response to HTTP response
		if frameworkResp != nil {
			err = ha.convertFrameworkResponseToHTTP(w, frameworkResp)
			if err != nil {
				ha.logger.Errorf("Failed to convert framework response: %v", err)
				ha.handleError(w, r, err)
				return
			}
		} else {
			// No framework response, continue with original handler
			next(w, r)
		}
	}
}

// convertHTTPToFrameworkRequest converts http.Request to framework Request
func (ha *HTTPAdapter) convertHTTPToFrameworkRequest(r *http.Request) (*Request, error) {
	// Use object pool if enabled and available
	var req *Request
	if ha.config.EnablePooling && GlobalPoolManager != nil && GlobalPoolManager.IsEnabled() {
		req = GlobalPoolManager.GetRequest()
	} else {
		req = &Request{
			Headers: make(map[string][]string),
			Context: make(map[string]interface{}),
		}
	}

	// Basic request information
	req.ID = generateHTTPRequestID()
	req.Method = r.Method
	req.Path = r.URL.Path
	req.RemoteAddr = getClientIP(r)
	req.UserAgent = r.Header.Get("User-Agent")
	req.ContentType = r.Header.Get("Content-Type")
	req.Timestamp = time.Now()

	// Copy headers
	for key, values := range r.Header {
		if ha.shouldPreserveHeader(key) {
			req.Headers[key] = values
		}
	}

	// Add custom headers
	for key, value := range ha.config.AddHeaders {
		req.Headers[key] = []string{value}
	}

	// Read body if present
	if r.Body != nil && r.ContentLength > 0 {
		if r.ContentLength > ha.config.MaxBodySize {
			return nil, fmt.Errorf("request body too large: %d bytes (max: %d)", r.ContentLength, ha.config.MaxBodySize)
		}

		body, err := ha.readRequestBody(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = body
	}

	// Extract context information
	ha.extractContextInfo(req, r)

	return req, nil
}

// convertFrameworkResponseToHTTP converts framework Response to HTTP response
func (ha *HTTPAdapter) convertFrameworkResponseToHTTP(w http.ResponseWriter, resp *Response) error {
	// Set headers
	for key, values := range resp.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	if resp.StatusCode > 0 {
		w.WriteHeader(resp.StatusCode)
	}

	// Write body
	if len(resp.Body) > 0 {
		_, err := w.Write(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to write response body: %w", err)
		}
	}

	return nil
}

// readRequestBody reads and buffers request body
func (ha *HTTPAdapter) readRequestBody(r *http.Request) ([]byte, error) {
	if !ha.config.EnableBuffering {
		// Simple read without buffering
		return io.ReadAll(r.Body)
	}

	// Use buffer pool if available
	var buf *bytes.Buffer
	if ha.config.EnablePooling && GlobalPoolManager != nil && GlobalPoolManager.IsEnabled() {
		poolBuf := GlobalPoolManager.GetBuffer()
		defer GlobalPoolManager.PutBuffer(poolBuf)
		buf = bytes.NewBuffer(poolBuf.Bytes()[:0])
	} else {
		buf = bytes.NewBuffer(make([]byte, 0, ha.config.BufferSize))
	}

	// Copy body to buffer
	_, err := io.CopyN(buf, r.Body, ha.config.MaxBodySize)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Replace request body with buffered version for potential re-reading
	bodyBytes := buf.Bytes()
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return bodyBytes, nil
}

// shouldSkipRequest determines if request should skip framework processing
func (ha *HTTPAdapter) shouldSkipRequest(r *http.Request) bool {
	// Check skip paths
	for _, skipPath := range ha.config.SkipPaths {
		if strings.HasPrefix(r.URL.Path, skipPath) {
			return true
		}
	}

	// Check skip methods
	for _, skipMethod := range ha.config.SkipMethods {
		if r.Method == skipMethod {
			return true
		}
	}

	return false
}

// shouldPreserveHeader determines if header should be preserved
func (ha *HTTPAdapter) shouldPreserveHeader(headerName string) bool {
	lowerName := strings.ToLower(headerName)

	for _, preserveHeader := range ha.config.PreserveHeaders {
		if strings.ToLower(preserveHeader) == lowerName {
			return true
		}
	}

	return false
}

// extractContextInfo extracts context information from HTTP request
func (ha *HTTPAdapter) extractContextInfo(req *Request, r *http.Request) {
	// Extract user ID from header or context
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		req.Context["user_id"] = userID
	}

	// Extract tenant ID from header
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		req.Context["tenant_id"] = tenantID
	}

	// Extract request ID from header
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		req.Context["request_id"] = requestID
	}

	// Extract trace ID for distributed tracing
	if traceID := r.Header.Get("X-Trace-ID"); traceID != "" {
		req.Context["trace_id"] = traceID
	}

	// Add HTTP-specific context
	req.Context["http_method"] = r.Method
	req.Context["http_path"] = r.URL.Path
	req.Context["http_query"] = r.URL.RawQuery
	req.Context["http_host"] = r.Host
	req.Context["http_scheme"] = getScheme(r)
}

// recoverPanic handles panics during request processing
func (ha *HTTPAdapter) recoverPanic(w http.ResponseWriter, r *http.Request) {
	if recovered := recover(); recovered != nil {
		ha.logger.Errorf("Panic recovered during request processing: %v", recovered)

		// Return 500 error
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleError handles errors during request processing
func (ha *HTTPAdapter) handleError(w http.ResponseWriter, r *http.Request, err error) {
	ha.logger.Errorf("HTTP adapter error: %v", err)

	statusCode := http.StatusInternalServerError
	message := "Internal Server Error"

	if ha.config.ReturnErrorDetails {
		message = err.Error()
	}

	http.Error(w, message, statusCode)
}

// Utility functions

// generateHTTPRequestID generates a unique request ID for HTTP adapter
func generateHTTPRequestID() string {
	return fmt.Sprintf("http_req_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000000)
}

// getClientIP extracts client IP address from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 {
		return ip[0]
	}

	return r.RemoteAddr
}

// getScheme determines HTTP scheme (http/https)
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}

	return "http"
}

// HTTPAdapterMiddleware creates a middleware that integrates framework with go-zero
func HTTPAdapterMiddleware(framework FrameworkCore, config *HTTPAdapterConfig) rest.Middleware {
	adapter := NewHTTPAdapter(framework, config)
	return adapter.Middleware()
}

// HTTPAdapterMiddlewareFunc creates a standard HTTP middleware function
func HTTPAdapterMiddlewareFunc(framework FrameworkCore, config *HTTPAdapterConfig) func(http.Handler) http.Handler {
	adapter := NewHTTPAdapter(framework, config)
	return adapter.MiddlewareFunc()
}

// GoZeroIntegration provides helper functions for go-zero integration
type GoZeroIntegration struct {
	framework FrameworkCore
	adapter   *HTTPAdapter
}

// NewGoZeroIntegration creates a new go-zero integration helper
func NewGoZeroIntegration(framework FrameworkCore, config *HTTPAdapterConfig) *GoZeroIntegration {
	return &GoZeroIntegration{
		framework: framework,
		adapter:   NewHTTPAdapter(framework, config),
	}
}

// RegisterMiddleware registers the adapter as a global middleware in go-zero server
func (gzi *GoZeroIntegration) RegisterMiddleware(server *rest.Server) {
	server.Use(gzi.adapter.Middleware())
}

// CreateHandler creates an HTTP handler that processes requests through the framework
func (gzi *GoZeroIntegration) CreateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create framework request
		frameworkReq, err := gzi.adapter.convertHTTPToFrameworkRequest(r)
		if err != nil {
			gzi.adapter.handleError(w, r, err)
			return
		}

		// Process through framework
		resp, err := gzi.framework.ProcessRequest(r.Context(), frameworkReq)
		if err != nil {
			gzi.adapter.handleError(w, r, err)
			return
		}

		// Convert and send response
		if resp != nil {
			err = gzi.adapter.convertFrameworkResponseToHTTP(w, resp)
			if err != nil {
				gzi.adapter.handleError(w, r, err)
				return
			}
		}
	}
}

// GetFramework returns the underlying framework instance
func (gzi *GoZeroIntegration) GetFramework() FrameworkCore {
	return gzi.framework
}

// GetAdapter returns the HTTP adapter instance
func (gzi *GoZeroIntegration) GetAdapter() *HTTPAdapter {
	return gzi.adapter
}

// UpdateConfig updates the adapter configuration
func (gzi *GoZeroIntegration) UpdateConfig(config *HTTPAdapterConfig) {
	gzi.adapter.config = config
}

// Stats returns adapter statistics
func (ha *HTTPAdapter) Stats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["config"] = map[string]interface{}{
		"max_body_size":    ha.config.MaxBodySize,
		"request_timeout":  ha.config.RequestTimeout.String(),
		"enable_framework": ha.config.EnableFramework,
		"enable_pooling":   ha.config.EnablePooling,
		"enable_buffering": ha.config.EnableBuffering,
		"handle_panics":    ha.config.HandlePanics,
	}

	stats["skip_paths"] = ha.config.SkipPaths
	stats["skip_methods"] = ha.config.SkipMethods
	stats["preserve_headers"] = ha.config.PreserveHeaders

	if ha.config.EnablePooling && GlobalPoolManager != nil {
		stats["pool_stats"] = map[string]interface{}{
			"enabled":  GlobalPoolManager.IsEnabled(),
			"requests": "pool_manager_active",
		}
	}

	return stats
}
