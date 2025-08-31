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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPAdapter_DefaultConfig(t *testing.T) {
	config := DefaultHTTPAdapterConfig()

	if config.MaxBodySize != 10*1024*1024 {
		t.Errorf("Expected MaxBodySize = %d, got %d", 10*1024*1024, config.MaxBodySize)
	}

	if config.RequestTimeout != 30*time.Second {
		t.Errorf("Expected RequestTimeout = %v, got %v", 30*time.Second, config.RequestTimeout)
	}

	if !config.EnableFramework {
		t.Error("Expected EnableFramework = true")
	}

	if !config.HandlePanics {
		t.Error("Expected HandlePanics = true")
	}

	expectedSkipPaths := []string{"/health", "/metrics", "/ping"}
	if len(config.SkipPaths) != len(expectedSkipPaths) {
		t.Errorf("Expected %d skip paths, got %d", len(expectedSkipPaths), len(config.SkipPaths))
	}
}

func TestHTTPAdapter_Creation(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	// Test with default config
	adapter := NewHTTPAdapter(framework, nil)
	if adapter == nil {
		t.Fatal("Expected non-nil adapter")
	}

	if adapter.framework != framework {
		t.Error("Framework not set correctly")
	}

	if adapter.config == nil {
		t.Error("Config should be set to default")
	}

	// Test with custom config
	customConfig := &HTTPAdapterConfig{
		MaxBodySize:     1024,
		RequestTimeout:  5 * time.Second,
		EnableFramework: false,
	}

	adapter2 := NewHTTPAdapter(framework, customConfig)
	if adapter2.config.MaxBodySize != 1024 {
		t.Errorf("Expected MaxBodySize = 1024, got %d", adapter2.config.MaxBodySize)
	}
}

func TestHTTPAdapter_SkipPaths(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.SkipPaths = []string{"/health", "/metrics"}

	adapter := NewHTTPAdapter(framework, config)

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/health/check", true},
		{"/metrics", true},
		{"/metrics/prometheus", true},
		{"/api/users", false},
		{"/", false},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", test.path, nil)
		result := adapter.shouldSkipRequest(req)
		if result != test.expected {
			t.Errorf("shouldSkipRequest(%s) = %v, expected %v", test.path, result, test.expected)
		}
	}
}

func TestHTTPAdapter_SkipMethods(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.SkipMethods = []string{"OPTIONS", "HEAD"}

	adapter := NewHTTPAdapter(framework, config)

	tests := []struct {
		method   string
		expected bool
	}{
		{"OPTIONS", true},
		{"HEAD", true},
		{"GET", false},
		{"POST", false},
		{"PUT", false},
	}

	for _, test := range tests {
		req := httptest.NewRequest(test.method, "/api/test", nil)
		result := adapter.shouldSkipRequest(req)
		if result != test.expected {
			t.Errorf("shouldSkipRequest(%s) = %v, expected %v", test.method, result, test.expected)
		}
	}
}

func TestHTTPAdapter_ConvertHTTPToFramework(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.EnablePooling = false // Disable pooling for tests
	adapter := NewHTTPAdapter(framework, config)

	// Create test HTTP request
	body := `{"name": "test", "value": 123}`
	req := httptest.NewRequest("POST", "/api/users?id=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Tenant-ID", "tenant456")
	req.RemoteAddr = "192.168.1.100:8080"

	// Convert to framework request
	frameworkReq, err := adapter.convertHTTPToFrameworkRequest(req)
	if err != nil {
		t.Fatalf("convertHTTPToFrameworkRequest failed: %v", err)
	}

	// Verify conversion
	if frameworkReq.Method != "POST" {
		t.Errorf("Expected Method = POST, got %s", frameworkReq.Method)
	}

	if frameworkReq.Path != "/api/users" {
		t.Errorf("Expected Path = /api/users, got %s", frameworkReq.Path)
	}

	if frameworkReq.ContentType != "application/json" {
		t.Errorf("Expected ContentType = application/json, got %s", frameworkReq.ContentType)
	}

	if string(frameworkReq.Body) != body {
		t.Errorf("Expected Body = %s, got %s", body, string(frameworkReq.Body))
	}

	// Check headers
	if frameworkReq.Headers["Authorization"][0] != "Bearer token123" {
		t.Error("Authorization header not preserved")
	}

	if frameworkReq.Headers["Content-Type"][0] != "application/json" {
		t.Error("Content-Type header not preserved")
	}

	// Check context
	if frameworkReq.Context["user_id"] != "user123" {
		t.Error("User ID not extracted correctly")
	}

	if frameworkReq.Context["tenant_id"] != "tenant456" {
		t.Error("Tenant ID not extracted correctly")
	}

	if frameworkReq.Context["http_method"] != "POST" {
		t.Error("HTTP method not set in context")
	}

	if frameworkReq.Context["http_query"] != "id=1" {
		t.Error("HTTP query not set in context")
	}
}

func TestHTTPAdapter_ConvertFrameworkToHTTP(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.EnablePooling = false // Disable pooling for tests
	adapter := NewHTTPAdapter(framework, config)

	// Create test framework response
	frameworkResp := &Response{
		StatusCode: 201,
		Headers: map[string][]string{
			"Content-Type":    {"application/json"},
			"X-Custom-Header": {"custom-value"},
		},
		Body: []byte(`{"id": 123, "status": "created"}`),
	}

	// Create response recorder
	recorder := httptest.NewRecorder()

	// Convert framework response to HTTP
	err := adapter.convertFrameworkResponseToHTTP(recorder, frameworkResp)
	if err != nil {
		t.Fatalf("convertFrameworkResponseToHTTP failed: %v", err)
	}

	// Verify conversion
	if recorder.Code != 201 {
		t.Errorf("Expected status code = 201, got %d", recorder.Code)
	}

	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Error("Content-Type header not set correctly")
	}

	if recorder.Header().Get("X-Custom-Header") != "custom-value" {
		t.Error("Custom header not set correctly")
	}

	expectedBody := `{"id": 123, "status": "created"}`
	if recorder.Body.String() != expectedBody {
		t.Errorf("Expected body = %s, got %s", expectedBody, recorder.Body.String())
	}
}

func TestHTTPAdapter_MiddlewareIntegration(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	// Register a test plugin
	plugin := NewTestPlugin("middleware-test")
	framework.RegisterPlugin(plugin)

	config := DefaultHTTPAdapterConfig()
	config.EnablePooling = false // Disable pooling for tests
	adapter := NewHTTPAdapter(framework, config)

	// Create test handler
	originalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("original response"))
	})

	// Wrap with adapter middleware
	middlewareFunc := adapter.MiddlewareFunc()
	wrappedHandler := middlewareFunc(originalHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/api/test", nil)
	recorder := httptest.NewRecorder()

	// Execute request
	wrappedHandler.ServeHTTP(recorder, req)

	// Verify response (should be from original handler since no plugin returned a response)
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code = 200, got %d", recorder.Code)
	}

	if recorder.Body.String() != "original response" {
		t.Errorf("Expected body = 'original response', got %s", recorder.Body.String())
	}
}

func TestHTTPAdapter_ErrorHandling(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.ReturnErrorDetails = true
	config.MaxBodySize = 10      // Very small to trigger error
	config.EnablePooling = false // Disable pooling for tests

	adapter := NewHTTPAdapter(framework, config)

	// Create request with body larger than limit
	largeBody := strings.Repeat("x", 100)
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(largeBody))
	req.Header.Set("Content-Length", "100")

	// Test error handling
	originalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middlewareFunc := adapter.MiddlewareFunc()
	wrappedHandler := middlewareFunc(originalHandler)

	recorder := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(recorder, req)

	// Should return error due to body size limit
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code = 500, got %d", recorder.Code)
	}

	if !strings.Contains(recorder.Body.String(), "request body too large") {
		t.Error("Expected error message about body size")
	}
}

func TestHTTPAdapter_PanicRecovery(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.HandlePanics = true
	config.EnablePooling = false // Disable pooling for tests

	adapter := NewHTTPAdapter(framework, config)

	// Create handler that panics
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	middlewareFunc := adapter.MiddlewareFunc()
	wrappedHandler := middlewareFunc(panicHandler)

	req := httptest.NewRequest("GET", "/api/test", nil)
	recorder := httptest.NewRecorder()

	// Should not panic
	wrappedHandler.ServeHTTP(recorder, req)

	// Should return 500 error
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code = 500, got %d", recorder.Code)
	}

	if !strings.Contains(recorder.Body.String(), "Internal Server Error") {
		t.Error("Expected internal server error message")
	}
}

func TestHTTPAdapter_RequestBodyBuffering(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.EnableBuffering = true
	config.EnablePooling = false // Disable pooling for tests

	adapter := NewHTTPAdapter(framework, config)

	// Create request with body
	originalBody := "test request body"
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(originalBody))

	// Read body through adapter
	bodyBytes, err := adapter.readRequestBody(req)
	if err != nil {
		t.Fatalf("readRequestBody failed: %v", err)
	}

	if string(bodyBytes) != originalBody {
		t.Errorf("Expected body = %s, got %s", originalBody, string(bodyBytes))
	}

	// Verify body can be read again from request
	newBodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read request body again: %v", err)
	}

	if string(newBodyBytes) != originalBody {
		t.Error("Request body should be re-readable after buffering")
	}
}

func TestHTTPAdapter_HeaderPreservation(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.PreserveHeaders = []string{"Authorization", "Custom-Header"}

	adapter := NewHTTPAdapter(framework, config)

	tests := []struct {
		header   string
		expected bool
	}{
		{"Authorization", true},
		{"Custom-Header", true},
		{"custom-header", true}, // Case insensitive
		{"AUTHORIZATION", true}, // Case insensitive
		{"Content-Length", false},
		{"Accept-Encoding", false},
	}

	for _, test := range tests {
		result := adapter.shouldPreserveHeader(test.header)
		if result != test.expected {
			t.Errorf("shouldPreserveHeader(%s) = %v, expected %v", test.header, result, test.expected)
		}
	}
}

func TestHTTPAdapter_Stats(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	adapter := NewHTTPAdapter(framework, DefaultHTTPAdapterConfig())

	stats := adapter.Stats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	config, ok := stats["config"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected config in stats")
	}

	if config["enable_framework"] != true {
		t.Error("Expected enable_framework = true in stats")
	}

	if config["enable_pooling"] != true {
		t.Error("Expected enable_pooling = true in stats")
	}
}

func TestGoZeroIntegration(t *testing.T) {
	framework := createTestFramework(t)
	defer framework.Stop()

	integration := NewGoZeroIntegration(framework, DefaultHTTPAdapterConfig())

	if integration.GetFramework() != framework {
		t.Error("Framework not set correctly in integration")
	}

	if integration.GetAdapter() == nil {
		t.Error("Adapter not created in integration")
	}

	// Test handler creation
	handler := integration.CreateHandler()
	if handler == nil {
		t.Error("Handler not created")
	}

	// Test config update
	newConfig := &HTTPAdapterConfig{
		EnableFramework: false,
	}
	integration.UpdateConfig(newConfig)

	if integration.GetAdapter().config.EnableFramework != false {
		t.Error("Config not updated correctly")
	}
}

func TestUtilityFunctions(t *testing.T) {
	// Test generateHTTPRequestID
	id1 := generateHTTPRequestID()
	id2 := generateHTTPRequestID()

	if id1 == "" || id2 == "" {
		t.Error("Request IDs should not be empty")
	}

	if id1 == id2 {
		t.Error("Request IDs should be unique")
	}

	// Test getClientIP
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:8080"

	ip := getClientIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("Expected IP = 192.168.1.100, got %s", ip)
	}

	// Test X-Real-IP
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Real-IP", "10.0.0.50")
	req2.RemoteAddr = "127.0.0.1:8080"

	ip2 := getClientIP(req2)
	if ip2 != "10.0.0.50" {
		t.Errorf("Expected IP = 10.0.0.50, got %s", ip2)
	}

	// Test getScheme
	req3 := httptest.NewRequest("GET", "/", nil)
	scheme := getScheme(req3)
	if scheme != "http" {
		t.Errorf("Expected scheme = http, got %s", scheme)
	}

	req4 := httptest.NewRequest("GET", "/", nil)
	req4.Header.Set("X-Forwarded-Proto", "https")
	scheme2 := getScheme(req4)
	if scheme2 != "https" {
		t.Errorf("Expected scheme = https, got %s", scheme2)
	}
}

// Helper function to create test framework
func createTestFramework(t *testing.T) FrameworkCore {
	config := &FrameworkConfig{
		Name:        "test-framework",
		Version:     "1.0.0",
		Environment: "test",
		LogLevel:    "info",
	}

	framework := NewCoreEngine()
	err := framework.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	err = framework.Start()
	if err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}

	return framework
}

// TestPlugin for testing
type TestPlugin struct {
	*BasePlugin
	processedRequests int
}

func NewTestPlugin(name string) *TestPlugin {
	plugin := &TestPlugin{
		BasePlugin: NewBasePlugin(name, "1.0.0", "Test plugin"),
	}

	return plugin
}

func (tp *TestPlugin) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	tp.processedRequests++

	// Add test header
	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}
	req.Headers["X-Test-Plugin"] = []string{"processed"}

	return next(ctx, req)
}

func (tp *TestPlugin) GetProcessedRequests() int {
	return tp.processedRequests
}

// Benchmark tests
func BenchmarkHTTPAdapter_ConvertRequest(b *testing.B) {
	framework := createTestFramework(&testing.T{})
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.EnablePooling = false // Disable pooling for benchmarks
	adapter := NewHTTPAdapter(framework, config)

	body := `{"name": "test", "value": 123}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")

		_, err := adapter.convertHTTPToFrameworkRequest(req)
		if err != nil {
			b.Fatalf("Conversion failed: %v", err)
		}
	}
}

func BenchmarkHTTPAdapter_ConvertResponse(b *testing.B) {
	framework := createTestFramework(&testing.T{})
	defer framework.Stop()

	config := DefaultHTTPAdapterConfig()
	config.EnablePooling = false // Disable pooling for benchmarks
	adapter := NewHTTPAdapter(framework, config)

	resp := &Response{
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(`{"status": "ok"}`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		err := adapter.convertFrameworkResponseToHTTP(recorder, resp)
		if err != nil {
			b.Fatalf("Conversion failed: %v", err)
		}
	}
}
