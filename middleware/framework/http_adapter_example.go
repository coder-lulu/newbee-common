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
	"log"
	"net/http"
	"time"

	"github.com/zeromicro/go-zero/rest"
)

// ExampleUsage demonstrates how to integrate the framework with go-zero
func ExampleUsage() {
	// 1. Create and configure the framework
	framework := NewCoreEngine()

	config := &FrameworkConfig{
		Name:           "example-api",
		Version:        "1.0.0",
		Environment:    "development",
		LogLevel:       "info",
		MaxConcurrency: 1000,
		RequestTimeout: 30 * time.Second,
		MetricsEnabled: true,
		MetricsPort:    9090,
		HealthEnabled:  true,
	}

	// Initialize framework
	err := framework.Initialize(config)
	if err != nil {
		log.Fatalf("Failed to initialize framework: %v", err)
	}

	// 2. Register plugins
	auditPlugin := NewAuditPlugin()
	framework.RegisterPlugin(auditPlugin)

	// 3. Start framework
	err = framework.Start()
	if err != nil {
		log.Fatalf("Failed to start framework: %v", err)
	}
	defer framework.Stop()

	// 4. Configure HTTP adapter
	adapterConfig := &HTTPAdapterConfig{
		MaxBodySize:        5 * 1024 * 1024, // 5MB
		RequestTimeout:     25 * time.Second,
		EnableFramework:    true,
		SkipPaths:          []string{"/health", "/metrics", "/swagger"},
		SkipMethods:        []string{"OPTIONS"},
		HandlePanics:       true,
		ReturnErrorDetails: false, // Don't expose internal errors in production
		PreserveHeaders:    []string{"Authorization", "Content-Type", "Accept", "X-User-ID", "X-Tenant-ID"},
		AddHeaders: map[string]string{
			"X-Framework": "newbee-middleware",
			"X-Version":   "1.0.0",
		},
		EnablePooling: true,
		PoolConfig: &PoolConfig{
			RequestPoolSize:  2000,
			ResponsePoolSize: 2000,
			BufferPoolSize:   1000,
		},
	}

	// 5. Create go-zero server
	server := rest.MustNewServer(rest.RestConf{
		Host: "0.0.0.0",
		Port: 8888,
	})
	defer server.Stop()

	// 6. Register framework middleware with go-zero
	integration := NewGoZeroIntegration(framework, adapterConfig)
	integration.RegisterMiddleware(server)

	// 7. Define your API handlers
	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/api/users/:id",
		Handler: getUserHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodPost,
		Path:    "/api/users",
		Handler: createUserHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodPut,
		Path:    "/api/users/:id",
		Handler: updateUserHandler,
	})

	// 8. Add health check endpoint
	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/health",
		Handler: healthCheckHandler,
	})

	// 9. Start server
	fmt.Println("Starting server on :8888")
	server.Start()
}

// Example handlers
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// This handler will be called after framework processing
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"id": "123", "name": "John Doe", "email": "john@example.com"}`))
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"id": "124", "name": "Jane Doe", "email": "jane@example.com", "status": "created"}`))
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"id": "123", "name": "John Smith", "email": "john.smith@example.com", "status": "updated"}`))
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy", "timestamp": "` + time.Now().Format(time.RFC3339) + `"}`))
}

// ExampleCustomPlugin demonstrates creating a custom plugin for the framework
type ExampleCustomPlugin struct {
	*BasePlugin
	requestCount int64
}

func NewExampleCustomPlugin() *ExampleCustomPlugin {
	return &ExampleCustomPlugin{
		BasePlugin: NewBasePlugin("example-custom", "1.0.0", "Example custom plugin"),
	}
}

func (p *ExampleCustomPlugin) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	p.requestCount++

	// Add custom processing logic
	startTime := time.Now()

	// Add custom headers
	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}
	req.Headers["X-Custom-Plugin"] = []string{"processed"}
	req.Headers["X-Request-Count"] = []string{fmt.Sprintf("%d", p.requestCount)}

	// Call next handler
	resp, err := next(ctx, req)

	// Add response processing
	duration := time.Since(startTime)
	if resp != nil {
		if resp.Headers == nil {
			resp.Headers = make(map[string][]string)
		}
		resp.Headers["X-Processing-Time"] = []string{duration.String()}
	}

	return resp, err
}

func (p *ExampleCustomPlugin) GetRequestCount() int64 {
	return p.requestCount
}

// ExampleAdvancedUsage shows advanced integration patterns
func ExampleAdvancedUsage() {
	// Create framework with advanced configuration
	framework := NewCoreEngine()

	config := &FrameworkConfig{
		Name:           "advanced-api",
		Version:        "2.0.0",
		Environment:    "production",
		LogLevel:       "warn",
		MaxConcurrency: 5000,
		RequestTimeout: 15 * time.Second,
		MetricsEnabled: true,
		MetricsPort:    9090,
		HealthEnabled:  true,
		PluginConfigs: map[string]PluginConfig{
			"audit": {
				Enabled:  true,
				Priority: 10,
				Config: map[string]interface{}{
					"capture_request":  true,
					"capture_response": false,
					"max_body_size":    256 * 1024, // 256KB
					"skip_paths":       []string{"/health", "/metrics"},
					"async_logging":    true,
				},
			},
		},
	}

	err := framework.Initialize(config)
	if err != nil {
		log.Fatalf("Failed to initialize framework: %v", err)
	}

	// Register multiple plugins
	auditPlugin := NewAuditPlugin()
	customPlugin := NewExampleCustomPlugin()

	framework.RegisterPlugin(auditPlugin)
	framework.RegisterPlugin(customPlugin)

	err = framework.Start()
	if err != nil {
		log.Fatalf("Failed to start framework: %v", err)
	}
	defer framework.Stop()

	// Advanced adapter configuration
	adapterConfig := &HTTPAdapterConfig{
		MaxBodySize:        10 * 1024 * 1024, // 10MB
		RequestTimeout:     10 * time.Second, // Shorter than framework timeout
		EnableFramework:    true,
		SkipPaths:          []string{"/health", "/metrics", "/debug", "/static"},
		SkipMethods:        []string{"OPTIONS", "HEAD"},
		HandlePanics:       true,
		ReturnErrorDetails: false, // Never expose errors in production
		PreserveHeaders: []string{
			"Authorization", "Content-Type", "Accept",
			"X-User-ID", "X-Tenant-ID", "X-Request-ID",
			"X-Forwarded-For", "X-Real-IP",
		},
		AddHeaders: map[string]string{
			"X-Framework":       "newbee-middleware",
			"X-Version":         "2.0.0",
			"X-Environment":     "production",
			"X-Processing-Mode": "advanced",
		},
		EnablePooling: true,
		PoolConfig: &PoolConfig{
			RequestPoolSize:  5000,
			ResponsePoolSize: 5000,
			BufferPoolSize:   2000,
		},
	}

	// Create REST server with advanced configuration
	server := rest.MustNewServer(rest.RestConf{
		Host:         "0.0.0.0",
		Port:         8888,
		MaxConns:     10000,
		Timeout:      30000, // 30 seconds
		CpuThreshold: 900,   // 90% CPU threshold
	})
	defer server.Stop()

	// Register framework integration
	integration := NewGoZeroIntegration(framework, adapterConfig)
	integration.RegisterMiddleware(server)

	// Add API routes with different patterns
	registerAPIRoutes(server)

	fmt.Println("Starting advanced server on :8888")
	server.Start()
}

func registerAPIRoutes(server *rest.Server) {
	// User management routes
	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/api/v1/users",
		Handler: listUsersHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/api/v1/users/:id",
		Handler: getUserHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodPost,
		Path:    "/api/v1/users",
		Handler: createUserHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodPut,
		Path:    "/api/v1/users/:id",
		Handler: updateUserHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodDelete,
		Path:    "/api/v1/users/:id",
		Handler: deleteUserHandler,
	})

	// System routes
	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/health",
		Handler: healthCheckHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/metrics",
		Handler: metricsHandler,
	})

	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/debug/stats",
		Handler: statsHandler,
	})
}

// Additional handlers
func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"users": [{"id": "123", "name": "John"}, {"id": "124", "name": "Jane"}], "total": 2}`))
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"requests_total": 1000, "errors_total": 5, "avg_response_time": "50ms"}`))
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"framework": "running", "plugins": 2, "uptime": "24h"}`))
}

// ExampleStandaloneHTTPAdapter shows how to use the adapter without go-zero
func ExampleStandaloneHTTPAdapter() {
	// Create framework
	framework := NewCoreEngine()
	config := &FrameworkConfig{
		Name:        "standalone-api",
		Version:     "1.0.0",
		Environment: "test",
	}

	framework.Initialize(config)
	framework.Start()
	defer framework.Stop()

	// Create HTTP adapter
	adapter := NewHTTPAdapter(framework, DefaultHTTPAdapterConfig())

	// Create standard HTTP handler
	mux := http.NewServeMux()

	// Add your routes
	mux.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Hello, World!"}`))
	})

	// Wrap with adapter middleware
	handler := adapter.MiddlewareFunc()(mux)

	// Start HTTP server
	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	fmt.Println("Starting standalone server on :8080")
	log.Fatal(server.ListenAndServe())
}

// ExampleConfigurationFromFile shows loading configuration from external source
func ExampleConfigurationFromFile() {
	// This would typically load from YAML/JSON file
	configData := `
framework:
  name: "file-config-api"
  version: "1.0.0"
  environment: "production"
  max_concurrency: 2000
  request_timeout: "20s"

adapter:
  max_body_size: 5242880  # 5MB
  request_timeout: "15s"
  enable_framework: true
  skip_paths: ["/health", "/metrics"]
  handle_panics: true
  preserve_headers: ["Authorization", "Content-Type"]
  enable_pooling: true
`

	// Parse configuration (implementation would depend on config format)
	_ = configData // Placeholder

	// Create framework with parsed config
	framework := NewCoreEngine()

	// Example of using parsed values
	config := &FrameworkConfig{
		Name:           "file-config-api",
		Version:        "1.0.0",
		Environment:    "production",
		MaxConcurrency: 2000,
		RequestTimeout: 20 * time.Second,
	}

	framework.Initialize(config)
	framework.Start()
	defer framework.Stop()

	// Create adapter with parsed config
	adapterConfig := &HTTPAdapterConfig{
		MaxBodySize:     5 * 1024 * 1024,
		RequestTimeout:  15 * time.Second,
		EnableFramework: true,
		SkipPaths:       []string{"/health", "/metrics"},
		HandlePanics:    true,
		PreserveHeaders: []string{"Authorization", "Content-Type"},
		EnablePooling:   true,
	}

	integration := NewGoZeroIntegration(framework, adapterConfig)

	fmt.Printf("Created integration with config: %+v\n", integration.GetAdapter().Stats())
}
