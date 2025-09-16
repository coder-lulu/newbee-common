# NewBee Middleware Integration Usage Examples

## Overview

This document provides practical examples for integrating NewBee middleware into your microservices. We offer multiple integration approaches to suit different needs and complexity levels.

## Quick Start (Recommended)

### 1. Zero-Configuration Setup

The simplest way to get started - just provide Redis client and JWT secret:

```go
package main

import (
    "github.com/coder-lulu/newbee-common/middleware/integration"
    "github.com/redis/go-redis/v9"
    "github.com/zeromicro/go-zero/rest"
)

func main() {
    // Setup Redis client
    rds := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })
    
    // One-click setup with all recommended defaults
    result, err := integration.OneClickSetupWithSecret(rds, "your-jwt-secret")
    if err != nil {
        panic(err)
    }
    
    // Create and configure server
    server := rest.MustNewServer(rest.RestConf{Port: 8080})
    integration.ApplyOneClickToServer(server, result)
    
    // Your API routes here...
    server.Start()
}
```

### 2. Service Context Integration

For services with existing ServiceContext:

```go
// internal/svc/service_context.go
package svc

import (
    "github.com/coder-lulu/newbee-common/middleware/integration"
    "github.com/coder-lulu/newbee-common/middleware/keys"
    "github.com/zeromicro/go-zero/rest"
)

type ServiceContext struct {
    Config            Config
    ContextManager    *keys.ContextManager
    ManagedMiddleware []rest.Middleware
    // ... other fields
}

func NewServiceContext(c Config) *ServiceContext {
    // Setup Redis
    rds := c.Redis.NewUniversalClient()
    
    // One-click middleware setup
    result := integration.MustOneClickSetup(rds, c.Auth.AccessSecret)
    
    return &ServiceContext{
        Config:            c,
        ContextManager:    result.ContextManager,
        ManagedMiddleware: result.Middlewares,
        // ... initialize other fields
    }
}
```

```go
// internal/config/config.go
type Config struct {
    rest.RestConf
    Auth struct {
        AccessSecret string
        AccessExpire int64
    }
    Redis redis.RedisConf
}
```

## Environment-Specific Setups

### Development Environment

Relaxed configuration for development convenience:

```go
func setupDevelopment() {
    rds := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    
    result, err := integration.OneClickSetupForDevelopment(rds)
    if err != nil {
        log.Fatal(err)
    }
    
    server := rest.MustNewServer(rest.RestConf{Port: 8080})
    integration.ApplyOneClickToServer(server, result)
    
    server.Start()
}
```

### Minimal Setup

For services that only need authentication and tenant checking:

```go
func setupMinimal() {
    rds := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    
    result, err := integration.OneClickSetupMinimal(rds, "jwt-secret")
    if err != nil {
        log.Fatal(err)
    }
    
    server := rest.MustNewServer(rest.RestConf{Port: 8080})
    integration.ApplyOneClickToServer(server, result)
    
    server.Start()
}
```

## Advanced Configuration

### Custom Plugin Configuration

```go
func setupWithCustomConfig() {
    rds := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    
    config := &integration.QuickSetupConfig{
        MiddlewareConfig: &framework.UnifiedConfig{
            Auth: &framework.AuthConfig{
                Enabled:      true,
                AccessSecret: "your-secret",
                AccessExpire: 3600,
                SkipPaths:    []string{"/health", "/api/v1/public/*"},
            },
            TenantCheck: &framework.TenantCheckConfig{
                Enabled:           true,
                ValidateStatus:    true,
                RateLimitEnabled:  true,
                MaxRequestsPerMin: 500, // Custom rate limit
            },
            // DataPerm and Audit with custom settings
        },
        RedisClient: rds,
    }
    
    result, err := integration.QuickSetup(config)
    if err != nil {
        log.Fatal(err)
    }
    
    server := rest.MustNewServer(rest.RestConf{Port: 8080})
    integration.ApplyOneClickToServer(server, result)
}
```

### Skip Specific Plugins

```go
func setupWithoutAudit() {
    config := &integration.QuickSetupConfig{
        MiddlewareConfig: integration.DefaultProductionConfig("jwt-secret"),
        RedisClient:      rds,
        SkipPlugins:      []string{"audit"}, // Skip audit plugin
    }
    
    result, err := integration.QuickSetup(config)
    // ... rest of setup
}
```

### Add Custom Plugins

```go
func setupWithCustomPlugin() {
    customPlugin := &MyCustomPlugin{} // Implements framework.MiddlewarePlugin
    
    config := &integration.QuickSetupConfig{
        MiddlewareConfig: integration.DefaultProductionConfig("jwt-secret"),
        RedisClient:      rds,
        CustomPlugins:    []framework.MiddlewarePlugin{customPlugin},
    }
    
    result, err := integration.QuickSetup(config)
    // ... rest of setup
}
```

## Route-Level Middleware Application

Instead of global middleware, apply to specific routes:

```go
// Don't use ApplyOneClickToServer for global application
result := integration.MustOneClickSetup(rds, "jwt-secret")

// Apply to specific route groups
server.AddRoute(rest.Route{
    Method:      http.MethodGet,
    Path:        "/api/v1/protected",
    Handler:     protectedHandler,
    Middlewares: result.Middlewares, // Apply only to this route
})

server.AddRoute(rest.Route{
    Method:  http.MethodGet,
    Path:    "/api/v1/public",
    Handler: publicHandler,
    // No middleware for public routes
})
```

## Context Usage in Handlers

Accessing user context in your handlers:

```go
func userHandler(w http.ResponseWriter, r *http.Request) {
    // Access the context manager from service context
    cm := svcCtx.ContextManager
    
    // Extract user information
    tenantID := cm.GetTenantID(r.Context())
    userID := cm.GetUserID(r.Context())
    deptID := cm.GetDeptID(r.Context())
    dataScope := cm.GetDataScope(r.Context())
    
    // Use the information in your business logic
    users, err := svcCtx.DB.User.Query().
        Where(user.TenantIDEQ(tenantID)).
        All(r.Context())
        
    // ... rest of handler logic
}
```

## Error Handling

```go
func setupWithErrorHandling() {
    rds := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    
    result, err := integration.OneClickSetupWithSecret(rds, "jwt-secret")
    if err != nil {
        log.Printf("Middleware setup failed: %v", err)
        // Fallback to basic setup or exit
        return
    }
    
    server := rest.MustNewServer(rest.RestConf{Port: 8080})
    integration.ApplyOneClickToServer(server, result)
    
    // Graceful shutdown
    defer func() {
        if result.Manager != nil {
            result.Manager.Shutdown()
        }
    }()
    
    server.Start()
}
```

## Testing Setup

For unit/integration tests:

```go
func setupTestMiddleware() *integration.OneClickResult {
    // Use test Redis or mock
    rds := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    
    result, err := integration.OneClickSetupForDevelopment(rds)
    if err != nil {
        panic(fmt.Sprintf("test setup failed: %v", err))
    }
    
    return result
}

func TestProtectedEndpoint(t *testing.T) {
    result := setupTestMiddleware()
    
    // Create test server with middleware
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Apply middleware chain manually for testing
        var handler http.HandlerFunc = yourHandler
        for i := len(result.Middlewares) - 1; i >= 0; i-- {
            handler = result.Middlewares[i](handler).ServeHTTP
        }
        handler(w, r)
    }))
    
    // Test with JWT token
    req, _ := http.NewRequest("GET", server.URL+"/test", nil)
    req.Header.Set("Authorization", "Bearer "+testJWT)
    // ... rest of test
}
```

## Migration from Legacy Setup

If you're migrating from manual middleware setup:

```go
// OLD WAY (manual setup)
/*
func NewServiceContext(c Config) *ServiceContext {
    authMiddleware := auth.NewAuthPlugin()
    tenantMiddleware := tenant.NewTenantCheckPlugin()
    // ... manual plugin creation and configuration
    
    manager := framework.NewManager(...)
    manager.Register(authMiddleware, tenantMiddleware, ...)
    
    return &ServiceContext{
        // ... manual field assignment
    }
}
*/

// NEW WAY (one-click setup)
func NewServiceContext(c Config) *ServiceContext {
    rds := c.Redis.NewUniversalClient()
    result := integration.MustOneClickSetup(rds, c.Auth.AccessSecret)
    
    return &ServiceContext{
        Config:            c,
        ContextManager:    result.ContextManager,
        ManagedMiddleware: result.Middlewares,
        // ... other fields as before
    }
}
```

## Best Practices

1. **Use One-Click Setup for New Services**: Start with `OneClickSetup` and customize only when needed.

2. **Environment-Specific Configs**: Use different configs for dev/staging/production environments.

3. **Graceful Shutdown**: Always call `manager.Shutdown()` during application shutdown.

4. **Context Manager Usage**: Always use `ContextManager` methods instead of direct `ctx.Value()` calls.

5. **Error Handling**: Handle setup errors gracefully, especially in production.

6. **Testing**: Use development config or minimal setup for tests to reduce dependencies.

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**: Ensure Redis is running and connection parameters are correct.

2. **JWT Secret Missing**: Always provide a strong JWT secret in production.

3. **Plugin Order Issues**: The framework automatically handles plugin ordering, but custom plugins should specify appropriate priorities.

4. **Context Values Missing**: Ensure middleware chain is properly applied before accessing context values.

For more advanced configuration options, see the `QuickSetupConfig` documentation and individual plugin configurations.