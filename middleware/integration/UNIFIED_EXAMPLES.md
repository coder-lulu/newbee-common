# NewBee 中间件统一集成指南

## 🎯 统一原则

NewBee中间件框架现在遵循"**一个功能，一个版本，一个标准**"的设计原则：

- ✅ **唯一集成函数**：`integration.Setup()`
- ✅ **唯一配置结构**：`integration.Config`  
- ✅ **唯一审计插件**：`audit.NewAuditPlugin()`
- ✅ **配置驱动行为**：通过Mode和参数控制功能

## 🚀 基础使用

### 最简单的生产环境集成

```go
package main

import (
    "github.com/coder-lulu/newbee-common/middleware/integration"
    "github.com/redis/go-redis/v9"
)

func main() {
    rds := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    
    // 🎉 唯一的集成入口
    result, err := integration.Setup(&integration.Config{
        Redis:     rds,
        JWTSecret: "your-production-secret",
        Mode:      integration.Production,
    })
    if err != nil {
        panic(err)
    }
    
    server := rest.MustNewServer(rest.RestConf{Port: 8080})
    integration.ApplyToServer(server, result)
    server.Start()
}
```

### 开发环境集成

```go
result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: "dev-secret",
    Mode:      integration.Development, // 开发环境预设
})
```

### 测试环境集成

```go
result, err := integration.Setup(&integration.Config{
    Redis:     rds, 
    JWTSecret: "test-secret",
    Mode:      integration.Testing,     // 测试环境预设
})
```

## 🎛️ 高级配置

### 跳过某些插件

```go
result, err := integration.Setup(&integration.Config{
    Redis:       rds,
    JWTSecret:   "secret",
    Mode:        integration.Production,
    SkipPlugins: []string{"audit", "dataperm"}, // 跳过审计和数据权限
})
```

### 只启用指定插件

```go
result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: "secret", 
    Mode:      integration.Production,
    Plugins:   []string{"auth", "tenant"}, // 只启用认证和租户检查
})
```

### 自定义详细配置（覆盖Mode预设）

```go
result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: "secret",
    Middleware: &framework.UnifiedConfig{
        Auth: &framework.AuthConfig{
            Enabled:      true,
            AccessSecret: "secret",
            AccessExpire: 3600,
            SkipPaths:    []string{"/health", "/custom"},
        },
        TenantCheck: &framework.TenantCheckConfig{
            Enabled:           true,
            RateLimitEnabled:  true,
            MaxRequestsPerMin: 500, // 自定义限流
        },
        // ... 其他插件配置
    },
})
```

## 📱 服务上下文集成

### 标准服务集成

```go
// internal/svc/service_context.go
type ServiceContext struct {
    Config            Config
    ContextManager    *keys.ContextManager
    ManagedMiddleware []rest.Middleware
    // ... 其他字段
}

func NewServiceContext(c Config) *ServiceContext {
    rds := c.Redis.NewUniversalClient()
    
    // 统一中间件集成
    result, err := integration.Setup(&integration.Config{
        Redis:     rds,
        JWTSecret: c.Auth.AccessSecret,
        Mode:      integration.Production,
    })
    if err != nil {
        panic(err)
    }
    
    return &ServiceContext{
        Config:            c,
        ContextManager:    result.ContextManager,
        ManagedMiddleware: result.Middlewares,
        // ... 其他字段初始化
    }
}
```

### 带RPC提供者的服务集成

```go
func NewServiceContext(c Config) *ServiceContext {
    // ... 初始化RPC客户端等
    
    result, err := integration.Setup(&integration.Config{
        Redis:     rds,
        JWTSecret: c.Auth.AccessSecret,
        Mode:      integration.Production,
        Middleware: &framework.UnifiedConfig{
            Audit: &framework.AuditConfig{
                Enabled:     true,
                WriterType:  "rpc",
                RpcProvider: svcCtx, // 注入RPC提供者
            },
            // ... 其他配置
        },
    })
    
    return &ServiceContext{
        // ... 字段赋值
    }
}
```

## 🔧 环境预设对比

### Production 模式
- ✅ 全部插件启用
- ✅ 租户状态验证启用  
- ✅ 缓存启用
- ✅ 限流启用 (1000 req/min/tenant)
- ✅ 异步审计启用 (5 workers, 2000 buffer)

### Development 模式  
- ✅ 认证和租户检查启用
- ❌ 数据权限和审计禁用
- ❌ 租户状态验证禁用
- ❌ 缓存禁用
- ❌ 限流禁用
- ⏰ JWT过期时间延长 (24小时)

### Testing 模式
- ✅ 认证和租户检查启用  
- ❌ 数据权限和审计禁用
- ❌ 状态验证、缓存、限流禁用
- ⏰ JWT过期时间适中 (1小时)

## 🔄 迁移指南

### 从旧API迁移

```go
// ❌ 旧的API (已弃用)
result := integration.OneClickSetupWithSecret(rds, "secret")
result := integration.OneClickSetupMinimal(rds, "secret") 
result := integration.OneClickSetupForDevelopment(rds)
result := integration.QuickSetup(config)

// ✅ 新的统一API
result := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: "secret",
    Mode:      integration.Production,
})

result := integration.Setup(&integration.Config{
    Redis:       rds,
    JWTSecret:   "secret", 
    SkipPlugins: []string{"dataperm", "audit"},
})

result := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: "secret",
    Mode:      integration.Development,
})
```

### 审计插件迁移

```go
// ❌ 旧的API (已弃用)  
audit.NewRpcAuditPlugin(svcProvider)
audit.NewEnhancedAuditPlugin(config)

// ✅ 新的统一API
audit.NewAuditPlugin()                // 使用框架配置
audit.NewAuditPlugin(svcProvider)     // 使用RPC提供者
```

## 🎯 最佳实践

### 1. 环境配置驱动
```go
var mode integration.Mode
switch os.Getenv("ENV") {
case "production":
    mode = integration.Production
case "development": 
    mode = integration.Development
default:
    mode = integration.Testing
}

result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: os.Getenv("JWT_SECRET"),
    Mode:      mode,
})
```

### 2. 错误处理
```go
result, err := integration.Setup(config)
if err != nil {
    log.Fatalf("Middleware setup failed: %v", err)
}

// 或者用于初始化阶段
result := integration.MustSetup(config) // 失败时panic
```

### 3. 上下文使用
```go
func handler(w http.ResponseWriter, r *http.Request) {
    cm := svcCtx.ContextManager
    
    tenantID := cm.GetTenantID(r.Context())
    userID := cm.GetUserID(r.Context())
    
    // 使用上下文信息...
}
```

### 4. 优雅关闭
```go
// 服务关闭时
defer func() {
    if result.Manager != nil {
        result.Manager.Shutdown()
    }
}()
```

## 🔍 故障排除

### 常见问题

1. **Redis连接失败**: 确保Redis服务运行且连接参数正确
2. **JWT密钥为空**: 生产环境必须提供强JWT密钥
3. **插件初始化失败**: 检查配置参数是否正确
4. **上下文值缺失**: 确保中间件链已正确应用

### 调试模式
```go
result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: "secret",
    Mode:      integration.Development, // 开发模式便于调试
})
```

---

## ✨ 总结

NewBee中间件框架现在提供了真正统一的集成体验：

- 🎯 **一个入口**：`integration.Setup()` 
- 🎛️ **配置驱动**：通过Mode和Config控制行为
- 🔧 **简单易用**：零配置到高度定制的完整支持
- 📈 **可扩展**：保持向后兼容的同时提供现代化API

这个统一化设计消除了版本混乱，提供了清晰一致的开发者体验。