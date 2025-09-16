# 审计中间件集成指南

## 📋 概述

本指南介绍如何使用新的简化审计中间件架构，消除每个微服务需要实现`AuditWriter`接口的复杂性。

### 🎯 架构优化亮点

| 对比项 | 旧架构 | 新架构 |
|--------|--------|--------|
| **微服务实现** | 需要实现`AuditWriter`接口 | 只需要提供`svc`上下文 |
| **代码重复** | 每个微服务都有相似的RPC调用逻辑 | 审计逻辑内置在中间件中 |
| **集成复杂度** | 高 - 需要了解接口细节 | 低 - 一行代码完成集成 |
| **维护性** | 分散在各个微服务 | 集中在审计中间件 |

## 🔄 迁移步骤

### 步骤1：了解新架构

#### 新架构核心组件

```go
// 1. AuditSvcProvider - 微服务只需实现这个简单接口
type AuditSvcProvider interface {
    GetCoreRpcClient() interface{} // 返回Core RPC客户端
}

// 2. EnhancedAuditPlugin - 内置写入逻辑的审计插件
type EnhancedAuditPlugin struct {
    *AuditPlugin                    // 继承所有优化功能
    builtinWriter *BuiltinAuditWriter // 内置RPC调用逻辑
}

// 3. 简化的工厂方法
func NewRpcAuditPlugin(svcProvider AuditSvcProvider) framework.MiddlewarePlugin
```

### 步骤2：微服务改造

#### 旧版本（需要删除）

```go
// ❌ 旧版本 - 需要删除这些代码
type RpcAuditWriter struct {
    coreRpc coreclient.Core
}

func (w *RpcAuditWriter) WriteAuditLog(ctx context.Context, auditData framework.AuditLogData) error {
    // 大量重复的RPC调用代码...
    operationType := w.mapMethodToOperationType(auditData.Method)
    auditInfo := &core.AuditLogInfo{
        // ... 大量字段映射代码
    }
    _, err := w.coreRpc.CreateAuditLog(ctx, auditInfo)
    return err
}

// 在CoreServices中注册
coreServices := &framework.CoreServices{
    AuditWriter: &RpcAuditWriter{coreRpc: svcCtx.CoreRpc},
    // ...
}
```

#### 新版本（推荐）

```go
// ✅ 新版本 - 极简集成
type ServiceContext struct {
    Config  config.Config
    CoreRpc coreclient.Core
    // ... 其他字段
}

// 可选：实现AuditSvcProvider接口（如果没有GetCoreRpcClient方法）
func (svc *ServiceContext) GetCoreRpcClient() interface{} {
    return svc.CoreRpc
}

// 在main.go或middleware注册处
func setupMiddlewares(svcCtx *svc.ServiceContext) {
    // 🎉 一行代码完成审计中间件集成！
    auditPlugin := audit.NewRpcAuditPlugin(svcCtx)
    
    // 注册到中间件管理器
    middlewareManager.Register(auditPlugin)
}
```

### 步骤3：具体迁移示例

#### Core API 服务迁移

**迁移前**：
```go
// core/api/internal/svc/service_context.go
type ServiceContext struct {
    Config  config.Config
    CoreRpc coreclient.Core
}

// 需要实现这个复杂的AuditWriter
type RpcAuditWriter struct {
    coreRpc coreclient.Core
}
func (w *RpcAuditWriter) WriteAuditLog(ctx context.Context, auditData framework.AuditLogData) error {
    // 50行+ 的重复代码...
}

// core/api/internal/middleware/setup.go
func SetupMiddlewares(svcCtx *svc.ServiceContext) {
    coreServices := &framework.CoreServices{
        AuditWriter: &RpcAuditWriter{coreRpc: svcCtx.CoreRpc},
        Config:      &framework.UnifiedConfig{Audit: auditConfig},
    }
    
    auditPlugin := audit.NewAuditPlugin()
    auditPlugin.Init(coreServices)
    // ...
}
```

**迁移后**：
```go
// core/api/internal/svc/service_context.go
type ServiceContext struct {
    Config  config.Config
    CoreRpc coreclient.Core
}

// 如果已经有GetCoreRpcClient方法，则无需修改
// 如果没有，添加这个简单方法：
func (svc *ServiceContext) GetCoreRpcClient() interface{} {
    return svc.CoreRpc
}

// core/api/internal/middleware/setup.go
func SetupMiddlewares(svcCtx *svc.ServiceContext) {
    // 🎉 一行代码搞定！
    auditPlugin := audit.NewRpcAuditPlugin(svcCtx)
    middlewareManager.Register(auditPlugin)
}
```

#### CMDB API 服务迁移

**迁移前**：
```go
// cmdb/api/internal/svc/service_context.go
type ServiceContext struct {
    Config  config.Config
    CoreRpc coreclient.Core
    CmdbRpc cmdbclient.Cmdb
}

// 又是一遍重复的AuditWriter实现...
type CmdbRpcAuditWriter struct {
    coreRpc coreclient.Core
}
// ... 重复代码
```

**迁移后**：
```go
// cmdb/api/internal/svc/service_context.go
type ServiceContext struct {
    Config  config.Config
    CoreRpc coreclient.Core
    CmdbRpc cmdbclient.Cmdb
}

func (svc *ServiceContext) GetCoreRpcClient() interface{} {
    return svc.CoreRpc
}

// cmdb/api/main.go 或 middleware setup
auditPlugin := audit.NewRpcAuditPlugin(svcCtx)
middlewareManager.Register(auditPlugin)
```

## 📊 代码对比

### 代码行数减少

| 微服务 | 迁移前 | 迁移后 | 减少 |
|--------|--------|--------|------|
| Core API | ~80行 | ~3行 | 96% |
| CMDB API | ~80行 | ~3行 | 96% |
| 其他微服务 | ~80行/个 | ~3行/个 | 96% |

### 维护复杂度降低

- **重复代码消除**：审计写入逻辑集中在中间件
- **接口简化**：从复杂的`AuditWriter`到简单的`AuditSvcProvider`
- **错误调试**：统一的错误处理和日志记录

## 🔧 高级配置

### 自定义配置

```go
// 如果需要自定义审计配置
config := &audit.EnhancedConfig{
    AuditConfig: &framework.AuditConfig{
        Enabled:                true,
        SkipPaths:             []string{"/health", "/metrics"},
        MaxRequestDataSize:    5000,
        MaxResponseDataSize:   2000,
        // 使用所有优化功能
    },
    WriterType:  audit.WriterTypeRPC,
    SvcProvider: svcCtx,
}

auditPlugin := audit.NewEnhancedAuditPlugin(config)
```

### 多种写入器支持

```go
// RPC写入器（推荐）
auditPlugin := audit.NewRpcAuditPlugin(svcCtx)

// 直接数据库写入器（未来支持）
// auditPlugin := audit.NewDBDirectAuditPlugin(svcCtx.DB)

// 自定义写入器
customWriter := &MyCustomAuditWriter{}
config := &audit.EnhancedConfig{
    WriterType:   audit.WriterTypeCustom,
    CustomWriter: customWriter,
}
auditPlugin := audit.NewEnhancedAuditPlugin(config)
```

## 🧪 测试验证

### 集成测试

```go
func TestAuditIntegration(t *testing.T) {
    // 创建模拟的服务上下文
    mockSvc := &MockServiceContext{
        coreRpc: &MockCoreRpcClient{},
    }
    
    // 创建审计插件
    auditPlugin := audit.NewRpcAuditPlugin(mockSvc)
    
    // 验证插件初始化
    assert.NotNil(t, auditPlugin)
    
    // 验证RPC调用
    // ... 测试代码
}
```

### 性能测试

```go
func BenchmarkNewAuditPlugin(b *testing.B) {
    svcCtx := &ServiceContext{CoreRpc: mockClient}
    
    for i := 0; i < b.N; i++ {
        audit.NewRpcAuditPlugin(svcCtx)
    }
}
```

## ⚠️ 注意事项

### 兼容性

1. **向后兼容**：旧版本的`AuditWriter`接口仍然支持
2. **渐进迁移**：可以逐个微服务进行迁移
3. **功能保持**：所有现有审计功能都保持不变

### 最佳实践

1. **统一命名**：建议所有服务上下文都使用`GetCoreRpcClient()`方法名
2. **错误处理**：审计失败不应影响主业务逻辑
3. **性能监控**：使用内置的性能监控功能

### 排错指南

#### 常见问题

1. **RPC客户端为nil**
   ```go
   // 确保服务上下文正确初始化CoreRpc
   func (svc *ServiceContext) GetCoreRpcClient() interface{} {
       if svc.CoreRpc == nil {
           logx.Error("CoreRpc client is nil")
       }
       return svc.CoreRpc
   }
   ```

2. **反射调用失败**
   ```go
   // 检查RPC客户端是否有CreateAuditLog方法
   // 审计中间件会自动降级到日志记录
   ```

## 🚀 迁移检查清单

### 迁移前

- [ ] 备份现有的审计相关代码
- [ ] 确认Core RPC客户端正常工作
- [ ] 记录当前的审计配置

### 迁移中

- [ ] 删除旧的`RpcAuditWriter`实现
- [ ] 添加`GetCoreRpcClient()`方法（如果没有）
- [ ] 使用`audit.NewRpcAuditPlugin(svcCtx)`替换旧的注册方式
- [ ] 更新中间件注册代码

### 迁移后

- [ ] 验证审计日志正常写入
- [ ] 检查性能改善情况
- [ ] 运行完整的集成测试
- [ ] 监控错误日志

## 📞 支持

如果在迁移过程中遇到问题：

1. **查看日志**：审计中间件会记录详细的调试信息
2. **检查配置**：确认RPC客户端配置正确
3. **逐步排查**：可以先在测试环境验证
4. **回滚预案**：保留旧代码作为应急回滚方案

---

*通过这次架构优化，我们预期每个微服务的审计相关代码减少90%+，同时获得更好的性能和可维护性。*