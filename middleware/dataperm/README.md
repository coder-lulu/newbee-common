# 统一数据权限中间件 (Unified Data Permission Middleware)

## 概览

统一数据权限中间件是NewBee系统中的企业级数据权限控制解决方案，它集成了现有的Casbin权限系统，提供了多维度的数据权限控制能力，包括行级权限、字段级权限和动态SQL过滤。

## 🎯 核心特性

### 1. 多维度权限控制
- **行级权限**: 基于用户角色和部门的数据行访问控制
- **字段级权限**: 细粒度的字段访问控制和数据脱敏
- **条件权限**: 基于动态条件的权限规则
- **时间权限**: 支持临时权限和权限有效期

### 2. Casbin深度集成
- 与现有core RPC服务中的Casbin系统无缝集成
- 支持复杂的RBAC和ABAC权限模型
- 权限规则的动态生成和缓存优化
- 企业级权限审批流程支持

### 3. 高性能设计
- Redis缓存优化，提升权限检查性能
- 批量权限检查支持
- 异步权限处理能力
- 智能的权限规则合并和优化

### 4. 开发友好
- 丰富的配置选项和默认策略
- 完整的测试套件和Mock支持
- 详细的调试日志和性能监控
- 灵活的扩展机制

## 🏗️ 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Request                             │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│               UnifiedDataPermPlugin                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  1. 解析资源和操作类型                               │   │
│  │  2. Casbin权限检查                                  │   │
│  │  3. 生成数据过滤规则                                │   │
│  │  4. 注入增强权限上下文                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 Business Logic                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│            EnhancedDataPermInterceptor                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  1. 获取权限上下文                                   │   │
│  │  2. 自动应用SQL过滤条件                             │   │
│  │  3. 字段级权限检查                                   │   │
│  │  4. 数据脱敏处理                                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Database                                  │
└─────────────────────────────────────────────────────────────┘
```

## 📦 核心组件

### 1. UnifiedDataPermPlugin
**职责**: 中间件入口，负责权限检查和上下文注入
```go
// 基本使用
plugin := NewUnifiedDataPermPlugin(casbinProvider)

// 注册到中间件框架
middleware.Register(plugin)
```

### 2. PermissionRuleEngine  
**职责**: 权限规则生成和管理
```go
// 生成数据过滤规则
dataRules, err := ruleEngine.GenerateDataRules(ctx, userID, resource, action, appliedRules)
```

### 3. EnhancedContextManager
**职责**: 权限上下文管理
```go
// 设置权限上下文
enhancedCtx := contextManager.SetEnhancedPermissions(ctx, userID, tenantID, dataRules)

// 获取SQL过滤条件
sqlFilters := contextManager.GetSQLFilters(ctx)
```

### 4. EnhancedDataPermInterceptor
**职责**: 自动SQL过滤和字段权限控制
```go
// 注册到ent客户端
interceptor := NewEnhancedDataPermInterceptor(logger, config)
interceptor.RegisterWithClient(entClient)
```

### 5. FieldMaskProcessor
**职责**: 字段级权限控制和数据脱敏
```go
// 处理字段掩码
maskedData := fieldProcessor.ProcessFieldMasks(ctx, data, fieldMasks)
```

## ⚙️ 配置指南

### 基础配置
```yaml
dataPerm:
  enabled: true
  casbinEnabled: true
  coreRpcEndpoint: "127.0.0.1:9100"
  unified:
    engine:
      templatesEnabled: true
      dynamicRules: true
      priorityStrategy: "highest"
    fieldMask:
      enabled: true
      defaultStrategy: "partial"
      autoDetection: true
      accessStrategy: "role_based"
    interceptor:
      sqlFiltering: true
      strictMode: true
      protectSystemTables: true
    performance:
      cacheEnabled: true
      cacheExpiry: 15
      batchConcurrency: 10
      checkTimeout: 5000
      metricsEnabled: true
    debug:
      verboseLogging: false
      logPermissionChecks: false
      logSqlFilters: false
      logFieldMasks: false
      profileEnabled: false
```

### 高级配置选项

#### 权限引擎配置
- `templatesEnabled`: 启用规则模板系统
- `customTemplates`: 自定义规则模板文件路径
- `dynamicRules`: 启用动态规则生成
- `priorityStrategy`: 规则优先级策略 (highest/lowest/merge)

#### 字段掩码配置  
- `defaultStrategy`: 默认掩码策略 (none/partial/full/hash/encrypt)
- `autoDetection`: 自动检测敏感字段
- `customSensitive`: 自定义敏感字段配置
- `accessStrategy`: 字段访问策略 (role_based/rule_based/hybrid)

#### 性能配置
- `cacheExpiry`: 缓存过期时间（分钟）
- `batchConcurrency`: 批量检查并发数
- `checkTimeout`: 权限检查超时时间（毫秒）
- `metricsEnabled`: 启用性能指标收集

## 🚀 快速开始

### 1. 集成到现有服务

```go
package main

import (
    "github.com/coder-lulu/newbee-common/middleware/dataperm"
    "github.com/coder-lulu/newbee-common/middleware/framework"
)

func main() {
    // 1. 创建Casbin提供者
    casbinProvider := dataperm.NewDefaultCasbinProvider(coreRPCClient, logger)
    
    // 2. 创建统一数据权限插件
    dataPermPlugin := dataperm.NewUnifiedDataPermPlugin(casbinProvider)
    
    // 3. 注册到中间件框架
    manager := framework.NewMiddlewareManager()
    manager.Register(dataPermPlugin)
    
    // 4. 创建并注册ent拦截器
    interceptor := dataperm.NewEnhancedDataPermInterceptor(logger, nil)
    interceptor.RegisterWithClient(entClient)
    
    // 5. 启动服务
    server.Start()
}
```

### 2. 使用权限上下文

```go
func (l *GetUserLogic) GetUser(req *types.GetUserReq) (*types.UserInfo, error) {
    // 权限上下文会自动注入，可以直接获取过滤条件
    sqlFilters := l.contextManager.GetSQLFilters(l.ctx)
    
    // ent查询会自动应用过滤条件
    user, err := l.svcCtx.DB.User.Query().
        Where(user.ID(req.ID)).
        Only(l.ctx)
    
    if err != nil {
        return nil, err
    }
    
    // 字段掩码会自动应用
    return &types.UserInfo{
        ID:       user.ID,
        Username: user.Username,
        Email:    user.Email, // 可能被掩码
        Phone:    user.Phone, // 可能被掩码
    }, nil
}
```

### 3. 自定义权限规则

```go
// 添加自定义权限规则模板
template := &dataperm.RuleTemplate{
    ServiceName:  "custom",
    ResourceType: "sensitive_data",
    Action:       "read",
    SQLTemplate:  "user_id = '{{user_id}}' AND department_id = '{{department_id}}'",
    FieldRules: []dataperm.FieldRule{
        {
            FieldName:    "sensitive_field",
            AccessLevels: []string{"admin"},
            MaskType:     "full",
        },
    },
    Priority: 90,
}

// 注册自定义规则模板
ruleEngine.RegisterRuleTemplate("custom:sensitive_data:read", template)
```

## 🧪 测试

### 运行测试套件
```go
// 创建测试套件
testSuite := dataperm.NewTestSuite(logger)

// 运行所有测试
results := testSuite.RunAllTests(ctx)

// 生成测试报告
report, err := testSuite.GenerateTestReportJSON()
fmt.Println(report)
```

### 验证配置
```go
// 验证配置有效性
config := &framework.UnifiedDataPermConfig{...}
errors := dataperm.ValidateConfiguration(config)
if len(errors) > 0 {
    log.Fatalf("Configuration errors: %v", errors)
}
```

## 📊 性能监控

### 获取性能指标
```go
// 获取插件统计信息
stats := dataPermPlugin.GetStats()
fmt.Printf("Cache hit rate: %.2f%%\n", stats["cache_hit_rate"])

// 获取规则引擎统计
engineStats := ruleEngine.GetStats()
fmt.Printf("Rules generated: %d\n", engineStats["rules_generated"])

// 获取字段处理器统计
fieldStats := fieldProcessor.GetStats()
fmt.Printf("Sensitive fields: %d\n", fieldStats["sensitive_fields_count"])
```

### 关键性能指标
- **权限检查延迟**: 平均权限检查时间
- **缓存命中率**: 权限结果缓存命中率
- **规则生成效率**: 数据过滤规则生成性能
- **SQL过滤开销**: 动态SQL过滤的性能影响

## 🔧 故障排除

### 常见问题

#### 1. 权限检查失败
```
ERROR: permission check failed: connection refused
```
**解决方案**: 检查core RPC服务连接和Casbin配置

#### 2. 缓存不工作
```
WARN: cache operation failed: redis connection timeout
```
**解决方案**: 检查Redis连接配置和网络状态

#### 3. SQL过滤无效
```
WARN: no SQL filters applied, using default restrictions
```
**解决方案**: 检查权限上下文注入和拦截器注册

### 调试模式
启用详细日志记录来诊断问题：
```yaml
debug:
  verboseLogging: true
  logPermissionChecks: true
  logSqlFilters: true
  logFieldMasks: true
```

## 🔒 安全考虑

### 1. 权限缓存安全
- 缓存键包含租户ID，防止跨租户数据泄露
- 定期缓存清理和过期机制
- 敏感权限信息的加密存储

### 2. SQL注入防护
- 所有动态SQL条件都经过参数化处理
- 禁止原生SQL绕过权限检查
- 系统表的自动保护机制

### 3. 字段脱敏安全
- 基于角色的字段访问控制
- 多级脱敏策略支持
- 敏感字段的自动检测和保护

## 📚 扩展开发

### 自定义掩码策略
```go
type CustomMaskStrategy struct{}

func (s *CustomMaskStrategy) Apply(value interface{}) interface{} {
    // 自定义掩码逻辑
    return "CUSTOM_MASKED"
}

func (s *CustomMaskStrategy) GetType() string {
    return "custom"
}

// 注册自定义策略
fieldProcessor.RegisterCustomMaskStrategy("custom", &CustomMaskStrategy{})
```

### 自定义权限提供者
```go
type CustomCasbinProvider struct {
    // 自定义实现
}

func (p *CustomCasbinProvider) CheckPermissionWithRoles(ctx context.Context, subject, object, action, serviceName string) (*PermissionResult, error) {
    // 自定义权限检查逻辑
    return &PermissionResult{...}, nil
}

// 使用自定义提供者
plugin := dataperm.NewUnifiedDataPermPlugin(customProvider)
```

## 📈 版本历史

### v1.0.0 (当前版本)
- ✅ 基础权限检查和数据过滤
- ✅ Casbin集成和缓存优化
- ✅ 字段级权限控制和脱敏
- ✅ 完整的测试套件和文档

### 计划中的功能
- 🔄 可视化权限规则管理界面
- 🔄 权限变更的实时通知
- 🔄 更高级的数据分析和权限推荐
- 🔄 多数据源权限控制支持

## 🤝 贡献指南

欢迎提交问题报告和功能请求！在开发新功能时，请：

1. 遵循现有的代码风格和架构模式
2. 添加相应的单元测试
3. 更新相关文档
4. 确保向后兼容性

## 📄 许可证

Copyright 2024 The NewBee Authors. All Rights Reserved.