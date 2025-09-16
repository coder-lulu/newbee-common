# NewBee 监控系统

NewBee中间件框架的全面监控和观测系统，提供性能监控、缓存监控、安全监控、系统健康检查和告警管理等功能。

## 核心特性

### 🎯 性能监控
- **中间件性能追踪**: 自动记录每个中间件的延迟、吞吐量和错误率
- **请求链路追踪**: 完整的请求执行路径监控
- **分位数统计**: P50、P95、P99延迟分析
- **实时性能指标**: 支持Prometheus格式导出

### 🗄️ 缓存监控  
- **多类型缓存支持**: JWT缓存、分片缓存、Redis缓存
- **命中率追踪**: 实时缓存效率监控
- **容量监控**: 缓存大小和使用率统计
- **操作延迟**: 缓存get/set/delete性能分析

### 🔒 安全监控
- **租户隔离违规检测**: 跨租户访问尝试监控
- **认证失败分析**: Token相关安全事件追踪  
- **权限违规记录**: 数据权限越权尝试监控
- **IP行为分析**: 可疑IP识别和风险评分
- **异常检测**: 基于统计学的异常行为识别

### 💚 系统健康监控
- **组件健康检查**: 多层次健康状态评估
- **自动恢复检测**: 智能恢复状态判断
- **健康评分**: 综合健康指标计算
- **依赖监控**: 外部服务依赖健康检查

### 🚨 智能告警
- **规则引擎**: 灵活的告警规则配置
- **告警分级**: Critical/High/Medium/Low四级告警
- **告警抑制**: 防止告警风暴的冷却机制
- **多通道告警**: 支持多种告警通道扩展

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    MonitoringManager                        │
│                   (统一监控管理器)                           │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
┌───▼───────┐ ┌──────▼──────┐ ┌────────▼────────┐
│Performance│ │    Cache    │ │    Security     │
│  Monitor  │ │   Monitor   │ │    Monitor      │  
└───────────┘ └─────────────┘ └─────────────────┘
    │                 │                 │
┌───▼───────┐ ┌──────▼──────┐ ┌────────▼────────┐
│  System   │ │   Health    │ │     Alert       │
│ Monitor   │ │   Monitor   │ │    Manager      │
└───────────┘ └─────────────┘ └─────────────────┘
```

## 快速开始

### 基本使用

```go
package main

import (
    "context"
    "log"
    
    "github.com/coder-lulu/newbee-common/middleware/monitoring"
)

func main() {
    // 1. 创建监控管理器
    manager, err := monitoring.CreateProductionMonitoringSetup()
    if err != nil {
        log.Fatal(err)
    }
    
    // 2. 启动监控
    ctx := context.Background()
    if err := manager.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer manager.Stop()
    
    // 3. 包装中间件进行监控
    authPlugin := NewAuthPlugin()
    monitoredAuth := manager.WrapMiddleware("auth", 10, authPlugin)
    
    // 4. 包装缓存进行监控
    jwtCache := NewJWTCache()
    monitoredCache := manager.WrapJWTCache(jwtCache, "jwt_cache")
    
    // 5. 记录安全事件
    manager.RecordTenantViolation(ctx, "tenant123", "user456", "/api/data", 
        map[string]interface{}{
            "reason": "cross_tenant_access",
        })
}
```

### 预设配置

支持多种预设配置，适应不同环境：

```go
// 生产环境 - 高精度监控
manager, err := monitoring.CreateProductionMonitoringSetup()

// 开发环境 - 平衡性能和监控
manager, err := monitoring.CreateDevelopmentMonitoringSetup()  

// 轻量级 - 最小资源消耗
manager, err := monitoring.CreateLightweightMonitoringSetup()

// 默认配置
manager, err := monitoring.CreateDefaultMonitoringSetup()
```

## 监控指标

### 中间件性能指标
- `middleware_requests_total`: 中间件处理请求总数
- `middleware_errors_total`: 中间件错误总数  
- `middleware_duration_seconds`: 中间件处理延迟直方图

### 缓存指标  
- `cache_operations_total`: 缓存操作总数
- `cache_hit_rate`: 缓存命中率
- `cache_size`: 当前缓存大小
- `cache_eviction_count`: 缓存淘汰次数

### 安全指标
- `security_violations_total`: 安全违规事件总数
- `auth_failures_total`: 认证失败总数
- `permission_denied_total`: 权限拒绝总数
- `rate_limit_exceeded_total`: 限流触发总数

### 系统指标
- `system_memory_usage`: 系统内存使用率
- `system_cpu_usage`: 系统CPU使用率  
- `system_goroutines`: 协程数量
- `system_gc_duration`: GC暂停时间

## HTTP API

监控系统提供RESTful API访问监控数据：

```bash
# 监控概览
curl http://localhost:9090/monitoring/overview

# 性能指标  
curl http://localhost:9090/monitoring/middleware

# 缓存指标
curl http://localhost:9090/monitoring/cache

# 安全指标  
curl http://localhost:9090/monitoring/security

# 健康检查
curl http://localhost:9090/monitoring/health

# 活跃告警
curl http://localhost:9090/monitoring/alerts

# 所有指标
curl http://localhost:9090/monitoring/metrics
```

## 报告生成

### 性能报告

```go
reporter := monitoring.NewMonitoringReporter(manager)
perfReport := reporter.GeneratePerformanceReport()

fmt.Printf("总请求数: %d\n", perfReport.Summary.TotalRequests)
fmt.Printf("总错误数: %d\n", perfReport.Summary.TotalErrors) 
fmt.Printf("错误率: %.2f%%\n", perfReport.Summary.OverallErrorRate * 100)
fmt.Printf("平均延迟: %v\n", perfReport.Summary.AverageLatency)
```

### 缓存报告

```go
cacheReport := reporter.GenerateCacheReport()

fmt.Printf("缓存数量: %d\n", cacheReport.Summary.TotalCaches)
fmt.Printf("总命中数: %d\n", cacheReport.Summary.TotalHits)
fmt.Printf("总未命中数: %d\n", cacheReport.Summary.TotalMisses)
fmt.Printf("整体命中率: %.2f%%\n", cacheReport.Summary.OverallHitRate * 100)
```

### 安全报告

```go
securityReport := reporter.GenerateSecurityReport()

fmt.Printf("总违规数: %d\n", securityReport.Summary.TotalViolations)
fmt.Printf("可疑IP数: %d\n", securityReport.Summary.SuspiciousIPCount)
fmt.Printf("最近违规时间: %v\n", securityReport.Summary.LastViolationTime)
```

## 最佳实践

### 配置验证

```go
practices := monitoring.NewMonitoringBestPractices(manager)

// 验证监控配置
issues := practices.ValidateConfiguration()
for _, issue := range issues {
    fmt.Printf("[%s] %s: %s\n", issue.Severity, issue.Component, issue.Issue)
}

// 获取优化建议  
suggestions := practices.GetOptimizationSuggestions()
for _, suggestion := range suggestions {
    fmt.Printf("[%s] %s: %s\n", 
        suggestion.Priority, suggestion.Component, suggestion.Suggestion)
}
```

### 自定义告警规则

```go
customRule := monitoring.AlertRule{
    ID:          "custom_high_latency",
    Name:        "High Response Latency",  
    Description: "API response time exceeds 2 seconds",
    Condition: monitoring.AlertCondition{
        MetricName: "middleware_duration_p99",
        Operator:   "gt", 
        Threshold:  2.0, // 2 seconds
        Duration:   5 * time.Minute,
    },
    Severity: monitoring.AlertSeverityHigh,
    Enabled:  true,
    Cooldown: 10 * time.Minute,
}
```

## 性能特性

### 高性能设计
- **分片缓存**: 降低锁竞争，提升并发性能
- **异步指标记录**: 避免阻塞主业务流程  
- **采样控制**: 可配置采样率平衡精度和性能
- **内存优化**: 对象池化和内存复用

### 扩展性
- **插件化架构**: 支持自定义监控组件
- **多收集器支持**: 内存、Prometheus等多种后端
- **灵活告警**: 可扩展的告警通道和规则引擎

### 可靠性  
- **优雅降级**: 监控故障不影响业务功能
- **错误恢复**: 自动检测和恢复机制
- **资源保护**: 内存和CPU使用控制

## 配置参考

### MonitoringConfig

```go
type MonitoringConfig struct {
    Enabled            bool          // 是否启用监控
    SamplingRate       float64       // 采样率 (0.0-1.0)  
    CollectionInterval time.Duration // 数据收集间隔
    AlertEnabled       bool          // 是否启用告警
    AlertCooldown      time.Duration // 告警冷却期
    MetricStorage      string        // 指标存储类型
    RetentionPeriod    time.Duration // 数据保留期
    
    // 阈值配置
    LatencyThresholds  LatencyThresholds
    ErrorThresholds    ErrorThresholds  
    CacheThresholds    CacheThresholds
}
```

### 延迟阈值

```go  
type LatencyThresholds struct {
    P50Warning  time.Duration // P50延迟告警阈值
    P50Critical time.Duration // P50延迟严重阈值
    P95Warning  time.Duration // P95延迟告警阈值  
    P95Critical time.Duration // P95延迟严重阈值
    P99Warning  time.Duration // P99延迟告警阈值
    P99Critical time.Duration // P99延迟严重阈值
}
```

## 故障排查

### 常见问题

1. **监控数据丢失**
   - 检查采样率配置
   - 验证存储后端连接
   - 查看内存使用情况

2. **告警不触发**  
   - 确认告警规则配置
   - 检查指标数据收集
   - 验证告警通道设置

3. **性能影响**
   - 降低采样率
   - 增加收集间隔
   - 优化指标存储

4. **内存使用过高**
   - 调整数据保留期  
   - 减少监控指标数量
   - 启用数据压缩

### 调试模式

```go
// 启用详细日志
config.LogLevel = "debug"

// 查看监控统计  
overview := manager.GetMonitoringOverview()
fmt.Printf("组件状态: %+v\n", overview.ComponentsStatus)

// 检查健康状态
health := manager.GetHealthReport()
fmt.Printf("健康摘要: %+v\n", health.Summary)
```

## 许可证

Copyright 2024 The NewBee Authors. All Rights Reserved.