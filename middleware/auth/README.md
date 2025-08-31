# 自适应认证中间件 (Adaptive Authentication Middleware)

基于机器学习和系统监控的智能认证中间件，能够根据系统负载和环境变化自动调优性能参数。

## 📋 目录

- [特性概述](#特性概述)
- [架构设计](#架构设计)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [核心组件](#核心组件)
- [监控指标](#监控指标)
- [性能优化](#性能优化)
- [故障排除](#故障排除)
- [最佳实践](#最佳实践)

## 🚀 特性概述

### 核心功能
- **JWT 认证**: 安全可靠的令牌验证机制
- **动态负载感知**: 实时监控 CPU、内存、网络性能
- **自适应缓存**: 基于命中率的智能缓存策略调整
- **智能限流**: 根据系统负载动态调整限流参数
- **服务降级**: 负载过高时自动降级保护核心功能
- **预测性扩缩容**: 基于历史数据预测负载变化

### 自适应能力
- **实时监控**: 系统资源使用率监控
- **机器学习**: 负载预测和模式识别
- **自动优化**: 无需人工干预的性能调优
- **故障恢复**: 自动检测和恢复异常状态
- **全局协调**: 各组件间的智能协调和冲突解决

## 🏗 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                 自适应认证中间件                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   系统资源监控   │  │   智能协调器     │  │  健康检查器   │ │
│  │   - CPU监控     │  │   - 冲突检测     │  │  - 组件状态   │ │
│  │   - 内存监控     │  │   - 全局优化     │  │  - 自动恢复   │ │
│  │   - 网络监控     │  │   - 决策引擎     │  │  - 告警管理   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   自适应缓存     │  │   动态连接池     │  │   智能限流    │ │
│  │   - L1/L2缓存   │  │   - 连接池调整   │  │  - 动态限制   │ │
│  │   - 命中率优化   │  │   - 负载均衡     │  │  - 行为分析   │ │
│  │   - 预取策略     │  │   - 健康检查     │  │  - 分层限流   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   服务降级管理   │  │   预测性扩缩容   │  │  运营仪表板   │ │
│  │   - 分级降级     │  │   - 负载预测     │  │  - 实时监控   │ │
│  │   - 策略执行     │  │   - 机器学习     │  │  - 历史数据   │ │
│  │   - 自动恢复     │  │   - 自动扩缩     │  │  - 告警通知   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                        基础认证层                            │
│               JWT 验证 · 用户上下文 · 权限控制                │
└─────────────────────────────────────────────────────────────┘
```

## ⚡ 快速开始

### 1. 安装依赖

```go
go mod init your-project
go get github.com/coder-lulu/newbee-common/middleware/auth
```

### 2. 基本使用

```go
package main

import (
    "database/sql"
    "net/http"
    
    "github.com/coder-lulu/newbee-common/middleware/auth"
    "github.com/redis/go-redis/v9"
    _ "github.com/go-sql-driver/mysql"
)

func main() {
    // 初始化 Redis 客户端
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    // 初始化数据库连接
    db, _ := sql.Open("mysql", "user:pass@tcp(localhost:3306)/db")

    // 创建自适应认证中间件
    authMiddleware := auth.NewAdaptiveAuthMiddleware(nil, redisClient, db)
    defer authMiddleware.Stop()

    // 设置路由
    http.HandleFunc("/api/", authMiddleware.Handle(apiHandler))
    http.HandleFunc("/health", healthHandler)

    // 启动服务器
    http.ListenAndServe(":8080", nil)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    // 从上下文获取用户信息
    userID := r.Context().Value("userID").(string)
    w.Write([]byte("Hello " + userID))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("OK"))
}
```

### 3. 使用配置文件

```go
// 从配置文件加载
config, err := auth.LoadConfigFromFile("config/adaptive_auth_config.yaml")
if err != nil {
    log.Fatal(err)
}

authMiddleware := auth.NewAdaptiveAuthMiddleware(config, redisClient, db)
```

## 📝 配置说明

### 基础认证配置

```yaml
auth:
  jwt_secret: "your-secret-key"
  enabled: true
  skip_paths:
    - "/health"
    - "/metrics"
```

### 监控配置

```yaml
monitoring:
  sample_interval: "10s"
  cpu_threshold: 75.0
  memory_threshold: 80.0
  enable_cpu_monitor: true
  enable_memory_monitor: true
```

### 缓存配置

```yaml
cache:
  initial_size: 2000
  max_size: 20000
  default_ttl: "15m"
  hit_rate_threshold: 0.85
  enable_l1_cache: true
  enable_l2_cache: true
```

### 限流配置

```yaml
rate_limit:
  global_rps: 2000.0
  user_rps: 200.0
  enable_adaptive: true
  enable_tiered_limiting: true
```

## 🔧 核心组件

### 1. 系统资源监控器 (SystemResourceMonitor)

实时监控系统资源使用情况，包括：

- **CPU 使用率**: 多核心 CPU 监控
- **内存使用率**: 物理内存和虚拟内存
- **网络延迟**: 多目标 ping 测试
- **系统负载**: 1分钟、5分钟、15分钟负载平均值
- **健康评分**: 综合健康状态评分 (0-100)

```go
// 获取系统指标
metrics := resourceMonitor.GetCurrentMetrics()
fmt.Printf("CPU: %.1f%%, Memory: %.1f%%", metrics.CPUUsage, metrics.MemoryUsage)

// 检查系统健康
if resourceMonitor.IsHealthy() {
    fmt.Println("System is healthy")
}
```

### 2. 自适应缓存管理器 (AdaptiveCacheManager)

智能缓存管理，具备以下特性：

- **多层缓存**: L1 (内存) + L2 (Redis) 缓存架构
- **命中率优化**: 基于命中率自动调整缓存大小
- **智能淘汰**: LRU, LFU, 自适应淘汰策略
- **预取机制**: 基于访问模式的数据预取
- **压缩存储**: 大对象自动压缩存储

```go
// 存储数据到缓存
cacheManager.Set("user:123", userData, time.Minute*15)

// 从缓存获取数据
if data, found := cacheManager.Get("user:123"); found {
    // 缓存命中
}

// 获取缓存统计
stats := cacheManager.GetStats()
fmt.Printf("Hit Rate: %.2f%%", stats.HitRate*100)
```

### 3. 动态连接池管理器 (DynamicConnectionPoolManager)

根据负载动态调整连接池大小：

- **数据库连接池**: MySQL, PostgreSQL 等关系数据库
- **Redis 连接池**: NoSQL 数据库连接管理
- **负载感知**: 基于并发量和响应时间调整
- **健康检查**: 连接有效性检查
- **统计监控**: 连接使用率和性能统计

```go
// 获取连接池统计
dbStats := connectionPool.GetDBStats()
redisStats := connectionPool.GetRedisStats()

// 查看调整历史
history := connectionPool.GetAdjustmentHistory()
for _, adjustment := range history {
    fmt.Printf("Adjustment: %s -> %d connections", 
        adjustment.Reason, adjustment.NewSize)
}
```

### 4. 智能限流器 (IntelligentRateLimiter)

多维度智能限流系统：

- **分层限流**: 全局、用户、IP 三层限流
- **动态调整**: 基于系统负载自动调整限流参数
- **行为分析**: 用户请求模式分析和异常检测
- **白名单/黑名单**: 灵活的访问控制
- **分布式协调**: 多实例间限流状态同步

```go
// 检查请求是否允许
if rateLimiter.Allow(request) {
    // 处理请求
} else {
    // 请求被限流
}

// 获取限流统计
stats := rateLimiter.GetStats()
fmt.Printf("Block Rate: %.2f%%", stats.BlockRate*100)
```

### 5. 服务降级管理器 (ServiceDegradationManager)

分级服务降级保护：

- **分级降级**: 轻度、中度、重度、极度四级降级
- **策略执行**: 缓存减少、限流加强、功能禁用
- **自动恢复**: 负载恢复后自动升级服务等级
- **影响预测**: 降级操作的影响评估
- **决策引擎**: 基于多指标的智能决策

```go
// 获取当前降级级别
level := degradationManager.GetCurrentLevel()
fmt.Printf("Current degradation level: %s", level.String())

// 获取活跃策略
strategies := degradationManager.GetActiveStrategies()
fmt.Printf("Active strategies: %v", strategies)
```

### 6. 预测性扩缩容系统 (PredictiveScalingSystem)

基于机器学习的负载预测：

- **多模型预测**: ARIMA, LSTM, 线性回归集成模型
- **模式识别**: 季节性、趋势性、异常检测
- **预测性扩容**: 提前 15-30 分钟预测负载变化
- **自动扩缩容**: 缓存、连接池、限流器自动调整
- **准确率追踪**: 预测准确率监控和模型优化

```go
// 获取预测统计
stats := scalingSystem.GetStats()
fmt.Printf("Prediction Accuracy: %.2f%%", stats.PredictionAccuracy*100)

// 注册自定义扩缩容执行器
executor := &CustomScalingExecutor{}
scalingSystem.RegisterScalingExecutor("custom", executor)
```

## 📊 监控指标

### Prometheus 指标

系统提供丰富的 Prometheus 指标用于监控：

#### 认证指标
- `adaptive_auth_requests_total`: 认证请求总数
- `adaptive_auth_response_time_seconds`: 认证响应时间
- `adaptive_auth_system_health_score`: 系统健康评分

#### 缓存指标
- `auth_adaptive_cache_hit_rate`: 缓存命中率
- `auth_adaptive_cache_size`: 缓存当前大小
- `auth_adaptive_cache_eviction_rate`: 缓存淘汰率

#### 连接池指标
- `auth_connection_pool_active_connections`: 活跃连接数
- `auth_connection_pool_utilization_rate`: 连接池使用率

#### 限流指标
- `auth_ratelimit_requests_blocked_total`: 被限流的请求总数
- `auth_ratelimit_current_limit`: 当前限流值

#### 降级指标
- `auth_degradation_level`: 当前降级级别
- `auth_degradations_total`: 降级操作总数
- `auth_recoveries_total`: 恢复操作总数

#### 扩缩容指标
- `auth_prediction_accuracy`: 预测准确率
- `auth_scaling_actions_total`: 扩缩容操作总数

### Grafana 仪表板

提供预配置的 Grafana 仪表板模板：

1. **系统概览**: 系统健康、请求量、响应时间
2. **资源监控**: CPU、内存、网络、负载趋势
3. **缓存性能**: 命中率、大小变化、淘汰统计
4. **限流分析**: 限流效果、调整历史、用户分析
5. **降级历史**: 降级级别变化、策略执行统计
6. **预测分析**: 负载预测、准确率、模型性能

## ⚡ 性能优化

### 内存优化

- **对象池**: 复用频繁创建的对象
- **内存池**: 预分配内存块减少 GC 压力
- **缓存分层**: L1 内存缓存 + L2 Redis 缓存
- **压缩存储**: 大对象自动压缩存储

### CPU 优化

- **无锁编程**: 使用 atomic 操作减少锁竞争
- **批量处理**: 批量更新缓存和统计数据
- **异步处理**: 后台异步执行非关键任务
- **算法优化**: 高效的数据结构和算法

### 网络优化

- **连接复用**: HTTP/1.1 keep-alive 和 HTTP/2
- **请求合并**: 合并小请求减少网络开销
- **数据压缩**: gzip 压缩传输数据
- **CDN 集成**: 静态资源 CDN 分发

### 并发优化

- **协程池**: 限制协程数量避免资源耗尽
- **流量整形**: 平滑处理突发流量
- **背压机制**: 系统过载时的反压保护
- **负载均衡**: 请求智能分发

## 🔍 故障排除

### 常见问题

#### 1. JWT 验证失败

**问题**: 认证请求返回 401 Unauthorized

**排查步骤**:
```bash
# 检查 JWT 密钥配置
curl -H "Authorization: Bearer <token>" http://localhost:8080/auth/status

# 查看认证日志
tail -f /var/log/auth.log | grep "authentication failed"

# 验证 token 有效性
jwt decode <token>
```

**解决方案**:
- 检查 JWT secret 配置是否正确
- 确认 token 未过期且格式正确
- 验证签名算法是否匹配

#### 2. 系统性能下降

**问题**: 响应时间增加，系统负载过高

**排查步骤**:
```bash
# 查看系统资源使用
curl http://localhost:8080/system/metrics

# 检查组件健康状态
curl http://localhost:8080/auth/status

# 查看 Prometheus 指标
curl http://localhost:9090/metrics | grep auth_
```

**解决方案**:
- 检查是否触发降级机制
- 调整缓存配置提高命中率
- 优化连接池配置
- 检查预测性扩缩容是否正常工作

#### 3. 缓存命中率低

**问题**: 缓存效果不佳，命中率低于预期

**解决方案**:
```yaml
# 调整缓存配置
cache:
  max_size: 50000           # 增加缓存大小
  default_ttl: "30m"        # 调整过期时间
  hit_rate_threshold: 0.8   # 降低自适应阈值
  enable_prefetch: true     # 启用预取
  prefetch_ratio: 0.2       # 增加预取比例
```

#### 4. 限流过于严格

**问题**: 正常请求被误限流

**解决方案**:
```yaml
# 调整限流配置
rate_limit:
  global_rps: 5000.0        # 提高全局限制
  user_rps: 500.0           # 提高用户限制
  enable_adaptive: true     # 启用自适应调整
  whitelist:                # 添加白名单
    - "192.168.1.100"
```

### 监控和告警

#### 1. 设置关键指标告警

```yaml
# Prometheus 告警规则
groups:
- name: adaptive_auth_alerts
  rules:
  - alert: HighErrorRate
    expr: rate(adaptive_auth_requests_total{status!="success"}[5m]) > 0.1
    for: 2m
    annotations:
      summary: "Authentication error rate too high"

  - alert: LowSystemHealth
    expr: adaptive_auth_system_health_score < 60
    for: 1m
    annotations:
      summary: "System health score below threshold"

  - alert: CacheLowHitRate
    expr: auth_adaptive_cache_hit_rate < 0.6
    for: 5m
    annotations:
      summary: "Cache hit rate below 60%"
```

#### 2. 日志监控

```bash
# 设置日志监控
tail -f auth.log | grep -E "(ERROR|WARN|degradation|scaling)"

# 使用 ELK Stack 分析日志
# Elasticsearch + Logstash + Kibana
```

## 📖 最佳实践

### 1. 配置优化

#### 生产环境配置建议

```yaml
# 生产环境配置模板
auth:
  jwt_secret: "${JWT_SECRET}"  # 使用环境变量
  
monitoring:
  sample_interval: "5s"        # 更频繁的监控
  cpu_threshold: 70.0          # 更保守的阈值
  memory_threshold: 75.0
  
cache:
  max_size: 100000            # 大容量缓存
  default_ttl: "1h"           # 长 TTL
  enable_l2_cache: true       # 启用 Redis 缓存
  
rate_limit:
  enable_adaptive: true       # 启用自适应限流
  enable_distributed: true   # 启用分布式限流
  
degradation:
  enable_degradation: true    # 启用自动降级
  check_interval: "30s"       # 快速响应
  
scaling:
  enable_predictive_scaling: true  # 启用预测扩缩容
  prediction_interval: "2m"        # 频繁预测
```

### 2. 监控策略

#### 关键指标监控

1. **系统健康指标**
   - 系统健康评分 > 80
   - CPU 使用率 < 80%
   - 内存使用率 < 85%
   - 网络延迟 < 100ms

2. **业务指标**
   - 认证成功率 > 99.5%
   - 平均响应时间 < 200ms
   - 缓存命中率 > 80%
   - 限流误杀率 < 0.1%

3. **运维指标**
   - 预测准确率 > 75%
   - 自动恢复成功率 > 95%
   - 降级操作频率 < 5/day
   - 扩缩容操作延迟 < 30s

#### 告警设置

```yaml
# 告警配置建议
alert_thresholds:
  critical:
    error_rate: 5.0           # 5% 错误率
    response_time: 1000.0     # 1秒响应时间
    system_health: 50.0       # 系统健康 50%
  warning:
    error_rate: 2.0           # 2% 错误率
    response_time: 500.0      # 500ms 响应时间
    system_health: 70.0       # 系统健康 70%
```

### 3. 部署建议

#### 容器化部署

```dockerfile
# Dockerfile 示例
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/config/ ./config/

EXPOSE 8080 9090
CMD ["./main"]
```

#### Kubernetes 部署

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: adaptive-auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: adaptive-auth
  template:
    metadata:
      labels:
        app: adaptive-auth
    spec:
      containers:
      - name: adaptive-auth
        image: adaptive-auth:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secret
              key: jwt-secret
        resources:
          limits:
            cpu: 2000m
            memory: 4Gi
          requests:
            cpu: 500m
            memory: 1Gi
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

### 4. 安全考虑

#### JWT 安全

```go
// 安全的 JWT 配置
config := &auth.AuthConfig{
    JWTSecret: generateSecureSecret(32), // 32 字节随机密钥
    Enabled:   true,
    SkipPaths: []string{
        "/health", "/metrics",           // 仅必要的跳过路径
    },
}

// 定期轮换 JWT 密钥
go func() {
    ticker := time.NewTicker(24 * time.Hour)
    for range ticker.C {
        rotateJWTSecret()
    }
}()
```

#### 访问控制

```yaml
# 严格的访问控制配置
rate_limit:
  # 黑名单配置
  blacklist:
    - "192.168.1.100"    # 恶意 IP
  
  # 信任网络配置
  trusted_networks:
    - "10.0.0.0/8"       # 内网段
    - "172.16.0.0/12"    # 内网段
  
  # 动态惩罚
  enable_dynamic_penalty: true
  penalty_multiplier: 0.1    # 严厉惩罚
  penalty_duration: "1h"     # 长时间惩罚
```

### 5. 性能调优

#### 高并发优化

```go
// 高并发场景配置
config := &auth.AdaptiveAuthConfig{
    ConnectionPool: auth.ConnectionPoolConfig{
        DB: auth.DBPoolConfig{
            MaxOpenConns: 200,           // 大连接池
            MaxIdleConns: 50,
            ConnMaxLifetime: time.Hour,
        },
        Redis: auth.RedisPoolConfig{
            PoolSize:     100,           // 大 Redis 连接池
            MinIdleConns: 20,
        },
    },
    Cache: auth.AdaptiveCacheConfig{
        MaxSize:        500000,         // 大缓存
        EnableL1Cache:  true,
        EnableL2Cache:  true,
        L1L2Ratio:      0.4,           // 更多 L1 缓存
    },
    RateLimit: auth.RateLimiterConfig{
        GlobalRPS: 50000,               // 高 RPS 限制
        UserRPS:   1000,
        BurstSize: 1000,               // 大突发容量
    },
}
```

#### 内存优化

```go
// 内存优化配置
runtime.GOMAXPROCS(runtime.NumCPU())
runtime.GC()

// 设置 GC 目标
debug.SetGCPercent(75)

// 预分配内存池
var (
    requestPool = sync.Pool{
        New: func() interface{} {
            return make([]byte, 1024)
        },
    }
)
```

## 📚 API 文档

### REST API

#### 健康检查
```http
GET /health
```
响应: `200 OK`
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 认证状态
```http
GET /auth/status
```
响应: `200 OK`
```json
{
  "system_health": 85.5,
  "status": "operational",
  "current_adaptations": {
    "degradation_level": "Normal",
    "active_strategies": []
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 系统指标
```http
GET /system/metrics
```
响应: `200 OK`
```json
{
  "total_requests": 1000000,
  "successful_requests": 995000,
  "failed_requests": 5000,
  "system_efficiency": 0.995,
  "component_stats": {
    "cache": {
      "hit_rate": 0.85,
      "size": 15000
    }
  }
}
```

### 管理 API (需要认证)

#### 获取统计信息
```http
GET /admin/stats
Authorization: Bearer <jwt_token>
```

#### 更新配置
```http
POST /admin/config
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "rate_limit": {
    "global_rps": 3000.0
  }
}
```

## 🤝 贡献指南

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

## 📄 许可证

本项目基于 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 🔗 相关链接

- [项目主页](https://github.com/coder-lulu/newbee-common)
- [问题反馈](https://github.com/coder-lulu/newbee-common/issues)
- [讨论社区](https://github.com/coder-lulu/newbee-common/discussions)
- [更新日志](CHANGELOG.md)

## 📞 技术支持

- 📧 邮件支持: support@newbee.com
- 💬 在线聊天: [Slack Channel](https://newbee-slack.com)
- 📖 文档中心: [docs.newbee.com](https://docs.newbee.com)
- 🎥 视频教程: [YouTube](https://youtube.com/newbee-tutorials)