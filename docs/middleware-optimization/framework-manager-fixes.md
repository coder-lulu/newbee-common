# 中间件框架管理器优化修复方案

## 📍 位置
`/opt/code/newbee/common/middleware/framework/manager.go`

## 🎯 修复目标
增强中间件框架管理器的监控、故障隔离和动态配置能力，保持现有插件化架构设计不变。

## 🔍 问题分析

### P2级别问题（增强优化）

#### 1. 缺少性能监控和统计
**位置**: `framework/manager.go:71-89`
**问题**: 无中间件执行时间统计，难以定位性能瓶颈
**影响**: 无法识别慢中间件，影响系统优化决策

#### 2. 缺少插件故障隔离
**问题**: 单个中间件异常可能影响整个请求链路
**风险**: 一个中间件bug导致整个服务不可用

#### 3. 缺少动态配置能力
**问题**: 中间件配置变更需要重启服务
**影响**: 运维便利性差，无法快速响应问题

#### 4. 可观测性不足
**问题**: 缺少中间件链路追踪和详细监控
**影响**: 故障排查困难，无法快速定位问题

## 🛠️ 修复方案

### 1. 中间件性能监控实现

```go
import (
    "sync"
    "time"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// 性能统计指标
var (
    middlewareDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "middleware_duration_seconds",
            Help: "Time spent in middleware execution",
            Buckets: prometheus.DefBuckets,
        },
        []string{"middleware", "status"},
    )
    
    middlewareRequests = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "middleware_requests_total", 
            Help: "Total number of middleware requests",
        },
        []string{"middleware", "status"},
    )
    
    middlewareErrors = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "middleware_errors_total",
            Help: "Total number of middleware errors", 
        },
        []string{"middleware", "error_type"},
    )
)

// 性能统计收集器
type MiddlewareStats struct {
    Name           string        `json:"name"`
    TotalRequests  int64         `json:"total_requests"`
    TotalErrors    int64         `json:"total_errors"`
    AvgDuration    time.Duration `json:"avg_duration"`
    MaxDuration    time.Duration `json:"max_duration"`
    MinDuration    time.Duration `json:"min_duration"`
    LastExecution  time.Time     `json:"last_execution"`
}

type StatsCollector struct {
    stats   map[string]*MiddlewareStats
    mutex   sync.RWMutex
}

func NewStatsCollector() *StatsCollector {
    return &StatsCollector{
        stats: make(map[string]*MiddlewareStats),
    }
}

func (sc *StatsCollector) RecordExecution(name string, duration time.Duration, err error) {
    sc.mutex.Lock()
    defer sc.mutex.Unlock()
    
    stats, exists := sc.stats[name]
    if !exists {
        stats = &MiddlewareStats{
            Name:        name,
            MinDuration: duration,
            MaxDuration: duration,
        }
        sc.stats[name] = stats
    }
    
    // 更新统计
    stats.TotalRequests++
    stats.LastExecution = time.Now()
    
    if err != nil {
        stats.TotalErrors++
        middlewareErrors.WithLabelValues(name, err.Error()).Inc()
    }
    
    // 更新持续时间统计
    if duration > stats.MaxDuration {
        stats.MaxDuration = duration
    }
    if duration < stats.MinDuration {
        stats.MinDuration = duration
    }
    
    // 计算平均持续时间（简化版本）
    totalDuration := time.Duration(stats.TotalRequests-1) * stats.AvgDuration + duration
    stats.AvgDuration = totalDuration / time.Duration(stats.TotalRequests)
    
    // 更新Prometheus指标
    status := "success"
    if err != nil {
        status = "error"
    }
    
    middlewareDuration.WithLabelValues(name, status).Observe(duration.Seconds())
    middlewareRequests.WithLabelValues(name, status).Inc()
}

func (sc *StatsCollector) GetStats() map[string]*MiddlewareStats {
    sc.mutex.RLock()
    defer sc.mutex.RUnlock()
    
    result := make(map[string]*MiddlewareStats)
    for k, v := range sc.stats {
        result[k] = v
    }
    return result
}

// 增强的中间件管理器
type MiddlewareManager struct {
    core          *CoreServices
    plugins       []MiddlewarePlugin
    statsCollector *StatsCollector     // 新增统计收集器
    circuitBreaker *CircuitBreakerManager // 新增熔断器
    configWatcher  *ConfigWatcher      // 新增配置监听器
}

func NewManager(config *UnifiedConfig, ctx context.Context, redisClient redis.Cmdable, auditWriter AuditWriter, apiResourceProvider ApiResourceProvider) (*MiddlewareManager, error) {
    if config == nil {
        config = DefaultUnifiedConfig()
    }

    if ctx == nil {
        ctx = context.Background()
    }

    coreServices := &CoreServices{
        Config:              config,
        ContextManager:      keys.NewContextManager(),
        Context:             ctx,
        Redis:               redisClient,
        AuditWriter:         auditWriter,
        ApiResourceProvider: apiResourceProvider,
    }

    manager := &MiddlewareManager{
        core:           coreServices,
        plugins:        make([]MiddlewarePlugin, 0),
        statsCollector: NewStatsCollector(),
        circuitBreaker: NewCircuitBreakerManager(),
    }
    
    // 初始化配置监听器
    if redisClient != nil {
        manager.configWatcher = NewConfigWatcher(redisClient, ctx, manager)
        go manager.configWatcher.Start()
    }

    logx.Info("Enhanced middleware manager initialized with monitoring and circuit breaking")
    return manager, nil
}
```

### 2. 插件故障隔离和熔断机制

```go
import (
    "errors"
    "sync/atomic"
)

// 熔断器状态
type CircuitState int32

const (
    CircuitClosed CircuitState = iota
    CircuitOpen
    CircuitHalfOpen
)

// 中间件熔断器
type MiddlewareCircuitBreaker struct {
    name            string
    state           CircuitState
    failureCount    int64
    successCount    int64  
    lastFailureTime time.Time
    timeout         time.Duration
    threshold       int64
    mutex           sync.RWMutex
}

func NewMiddlewareCircuitBreaker(name string, threshold int64, timeout time.Duration) *MiddlewareCircuitBreaker {
    return &MiddlewareCircuitBreaker{
        name:      name,
        state:     CircuitClosed,
        threshold: threshold,
        timeout:   timeout,
    }
}

func (cb *MiddlewareCircuitBreaker) CanExecute() bool {
    cb.mutex.RLock()
    defer cb.mutex.RUnlock()
    
    switch cb.state {
    case CircuitClosed:
        return true
    case CircuitOpen:
        // 检查是否可以转为半开状态
        if time.Since(cb.lastFailureTime) > cb.timeout {
            cb.state = CircuitHalfOpen
            return true
        }
        return false
    case CircuitHalfOpen:
        return true
    default:
        return false
    }
}

func (cb *MiddlewareCircuitBreaker) RecordSuccess() {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    atomic.AddInt64(&cb.successCount, 1)
    
    if cb.state == CircuitHalfOpen {
        // 半开状态下成功，转为关闭状态
        cb.state = CircuitClosed
        atomic.StoreInt64(&cb.failureCount, 0)
    }
}

func (cb *MiddlewareCircuitBreaker) RecordFailure() {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    atomic.AddInt64(&cb.failureCount, 1)
    cb.lastFailureTime = time.Now()
    
    if atomic.LoadInt64(&cb.failureCount) >= cb.threshold {
        cb.state = CircuitOpen
    }
}

func (cb *MiddlewareCircuitBreaker) GetState() CircuitState {
    cb.mutex.RLock()
    defer cb.mutex.RUnlock()
    return cb.state
}

// 熔断器管理器
type CircuitBreakerManager struct {
    breakers map[string]*MiddlewareCircuitBreaker
    mutex    sync.RWMutex
}

func NewCircuitBreakerManager() *CircuitBreakerManager {
    return &CircuitBreakerManager{
        breakers: make(map[string]*MiddlewareCircuitBreaker),
    }
}

func (cbm *CircuitBreakerManager) GetBreaker(name string) *MiddlewareCircuitBreaker {
    cbm.mutex.RLock()
    if breaker, exists := cbm.breakers[name]; exists {
        cbm.mutex.RUnlock()
        return breaker
    }
    cbm.mutex.RUnlock()
    
    cbm.mutex.Lock()
    defer cbm.mutex.Unlock()
    
    // 双重检查
    if breaker, exists := cbm.breakers[name]; exists {
        return breaker
    }
    
    // 创建新的熔断器（默认5次失败触发，30秒恢复）
    breaker := NewMiddlewareCircuitBreaker(name, 5, 30*time.Second)
    cbm.breakers[name] = breaker
    
    return breaker
}

// 带监控和熔断的中间件包装器
func (m *MiddlewareManager) wrapMiddleware(plugin MiddlewarePlugin) rest.Middleware {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            name := plugin.Name()
            startTime := time.Now()
            
            // 检查熔断器状态
            breaker := m.circuitBreaker.GetBreaker(name)
            if !breaker.CanExecute() {
                logx.Errorw("Middleware circuit breaker is open, skipping execution",
                    logx.Field("middleware", name))
                
                // 熔断时直接跳过该中间件
                next(w, r)
                return
            }
            
            // 执行中间件并捕获panic
            var err error
            func() {
                defer func() {
                    if recovered := recover(); recovered != nil {
                        err = fmt.Errorf("middleware panic: %v", recovered)
                        logx.Errorw("Middleware panic recovered",
                            logx.Field("middleware", name),
                            logx.Field("error", err),
                            logx.Field("stack", string(debug.Stack())))
                    }
                }()
                
                // 实际执行中间件
                plugin.Handle(next)(w, r)
            }()
            
            // 记录执行时间和结果
            duration := time.Since(startTime)
            
            if err != nil {
                breaker.RecordFailure()
                m.statsCollector.RecordExecution(name, duration, err)
            } else {
                breaker.RecordSuccess()
                m.statsCollector.RecordExecution(name, duration, nil)
            }
            
            // 记录慢中间件
            if duration > 1*time.Second {
                logx.Warnw("Slow middleware detected",
                    logx.Field("middleware", name),
                    logx.Field("duration", duration))
            }
        }
    }
}

// 更新BuildChain方法
func (m *MiddlewareManager) BuildChain() []rest.Middleware {
    sort.SliceStable(m.plugins, func(i, j int) bool {
        return m.plugins[i].Priority() < m.plugins[j].Priority()
    })

    chain := make([]rest.Middleware, len(m.plugins))
    for i, p := range m.plugins {
        chain[i] = m.wrapMiddleware(p) // 使用包装器
    }

    logx.Info("Enhanced middleware chain built with monitoring and circuit breaking")
    return chain
}
```

### 3. 动态配置热更新

```go
// 配置监听器
type ConfigWatcher struct {
    redis   redis.Cmdable
    ctx     context.Context
    manager *MiddlewareManager
    pubsub  *redis.PubSub
}

func NewConfigWatcher(redis redis.Cmdable, ctx context.Context, manager *MiddlewareManager) *ConfigWatcher {
    return &ConfigWatcher{
        redis:   redis,
        ctx:     ctx,
        manager: manager,
    }
}

func (cw *ConfigWatcher) Start() {
    cw.pubsub = cw.redis.Subscribe(cw.ctx, "middleware_config_changes")
    defer cw.pubsub.Close()
    
    ch := cw.pubsub.Channel()
    for msg := range ch {
        var event ConfigChangeEvent
        if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
            logx.Error("Failed to parse config change event", logx.Field("error", err))
            continue
        }
        
        cw.handleConfigChange(event)
    }
}

type ConfigChangeEvent struct {
    Component string                 `json:"component"` // "auth", "audit", "dataperm", "tenant"
    Action    string                 `json:"action"`    // "update", "reload", "disable", "enable"
    Config    map[string]interface{} `json:"config"`
    Timestamp time.Time              `json:"timestamp"`
}

func (cw *ConfigWatcher) handleConfigChange(event ConfigChangeEvent) {
    logx.Infow("Processing middleware config change",
        logx.Field("component", event.Component),
        logx.Field("action", event.Action))
    
    switch event.Component {
    case "auth":
        cw.updateAuthConfig(event)
    case "audit":
        cw.updateAuditConfig(event)
    case "dataperm":
        cw.updateDataPermConfig(event)
    case "tenant":
        cw.updateTenantConfig(event)
    case "global":
        cw.updateGlobalConfig(event)
    default:
        logx.Warnw("Unknown config component", logx.Field("component", event.Component))
    }
}

func (cw *ConfigWatcher) updateAuthConfig(event ConfigChangeEvent) {
    // 找到认证中间件并更新配置
    for _, plugin := range cw.manager.plugins {
        if plugin.Name() == "Authentication" {
            if configurable, ok := plugin.(ConfigurablePlugin); ok {
                if err := configurable.UpdateConfig(event.Config); err != nil {
                    logx.Errorw("Failed to update auth config", logx.Field("error", err))
                } else {
                    logx.Info("Auth middleware config updated successfully")
                }
            }
            break
        }
    }
}

// 可配置的中间件接口
type ConfigurablePlugin interface {
    MiddlewarePlugin
    UpdateConfig(config map[string]interface{}) error
    ValidateConfig(config map[string]interface{}) error
}

// 在各个中间件中实现ConfigurablePlugin接口示例（认证中间件）
func (p *AuthPlugin) UpdateConfig(config map[string]interface{}) error {
    // 验证配置
    if err := p.ValidateConfig(config); err != nil {
        return err
    }
    
    // 应用新配置
    if skipPaths, ok := config["skip_paths"].([]interface{}); ok {
        newSkipPaths := make([]string, len(skipPaths))
        for i, path := range skipPaths {
            newSkipPaths[i] = path.(string)
        }
        p.config.SkipPaths = newSkipPaths
    }
    
    if accessSecret, ok := config["access_secret"].(string); ok {
        p.config.AccessSecret = accessSecret
    }
    
    logx.Info("Auth plugin config updated")
    return nil
}

func (p *AuthPlugin) ValidateConfig(config map[string]interface{}) error {
    if accessSecret, ok := config["access_secret"]; ok {
        if secret, isString := accessSecret.(string); !isString || secret == "" {
            return errors.New("access_secret must be a non-empty string")
        }
    }
    
    return nil
}
```

### 4. 监控API和健康检查

```go
// 监控API端点
func (m *MiddlewareManager) RegisterMonitoringEndpoints(server *rest.Server) {
    // 统计信息端点
    server.AddRoute(rest.Route{
        Method: http.MethodGet,
        Path:   "/middleware/stats",
        Handler: func(w http.ResponseWriter, r *http.Request) {
            stats := m.statsCollector.GetStats()
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(stats)
        },
    })
    
    // 熔断器状态端点
    server.AddRoute(rest.Route{
        Method: http.MethodGet,
        Path:   "/middleware/circuit-breakers",
        Handler: func(w http.ResponseWriter, r *http.Request) {
            states := m.getCircuitBreakerStates()
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(states)
        },
    })
    
    // 健康检查端点
    server.AddRoute(rest.Route{
        Method: http.MethodGet,
        Path:   "/middleware/health",
        Handler: func(w http.ResponseWriter, r *http.Request) {
            health := m.getHealthStatus()
            w.Header().Set("Content-Type", "application/json")
            
            if health.Status == "unhealthy" {
                w.WriteHeader(http.StatusServiceUnavailable)
            }
            
            json.NewEncoder(w).Encode(health)
        },
    })
}

type HealthStatus struct {
    Status     string                    `json:"status"`
    Timestamp  time.Time                 `json:"timestamp"`
    Middleware map[string]MiddlewareHealth `json:"middleware"`
}

type MiddlewareHealth struct {
    Status        string        `json:"status"`
    ErrorRate     float64       `json:"error_rate"`
    AvgDuration   time.Duration `json:"avg_duration"`
    CircuitState  string        `json:"circuit_state"`
}

func (m *MiddlewareManager) getHealthStatus() HealthStatus {
    stats := m.statsCollector.GetStats()
    health := HealthStatus{
        Status:     "healthy",
        Timestamp:  time.Now(),
        Middleware: make(map[string]MiddlewareHealth),
    }
    
    for name, stat := range stats {
        errorRate := float64(stat.TotalErrors) / float64(stat.TotalRequests)
        
        middlewareHealth := MiddlewareHealth{
            Status:       "healthy",
            ErrorRate:    errorRate,
            AvgDuration:  stat.AvgDuration,
            CircuitState: m.getCircuitBreakerState(name),
        }
        
        // 判断中间件健康状态
        if errorRate > 0.1 { // 错误率超过10%
            middlewareHealth.Status = "unhealthy"
            health.Status = "degraded"
        }
        
        if stat.AvgDuration > 5*time.Second { // 平均响应时间超过5秒
            middlewareHealth.Status = "slow"
            if health.Status == "healthy" {
                health.Status = "degraded"
            }
        }
        
        health.Middleware[name] = middlewareHealth
    }
    
    return health
}
```

## 📊 配置优化

### 新增配置项

```go
type FrameworkConfig struct {
    // 监控配置
    MonitoringEnabled   bool `json:"MonitoringEnabled,default=true"`
    MetricsEnabled      bool `json:"MetricsEnabled,default=true"`
    
    // 熔断器配置
    CircuitBreakerEnabled bool `json:"CircuitBreakerEnabled,default=true"`
    FailureThreshold      int  `json:"FailureThreshold,default=5"`
    RecoveryTimeout       int  `json:"RecoveryTimeout,default=30"` // seconds
    
    // 配置热更新
    HotReloadEnabled    bool `json:"HotReloadEnabled,default=true"`
    
    // 性能阈值
    SlowMiddlewareThreshold int `json:"SlowMiddlewareThreshold,default=1000"` // ms
}
```

## 🧪 测试策略

### 1. 监控测试
```go
func TestMiddlewareMonitoring(t *testing.T) {
    // 测试统计信息收集
    // 测试Prometheus指标
    // 测试性能基准
}
```

### 2. 熔断器测试
```go
func TestCircuitBreaker(t *testing.T) {
    // 测试故障检测
    // 测试自动恢复
    // 测试状态转换
}
```

### 3. 配置热更新测试
```go
func TestConfigHotReload(t *testing.T) {
    // 测试配置变更响应
    // 测试配置验证
    // 测试降级处理
}
```

## 📈 预期效果

### 可观测性提升
- 完整的中间件性能监控
- Prometheus指标集成
- 实时健康状态检查

### 稳定性加强
- 故障自动隔离
- 熔断器保护机制
- Panic自动恢复

### 运维便利性
- 配置热更新能力
- 详细的监控API
- 智能故障诊断

## ⚠️ 注意事项

1. **性能影响**: 监控代码本身不能显著影响性能
2. **内存使用**: 统计数据收集要控制内存消耗
3. **熔断精度**: 避免过度敏感导致误熔断
4. **配置安全**: 热更新要验证配置有效性

## 🚀 实施优先级

1. **P2**: 性能监控实现（可观测性）
2. **P2**: 插件故障隔离（稳定性）
3. **P3**: 动态配置热更新（运维便利）
4. **P3**: 监控API和健康检查（完整性）

## 📋 验收标准

- [ ] 中间件性能监控正常工作
- [ ] 熔断器正确保护系统
- [ ] 配置热更新及时生效
- [ ] 监控API返回准确数据
- [ ] 所有现有功能保持正常
- [ ] 监控开销控制在合理范围内