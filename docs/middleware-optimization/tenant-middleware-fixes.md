# 租户检查中间件优化修复方案

## 📍 位置
`/opt/code/newbee/common/middleware/tenant/plugin.go`

## 🎯 修复目标
完善租户检查中间件的功能，增加租户状态验证、成员验证和配额控制，保持简洁的设计不变。

## 🔍 问题分析

### P1级别问题（功能完善）

#### 1. 高级租户验证功能缺失
**位置**: `tenant/plugin.go:69-71` 
**问题**: 注释提到的租户状态检查、成员验证功能未实现
**影响**: 无法防止访问被暂停或无效的租户数据

#### 2. 租户配额和限流缺失
**问题**: 缺少租户级别的资源配额和请求限流
**影响**: 无法防止租户资源滥用，影响多租户公平性

#### 3. 动态配置支持缺失
**问题**: 租户状态变更无法实时生效
**影响**: 租户暂停后需要重启服务才能生效

#### 4. 租户隔离验证不完整
**问题**: 缺少租户隔离完整性验证
**风险**: 可能存在跨租户数据泄露风险

## 🛠️ 修复方案

### 1. 租户状态验证实现

```go
import (
    "encoding/json"
    "sync"
    "time"
)

// 租户信息结构
type TenantInfo struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Status      TenantStatus           `json:"status"`
    ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
    Quota       *TenantQuota           `json:"quota,omitempty"`
    Members     map[string]TenantRole  `json:"members,omitempty"`
    Config      map[string]interface{} `json:"config,omitempty"`
    UpdatedAt   time.Time              `json:"updated_at"`
}

type TenantStatus string

const (
    TenantStatusActive     TenantStatus = "active"
    TenantStatusSuspended  TenantStatus = "suspended" 
    TenantStatusExpired    TenantStatus = "expired"
    TenantStatusInactive   TenantStatus = "inactive"
)

type TenantRole string

const (
    TenantRoleOwner  TenantRole = "owner"
    TenantRoleAdmin  TenantRole = "admin"
    TenantRoleMember TenantRole = "member"
    TenantRoleGuest  TenantRole = "guest"
)

type TenantQuota struct {
    MaxRequests    int64 `json:"max_requests"`     // 每分钟最大请求数
    MaxUsers       int64 `json:"max_users"`        // 最大用户数
    MaxStorage     int64 `json:"max_storage"`      // 最大存储空间(MB)
    MaxConnections int64 `json:"max_connections"`  // 最大并发连接数
}

// 租户缓存管理器
type TenantCacheManager struct {
    cache      *sync.Map                    // 租户信息缓存
    limiter    map[string]*TenantLimiter    // 租户限流器
    limiterMux sync.RWMutex                 // 限流器读写锁
    redis      redis.Cmdable                // Redis客户端
    ctx        context.Context              // 上下文
}

func NewTenantCacheManager(redis redis.Cmdable, ctx context.Context) *TenantCacheManager {
    return &TenantCacheManager{
        cache:   &sync.Map{},
        limiter: make(map[string]*TenantLimiter),
        redis:   redis,
        ctx:     ctx,
    }
}

// 获取租户信息（带缓存）
func (tcm *TenantCacheManager) GetTenantInfo(tenantID string) (*TenantInfo, error) {
    // 检查本地缓存
    if value, ok := tcm.cache.Load(tenantID); ok {
        tenantInfo := value.(*TenantInfo)
        // 检查缓存是否过期（5分钟TTL）
        if time.Since(tenantInfo.UpdatedAt) < 5*time.Minute {
            return tenantInfo, nil
        }
        // 过期则删除
        tcm.cache.Delete(tenantID)
    }
    
    // 从Redis获取
    key := fmt.Sprintf("tenant_info:%s", tenantID)
    result, err := tcm.redis.Get(tcm.ctx, key).Result()
    if err != nil {
        if err == redis.Nil {
            return nil, fmt.Errorf("tenant not found: %s", tenantID)
        }
        return nil, fmt.Errorf("failed to get tenant info: %w", err)
    }
    
    var tenantInfo TenantInfo
    if err := json.Unmarshal([]byte(result), &tenantInfo); err != nil {
        return nil, fmt.Errorf("failed to parse tenant info: %w", err)
    }
    
    // 更新本地缓存
    tenantInfo.UpdatedAt = time.Now()
    tcm.cache.Store(tenantID, &tenantInfo)
    
    return &tenantInfo, nil
}

// 验证用户是否为租户成员
func (tcm *TenantCacheManager) ValidateTenantMembership(tenantID, userID string) (TenantRole, error) {
    tenantInfo, err := tcm.GetTenantInfo(tenantID)
    if err != nil {
        return "", err
    }
    
    if tenantInfo.Members == nil {
        return "", fmt.Errorf("user %s is not a member of tenant %s", userID, tenantID)
    }
    
    role, exists := tenantInfo.Members[userID]
    if !exists {
        return "", fmt.Errorf("user %s is not a member of tenant %s", userID, tenantID)
    }
    
    return role, nil
}

// 在 TenantCheckPlugin 中集成高级验证
type TenantCheckPlugin struct {
    core         *framework.CoreServices
    config       *framework.TenantCheckConfig
    cacheManager *TenantCacheManager  // 新增缓存管理器
}

func (p *TenantCheckPlugin) Init(core *framework.CoreServices) error {
    p.core = core
    p.config = core.Config.TenantCheck
    
    if p.config == nil || !p.config.Enabled {
        return fmt.Errorf("tenantcheck config is missing or disabled")
    }
    
    // 初始化租户缓存管理器
    if core.Redis != nil {
        p.cacheManager = NewTenantCacheManager(core.Redis, core.Context)
        
        // 启动配置监听
        go p.startTenantConfigListener()
    }
    
    return nil
}

// 增强的租户检查逻辑
func (p *TenantCheckPlugin) validateTenant(ctx context.Context, tenantID string) error {
    if p.cacheManager == nil {
        // 降级到基本验证
        return p.basicTenantValidation(tenantID)
    }
    
    // 1. 获取租户信息
    tenantInfo, err := p.cacheManager.GetTenantInfo(tenantID)
    if err != nil {
        logx.WithContext(ctx).Errorw("Failed to get tenant info", 
            logx.Field("tenantId", tenantID), 
            logx.Field("error", err))
        return fmt.Errorf("tenant validation failed: %w", err)
    }
    
    // 2. 检查租户状态
    switch tenantInfo.Status {
    case TenantStatusActive:
        // 继续后续检查
    case TenantStatusSuspended:
        return fmt.Errorf("tenant %s is suspended", tenantID)
    case TenantStatusExpired:
        return fmt.Errorf("tenant %s has expired", tenantID)
    case TenantStatusInactive:
        return fmt.Errorf("tenant %s is inactive", tenantID)
    default:
        return fmt.Errorf("tenant %s has invalid status: %s", tenantID, tenantInfo.Status)
    }
    
    // 3. 检查租户过期时间
    if tenantInfo.ExpiresAt != nil && time.Now().After(*tenantInfo.ExpiresAt) {
        return fmt.Errorf("tenant %s has expired at %v", tenantID, tenantInfo.ExpiresAt)
    }
    
    // 4. 检查用户成员身份
    cm := p.core.ContextManager
    userID := cm.GetUserID(ctx)
    if userID != "" && p.config.ValidateMembership {
        role, err := p.cacheManager.ValidateTenantMembership(tenantID, userID)
        if err != nil {
            logx.WithContext(ctx).Errorw("Tenant membership validation failed",
                logx.Field("tenantId", tenantID),
                logx.Field("userId", userID),
                logx.Field("error", err))
            return fmt.Errorf("access denied: not a member of tenant %s", tenantID)
        }
        
        // 将租户角色添加到上下文中（供其他中间件使用）
        ctx = context.WithValue(ctx, "tenant_role", string(role))
    }
    
    return nil
}
```

### 2. 租户限流和配额控制

```go
import (
    "golang.org/x/time/rate"
    "sync/atomic"
)

// 租户限流器
type TenantLimiter struct {
    tenantID       string
    requestLimiter *rate.Limiter     // 请求频率限制
    connections    int64             // 当前连接数
    maxConnections int64             // 最大连接数
    quota          *TenantQuota      // 租户配额
    createdAt      time.Time         // 创建时间
}

func NewTenantLimiter(tenantID string, quota *TenantQuota) *TenantLimiter {
    var requestLimiter *rate.Limiter
    if quota != nil && quota.MaxRequests > 0 {
        // 每分钟最大请求数转换为每秒
        requestsPerSecond := float64(quota.MaxRequests) / 60.0
        requestLimiter = rate.NewLimiter(rate.Limit(requestsPerSecond), int(quota.MaxRequests))
    } else {
        // 默认限制：每分钟1000请求
        requestLimiter = rate.NewLimiter(rate.Limit(16.67), 1000)
    }
    
    maxConn := int64(100) // 默认最大连接数
    if quota != nil && quota.MaxConnections > 0 {
        maxConn = quota.MaxConnections
    }
    
    return &TenantLimiter{
        tenantID:       tenantID,
        requestLimiter: requestLimiter,
        maxConnections: maxConn,
        createdAt:      time.Now(),
        quota:          quota,
    }
}

func (tl *TenantLimiter) AllowRequest() bool {
    return tl.requestLimiter.Allow()
}

func (tl *TenantLimiter) AcquireConnection() bool {
    current := atomic.LoadInt64(&tl.connections)
    if current >= tl.maxConnections {
        return false
    }
    atomic.AddInt64(&tl.connections, 1)
    return true
}

func (tl *TenantLimiter) ReleaseConnection() {
    atomic.AddInt64(&tl.connections, -1)
}

func (tl *TenantLimiter) GetStats() map[string]interface{} {
    return map[string]interface{}{
        "tenant_id":      tl.tenantID,
        "connections":    atomic.LoadInt64(&tl.connections),
        "max_connections": tl.maxConnections,
        "created_at":     tl.createdAt,
    }
}

// 获取或创建租户限流器
func (tcm *TenantCacheManager) GetTenantLimiter(tenantID string) (*TenantLimiter, error) {
    tcm.limiterMux.RLock()
    if limiter, exists := tcm.limiter[tenantID]; exists {
        tcm.limiterMux.RUnlock()
        return limiter, nil
    }
    tcm.limiterMux.RUnlock()
    
    // 获取租户信息以获取配额
    tenantInfo, err := tcm.GetTenantInfo(tenantID)
    if err != nil {
        return nil, err
    }
    
    tcm.limiterMux.Lock()
    defer tcm.limiterMux.Unlock()
    
    // 双重检查
    if limiter, exists := tcm.limiter[tenantID]; exists {
        return limiter, nil
    }
    
    // 创建新的限流器
    limiter := NewTenantLimiter(tenantID, tenantInfo.Quota)
    tcm.limiter[tenantID] = limiter
    
    return limiter, nil
}

// 集成到中间件中
func (p *TenantCheckPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if p.shouldSkip(r.URL.Path) {
            next(w, r)
            return
        }

        ctx := r.Context()
        cm := p.core.ContextManager
        tenantID := cm.GetTenantID(ctx)

        if tenantID == "" {
            logx.WithContext(ctx).Error("TenantCheckPlugin: Missing tenant ID in context after authentication.")
            p.writeForbidden(w, "Access denied: No tenant information available")
            return
        }

        // 增强的租户验证
        if err := p.validateTenant(ctx, tenantID); err != nil {
            logx.WithContext(ctx).Errorw("Tenant validation failed", 
                logx.Field("tenantId", tenantID), 
                logx.Field("error", err))
            p.writeForbidden(w, "Access denied: Tenant validation failed")
            return
        }

        // 租户限流检查
        if p.cacheManager != nil && p.config.RateLimitEnabled {
            limiter, err := p.cacheManager.GetTenantLimiter(tenantID)
            if err != nil {
                logx.WithContext(ctx).Errorw("Failed to get tenant limiter", 
                    logx.Field("tenantId", tenantID), 
                    logx.Field("error", err))
                // 不因限流器失败而拒绝请求，记录错误继续
            } else {
                // 检查请求频率限制
                if !limiter.AllowRequest() {
                    logx.WithContext(ctx).Warnw("Request rate limit exceeded", 
                        logx.Field("tenantId", tenantID))
                    p.writeRateLimited(w, "Request rate limit exceeded")
                    return
                }
                
                // 检查连接数限制
                if !limiter.AcquireConnection() {
                    logx.WithContext(ctx).Warnw("Connection limit exceeded", 
                        logx.Field("tenantId", tenantID))
                    p.writeRateLimited(w, "Connection limit exceeded")
                    return
                }
                
                // 在请求完成后释放连接
                defer limiter.ReleaseConnection()
            }
        }

        logx.WithContext(ctx).Infof("Tenant check passed for TenantID: %s", tenantID)
        next(w, r.WithContext(ctx))
    }
}
```

### 3. 动态配置热更新

```go
// 租户配置变更监听
func (p *TenantCheckPlugin) startTenantConfigListener() {
    if p.core.Redis == nil {
        return
    }
    
    pubsub := p.core.Redis.Subscribe(p.core.Context, "tenant_config_changes")
    defer pubsub.Close()
    
    ch := pubsub.Channel()
    for msg := range ch {
        var event TenantConfigChangeEvent
        if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
            logx.Error("Failed to parse tenant config change event", logx.Field("error", err))
            continue
        }
        
        p.handleTenantConfigChange(event)
    }
}

type TenantConfigChangeEvent struct {
    TenantID  string    `json:"tenant_id"`
    Action    string    `json:"action"` // "update", "suspend", "activate", "delete"
    Changes   map[string]interface{} `json:"changes"`
    Timestamp time.Time `json:"timestamp"`
}

func (p *TenantCheckPlugin) handleTenantConfigChange(event TenantConfigChangeEvent) {
    logx.Infow("Processing tenant config change", 
        logx.Field("tenantId", event.TenantID),
        logx.Field("action", event.Action))
    
    if p.cacheManager == nil {
        return
    }
    
    switch event.Action {
    case "update", "activate":
        // 清除缓存，强制重新加载
        p.cacheManager.cache.Delete(event.TenantID)
        
        // 如果配额变更，更新限流器
        if changes, ok := event.Changes["quota"].(map[string]interface{}); ok {
            p.updateTenantLimiter(event.TenantID, changes)
        }
        
    case "suspend", "delete":
        // 清除缓存
        p.cacheManager.cache.Delete(event.TenantID)
        
        // 移除限流器
        p.cacheManager.limiterMux.Lock()
        delete(p.cacheManager.limiter, event.TenantID)
        p.cacheManager.limiterMux.Unlock()
        
    default:
        logx.Warnw("Unknown tenant config change action", 
            logx.Field("action", event.Action))
    }
}

func (p *TenantCheckPlugin) updateTenantLimiter(tenantID string, quotaChanges map[string]interface{}) {
    p.cacheManager.limiterMux.Lock()
    defer p.cacheManager.limiterMux.Unlock()
    
    // 移除旧的限流器
    delete(p.cacheManager.limiter, tenantID)
    
    // 新的限流器会在下次请求时根据新配额创建
    logx.Infow("Tenant limiter configuration updated", 
        logx.Field("tenantId", tenantID))
}
```

### 4. 错误响应优化

```go
func (p *TenantCheckPlugin) writeForbidden(w http.ResponseWriter, message string) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.WriteHeader(http.StatusForbidden)
    response := fmt.Sprintf(`{"code":40003,"message":"%s","data":null}`, message)
    w.Write([]byte(response))
}

func (p *TenantCheckPlugin) writeRateLimited(w http.ResponseWriter, message string) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Retry-After", "60") // 建议60秒后重试
    w.WriteHeader(http.StatusTooManyRequests)
    response := fmt.Sprintf(`{"code":42901,"message":"%s","data":null}`, message)
    w.Write([]byte(response))
}
```

## 📊 配置优化

### 新增配置项

```go
type TenantCheckConfig struct {
    Enabled   bool     `json:"Enabled,optional"`
    SkipPaths []string `json:"SkipPaths,optional"`
    
    // 高级验证配置
    ValidateMembership  bool `json:"ValidateMembership,default=true"`
    ValidateExpiry      bool `json:"ValidateExpiry,default=true"`
    
    // 限流配置
    RateLimitEnabled    bool `json:"RateLimitEnabled,default=true"`
    
    // 缓存配置
    CacheEnabled        bool `json:"CacheEnabled,default=true"`
    CacheTTLMinutes     int  `json:"CacheTTLMinutes,default=5"`
    
    // 热更新配置
    HotReloadEnabled    bool `json:"HotReloadEnabled,default=true"`
}
```

## 🧪 测试策略

### 1. 租户状态测试
```go
func TestTenantStatusValidation(t *testing.T) {
    // 测试活跃租户通过验证
    // 测试暂停租户被拒绝
    // 测试过期租户被拒绝
}
```

### 2. 限流测试
```go
func TestTenantRateLimit(t *testing.T) {
    // 测试请求频率限制
    // 测试连接数限制
    // 测试限流器恢复机制
}
```

### 3. 热更新测试
```go
func TestConfigHotReload(t *testing.T) {
    // 测试租户配置变更实时生效
    // 测试缓存清理
    // 测试限流器更新
}
```

## 📈 预期效果

### 功能完善
- 支持完整的租户生命周期管理
- 实现租户成员身份验证
- 提供细粒度的配额控制

### 性能优化
- 租户信息缓存减少Redis查询
- 智能限流保护系统稳定性
- 热更新避免服务重启

### 安全加固
- 防止无效租户访问
- 租户间资源隔离保证
- 实时配置变更响应

## ⚠️ 注意事项

1. **缓存一致性**: 租户配置变更时及时清理缓存
2. **限流公平性**: 确保限流策略不影响正常用户
3. **热更新可靠性**: 配置变更监听不能影响主业务
4. **兼容性**: 新增功能对现有系统向后兼容

## 🚀 实施优先级

1. **P1**: 租户状态验证实现（核心功能）
2. **P1**: 租户成员身份验证（安全加固）  
3. **P2**: 限流和配额控制（性能保护）
4. **P2**: 动态配置热更新（运维便利）

## 📋 验收标准

- [ ] 租户状态验证正常工作
- [ ] 成员身份验证生效
- [ ] 限流机制正确保护系统
- [ ] 配置热更新及时生效
- [ ] 所有现有功能保持正常
- [ ] 性能影响在可接受范围内