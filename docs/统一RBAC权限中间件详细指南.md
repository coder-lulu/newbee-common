# 统一RBAC权限中间件详细指南

## 目录

1. [概述](#概述)
2. [核心架构](#核心架构)
3. [快速开始](#快速开始)
4. [详细配置](#详细配置)
5. [Casbin集成](#casbin集成)
6. [权限模型设计](#权限模型设计)
7. [高级特性](#高级特性)
8. [性能优化](#性能优化)
9. [最佳实践](#最佳实践)
10. [故障排除](#故障排除)
11. [API参考](#api参考)
12. [迁移指南](#迁移指南)

---

## 概述

### 什么是统一RBAC权限中间件

统一RBAC权限中间件是NewBee架构中负责**基于角色的访问控制**的核心组件。它通过**Casbin权限引擎**和**灵活的权限模型**，实现了接口级别的细粒度权限控制，支持复杂的组织架构和业务场景。

### 核心特性

#### 🔐 强大的权限控制
- **基于角色的访问控制(RBAC)** - 支持用户-角色-权限的经典模型
- **层次化角色继承** - 支持角色继承和权限继承
- **细粒度权限控制** - 精确到接口和操作级别
- **动态权限检查** - 实时验证用户权限，支持权限实时变更

#### 🧠 智能权限引擎
- **Casbin集成** - 基于业界标准的权限控制框架
- **多种权限模型** - RBAC、ABAC、RESTful等模型支持
- **灵活的策略语言** - 支持复杂的权限策略表达
- **高性能匹配** - 优化的权限匹配算法

#### 🚀 高性能设计
- **智能缓存策略** - 多级缓存提升权限检查性能
- **权限预加载** - 批量加载减少数据库查询
- **并发安全** - 线程安全的权限检查
- **内存优化** - 对象池化和内存复用

#### 📊 丰富的管理功能
- **权限可视化** - 权限关系图形化展示
- **权限继承追踪** - 权限来源透明化
- **权限冲突检测** - 自动检测权限冲突
- **权限审计** - 完整的权限变更记录

### 系统要求

- Go 1.21+
- Casbin v2.0+
- Redis 6.0+ (可选，用于权限缓存)
- NewBee Common >= v1.0.0

---

## 核心架构

### 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                      HTTP/gRPC请求                              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   统一RBAC权限中间件                             │
│  ┌─────────────────┬─────────────────┬─────────────────────────┐ │
│  │   权限拦截器    │   Casbin引擎    │    权限缓存管理器        │ │
│  │                 │                 │                         │ │
│  │ • 请求解析      │ • 策略加载      │ • 多级缓存策略          │ │
│  │ • 用户识别      │ • 权限匹配      │ • 缓存失效管理          │ │
│  │ • 权限检查      │ • 结果计算      │ • 性能监控              │ │
│  └─────────────────┴─────────────────┴─────────────────────────┘ │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    权限决策引擎                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ • 策略评估引擎    • 角色继承计算     • 权限聚合算法        │ │
│  │ • 冲突解决机制    • 上下文分析      • 决策日志记录        │ │
│  │ • 动态策略加载    • 权限推导       • 结果缓存            │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     存储层                                       │
│  ┌─────────────────┬─────────────────┬─────────────────────────┐ │
│  │  策略存储       │   缓存存储      │      元数据存储          │ │
│  │                 │                 │                         │ │
│  │ • 权限策略      │ • 权限结果缓存   │ • 角色定义数据          │ │
│  │ • 角色定义      │ • 用户角色缓存   │ • 权限元数据            │ │
│  │ • 用户角色映射   │ • 策略编译缓存   │ • 变更历史记录          │ │
│  └─────────────────┴─────────────────┴─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 核心组件

#### RbacPlugin - RBAC权限插件主体
```go
type RbacPlugin struct {
    core     *framework.CoreServices
    config   *framework.PermissionConfig
    enforcer *casbin.Enforcer
    provider EnforcerProvider
    logger   *logging.MiddlewareLogger
    
    // 缓存管理
    permissionCache *PermissionCache
    roleCache       *RoleCache
    
    // 性能监控
    metrics         *RBACMetrics
    performanceMonitor *PerformanceMonitor
}
```

**主要职责**：
- 拦截HTTP/gRPC请求进行权限检查
- 协调Casbin执行权限验证
- 管理权限缓存和性能优化
- 提供权限检查的统一接口

#### EnforcerProvider - 权限执行器提供者
```go
type EnforcerProvider interface {
    GetCasbinEnforcer() interface{}
}

type CasbinEnforcerManager struct {
    enforcer    *casbin.Enforcer
    watcher     persist.Watcher
    adapter     persist.Adapter
    modelPath   string
    policyPath  string
    autoSave    bool
    autoLoad    bool
    logger      *logging.MiddlewareLogger
}
```

**主要职责**：
- 管理Casbin执行器的生命周期
- 提供权限策略的动态加载和更新
- 支持分布式权限策略同步
- 处理权限策略的持久化

#### PermissionCache - 权限缓存管理器
```go
type PermissionCache struct {
    localCache  *sync.Map
    redisCache  redis.UniversalClient
    cacheConfig CacheConfig
    stats       *CacheStats
    cleaner     *CacheCleaner
}

type CacheConfig struct {
    TTL                time.Duration
    LocalCacheSize     int
    RedisCacheEnabled  bool
    InvalidationEnabled bool
    PrefetchEnabled    bool
}
```

**主要职责**：
- 实现多级权限缓存策略
- 管理缓存失效和更新
- 提供缓存性能统计
- 支持权限预加载

#### RoleHierarchyManager - 角色层级管理器
```go
type RoleHierarchyManager struct {
    hierarchyTree *RoleTree
    inheritanceMap map[string][]string
    conflictResolver *ConflictResolver
    logger         *logging.MiddlewareLogger
}

type RoleTree struct {
    Root     *RoleNode
    NodeMap  map[string]*RoleNode
    MaxDepth int
}

type RoleNode struct {
    RoleCode    string
    Children    []*RoleNode
    Parent      *RoleNode
    Permissions []Permission
    Metadata    map[string]interface{}
}
```

**主要职责**：
- 管理角色继承关系
- 计算有效权限集合
- 检测和解决权限冲突
- 提供角色关系查询

---

## 快速开始

### 5分钟集成指南

#### 步骤1: 基础配置

**配置文件** (`etc/config.yaml`):
```yaml
Permission:
  Enabled: true
  CasbinEnabled: true
  
  # Casbin配置
  Casbin:
    ModelPath: "./conf/rbac_model.conf"
    PolicyPath: "./conf/policy.csv"
    AutoLoad: true
    AutoSave: true
    
  # 缓存配置
  Cache:
    Enabled: true
    TTL: "10m"
    LocalCacheSize: 10000
    RedisCacheEnabled: true
    
  # 跳过权限检查的路径
  SkipPaths:
    - "/health"
    - "/metrics"
    - "/captcha"
    - "/auth/login"
```

#### 步骤2: Casbin模型配置

**RBAC with Domains模型文件** (`conf/rbac_model.conf`):
```ini
# 🔥 RBAC with Domains 模型 - 支持多租户域隔离
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act, eft

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, r.dom, p.sub) && r.dom == p.dom && keyMatch2(r.obj,p.obj) && r.act == p.act
```

> **注**: 从v2.0开始,NewBee统一使用RBAC with Domains模型实现租户级别的权限隔离。domain参数对应租户ID(格式:`tenant_{tenant_id}`),确保不同租户的权限规则完全隔离。

**权限策略文件** (`conf/policy.csv`):
```csv
# 策略规则 (p): subject, domain, object, action, effect
p, admin, tenant_1, /user/*, *, allow
p, admin, tenant_1, /role/*, *, allow
p, admin, tenant_1, /permission/*, *, allow
p, manager, tenant_1, /user/list, GET, allow
p, manager, tenant_1, /user/create, POST, allow
p, manager, tenant_1, /user/update, PUT, allow
p, employee, tenant_1, /user/profile, GET, allow
p, employee, tenant_1, /user/profile, PUT, allow

# 角色继承 (g): user, role, domain
g, alice, admin, tenant_1
g, bob, manager, tenant_1
g, charlie, employee, tenant_1
g, david, employee, tenant_1
```

> **注**: 策略规则和角色继承都包含domain参数(租户域),实现租户级别的完全隔离。

#### 步骤3: ServiceContext集成

```go
package svc

import (
    "github.com/coder-lulu/newbee-common/middleware/permission"
    "github.com/casbin/casbin/v2"
    "github.com/casbin/casbin/v2/persist/file-adapter"
)

type ServiceContext struct {
    Config      config.Config
    RbacPlugin  framework.MiddlewarePlugin
}

func NewServiceContext(c config.Config) *ServiceContext {
    // 创建Casbin enforcer
    enforcer, err := casbin.NewEnforcer(c.Permission.Casbin.ModelPath, c.Permission.Casbin.PolicyPath)
    if err != nil {
        panic("初始化Casbin失败: " + err.Error())
    }
    
    // 创建RBAC插件
    rbacPlugin := permission.NewRbacPluginWithEnforcer(enforcer)
    
    return &ServiceContext{
        Config:     c,
        RbacPlugin: rbacPlugin,
    }
}
```

#### 步骤4: API集成

```go
@server(
    group: user
    middleware: Authority,RBAC  // 添加RBAC权限中间件
)
service Core {
    @handler createUser
    post /user/create (CreateUserReq) returns (CreateUserResp)
    
    @handler listUsers
    get /user/list returns (UserListResp)
    
    @handler updateUser
    put /user/:id (UpdateUserReq) returns (UpdateUserResp)
    
    @handler deleteUser
    delete /user/:id returns (BaseResp)
}
```

#### 步骤5: 验证权限控制

```bash
# 1. 使用admin角色token（应该成功）
curl -X POST http://localhost:8000/user/create \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"测试用户","role":"employee"}'

# 2. 使用employee角色token（应该失败，403）
curl -X POST http://localhost:8000/user/create \
  -H "Authorization: Bearer <employee_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"测试用户","role":"employee"}'

# 3. 查看权限检查日志
curl -X GET http://localhost:8000/admin/rbac/logs \
  -H "Authorization: Bearer <admin_token>"
```

---

## 详细配置

### 核心配置项

#### PermissionConfig 结构
```go
type PermissionConfig struct {
    // 基础配置
    Enabled       bool     `json:"enabled"`
    CasbinEnabled bool     `json:"casbin_enabled"`
    SkipPaths     []string `json:"skip_paths"`
    
    // Casbin配置
    Casbin        CasbinConfig        `json:"casbin"`
    
    // 缓存配置
    Cache         PermissionCacheConfig `json:"cache"`
    
    // 角色层级配置
    RoleHierarchy RoleHierarchyConfig `json:"role_hierarchy"`
    
    // 性能配置
    Performance   PerformanceConfig   `json:"performance"`
    
    // 监控配置
    Monitoring    MonitoringConfig    `json:"monitoring"`
}
```

#### Casbin配置详解
```go
type CasbinConfig struct {
    ModelPath       string `json:"model_path"`        // 权限模型文件路径
    PolicyPath      string `json:"policy_path"`       // 策略文件路径
    AutoLoad        bool   `json:"auto_load"`         // 自动加载策略
    AutoSave        bool   `json:"auto_save"`         // 自动保存策略
    WatcherEnabled  bool   `json:"watcher_enabled"`   // 启用策略监控
    
    // 数据库适配器配置
    DatabaseAdapter struct {
        Enabled    bool   `json:"enabled"`
        DriverName string `json:"driver_name"`   // mysql, postgresql, sqlite
        DataSource string `json:"data_source"`   // 数据库连接字符串
        TableName  string `json:"table_name"`    // 策略表名
    } `json:"database_adapter"`
    
    // Redis适配器配置
    RedisAdapter struct {
        Enabled  bool   `json:"enabled"`
        Address  string `json:"address"`
        Password string `json:"password"`
        DB       int    `json:"db"`
        KeyPrefix string `json:"key_prefix"`
    } `json:"redis_adapter"`
    
    // 性能配置
    Performance struct {
        EnableG          bool `json:"enable_g"`           // 启用角色继承
        EnableLog        bool `json:"enable_log"`         // 启用日志
        EnableAutoSave   bool `json:"enable_auto_save"`   // 启用自动保存
        AutoLoadPolicy   bool `json:"auto_load_policy"`   // 自动加载策略
    } `json:"performance"`
}
```

#### 缓存配置优化
```go
type PermissionCacheConfig struct {
    Enabled           bool          `json:"enabled"`
    TTL               time.Duration `json:"ttl"`
    LocalCacheSize    int           `json:"local_cache_size"`
    RedisCacheEnabled bool          `json:"redis_cache_enabled"`
    
    // 缓存策略
    Strategy struct {
        WriteThrough    bool `json:"write_through"`     // 写入时更新缓存
        WriteBack       bool `json:"write_back"`        // 延迟写入
        ReadThrough     bool `json:"read_through"`      // 缓存穿透保护
        RefreshAhead    bool `json:"refresh_ahead"`     // 预刷新
    } `json:"strategy"`
    
    // 失效策略
    Invalidation struct {
        Enabled         bool          `json:"enabled"`
        PubSubEnabled   bool          `json:"pubsub_enabled"`   // Redis发布订阅失效
        TimeBasedEnabled bool         `json:"time_based_enabled"` // 基于时间失效
        EventBasedEnabled bool        `json:"event_based_enabled"` // 基于事件失效
    } `json:"invalidation"`
    
    // 预加载配置
    Preload struct {
        Enabled         bool     `json:"enabled"`
        UserRoles       bool     `json:"user_roles"`       // 预加载用户角色
        RolePermissions bool     `json:"role_permissions"` // 预加载角色权限
        CommonPatterns  []string `json:"common_patterns"`  // 常用权限模式
    } `json:"preload"`
}
```

### 环境配置示例

#### 开发环境配置
```yaml
Permission:
  Enabled: true
  CasbinEnabled: true
  SkipPaths:
    - "/health"
    - "/debug/*"
    - "/swagger/*"
    
  Casbin:
    ModelPath: "./conf/rbac_model.conf"
    PolicyPath: "./conf/policy_dev.csv"
    AutoLoad: true
    AutoSave: true
    WatcherEnabled: true
    Performance:
      EnableLog: true
      EnableAutoSave: true
      
  Cache:
    Enabled: false  # 开发环境关闭缓存，便于调试
    TTL: "1m"
    
  Monitoring:
    MetricsEnabled: true
    LogLevel: "debug"
    PerformanceLogging: true
```

#### 生产环境配置
```yaml
Permission:
  Enabled: true
  CasbinEnabled: true
  SkipPaths:
    - "/health"
    - "/metrics"
    
  Casbin:
    ModelPath: "./conf/rbac_model.conf"
    DatabaseAdapter:
      Enabled: true
      DriverName: "mysql"
      DataSource: "rbac_user:password@tcp(mysql-cluster:3306)/rbac_db"
      TableName: "casbin_policy"
    AutoLoad: true
    AutoSave: true
    WatcherEnabled: true
    Performance:
      EnableG: true
      EnableLog: false  # 生产环境关闭详细日志
      EnableAutoSave: true
      
  Cache:
    Enabled: true
    TTL: "30m"
    LocalCacheSize: 50000
    RedisCacheEnabled: true
    Strategy:
      WriteThrough: true
      ReadThrough: true
      RefreshAhead: true
    Invalidation:
      Enabled: true
      PubSubEnabled: true
      EventBasedEnabled: true
    Preload:
      Enabled: true
      UserRoles: true
      RolePermissions: true
      CommonPatterns:
        - "/user/*"
        - "/role/*"
        - "/permission/*"
        
  RoleHierarchy:
    Enabled: true
    MaxDepth: 10
    ConflictResolution: "deny_overrides"  # allow_overrides, deny_overrides, first_applicable
    
  Performance:
    MaxConcurrentChecks: 10000
    CheckTimeout: "5s"
    CircuitBreaker:
      Enabled: true
      FailureThreshold: 100
      TimeoutDuration: "30s"
      
  Monitoring:
    MetricsEnabled: true
    LogLevel: "info"
    PerformanceLogging: false
    AlertingEnabled: true
```

---

## Casbin集成

### 权限模型设计

#### RBAC with Domains模型 (推荐)
```ini
# 🔥 NewBee标准权限模型 - RBAC with Domains
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act, eft

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, r.dom, p.sub) && r.dom == p.dom && keyMatch2(r.obj,p.obj) && r.act == p.act
```

**模型说明**:
- `sub`: 主体(subject),可以是用户ID或角色编码
- `dom`: 域(domain),对应租户ID,格式为`tenant_{tenant_id}`
- `obj`: 对象(object),资源路径或标识符
- `act`: 操作(action),如GET、POST、PUT、DELETE等
- `eft`: 效果(effect),allow或deny

**核心优势**:
- ✅ **租户隔离**: domain参数确保不同租户权限完全隔离
- ✅ **显式可见**: 从规则本身就能看出租户归属
- ✅ **防止误操作**: 即使误操作也不会跨租户
- ✅ **便于调试**: 可直接查询特定租户的规则

#### RESTful权限模型 (支持通配符)
```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act, eft

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, r.dom, p.sub) && r.dom == p.dom && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
```

**适用场景**: 需要支持路径通配符和正则表达式匹配的RESTful API权限控制。

### 权限策略管理

#### 动态策略加载器
```go
type PolicyManager struct {
    enforcer    *casbin.Enforcer
    adapter     persist.Adapter
    watcher     persist.Watcher
    policyCache *PolicyCache
    loader      *PolicyLoader
    logger      *logging.MiddlewareLogger
}

func (pm *PolicyManager) LoadPoliciesFromDatabase() error {
    // 1. 从数据库加载策略
    policies, err := pm.adapter.LoadPolicy(pm.enforcer.GetModel())
    if err != nil {
        return fmt.Errorf("加载策略失败: %w", err)
    }
    
    // 2. 解析和验证策略
    validPolicies := pm.validatePolicies(policies)
    
    // 3. 批量添加策略
    success, err := pm.enforcer.AddPolicies(validPolicies)
    if err != nil {
        return fmt.Errorf("添加策略失败: %w", err)
    }
    
    pm.logger.WithField("loaded_policies", len(validPolicies)).
        WithField("success", success).
        Info("策略加载完成")
    
    return nil
}

func (pm *PolicyManager) AddPolicy(subject, object, action string) error {
    // 1. 验证策略参数
    if err := pm.validatePolicyParams(subject, object, action); err != nil {
        return err
    }
    
    // 2. 检查策略是否已存在
    if pm.enforcer.HasPolicy(subject, object, action) {
        return fmt.Errorf("策略已存在: %s, %s, %s", subject, object, action)
    }
    
    // 3. 添加策略
    success, err := pm.enforcer.AddPolicy(subject, object, action)
    if err != nil {
        return fmt.Errorf("添加策略失败: %w", err)
    }
    
    if success {
        // 4. 清除相关缓存
        pm.policyCache.InvalidateBySubject(subject)
        
        // 5. 记录策略变更
        pm.logPolicyChange("add", subject, object, action)
    }
    
    return nil
}

func (pm *PolicyManager) RemovePolicy(subject, object, action string) error {
    success, err := pm.enforcer.RemovePolicy(subject, object, action)
    if err != nil {
        return fmt.Errorf("删除策略失败: %w", err)
    }
    
    if success {
        pm.policyCache.InvalidateBySubject(subject)
        pm.logPolicyChange("remove", subject, object, action)
    }
    
    return nil
}
```

#### 策略热更新
```go
type PolicyWatcher struct {
    enforcer    *casbin.Enforcer
    redisClient redis.UniversalClient
    pubsub      *redis.PubSub
    callback    func(string)
    logger      *logging.MiddlewareLogger
}

func (pw *PolicyWatcher) StartWatching() error {
    // 订阅策略变更通知
    pw.pubsub = pw.redisClient.Subscribe(context.Background(), "casbin_policy_update")
    
    go func() {
        defer pw.pubsub.Close()
        
        for msg := range pw.pubsub.Channel() {
            pw.handlePolicyUpdate(msg.Payload)
        }
    }()
    
    return nil
}

func (pw *PolicyWatcher) handlePolicyUpdate(payload string) {
    var updateEvent PolicyUpdateEvent
    if err := json.Unmarshal([]byte(payload), &updateEvent); err != nil {
        pw.logger.WithError(err).Error("解析策略更新事件失败")
        return
    }
    
    switch updateEvent.Type {
    case "policy_add":
        pw.enforcer.AddPolicy(updateEvent.Subject, updateEvent.Object, updateEvent.Action)
    case "policy_remove":
        pw.enforcer.RemovePolicy(updateEvent.Subject, updateEvent.Object, updateEvent.Action)
    case "role_add":
        pw.enforcer.AddGroupingPolicy(updateEvent.User, updateEvent.Role)
    case "role_remove":
        pw.enforcer.RemoveGroupingPolicy(updateEvent.User, updateEvent.Role)
    case "reload_all":
        pw.enforcer.LoadPolicy()
    }
    
    pw.logger.WithField("event", updateEvent).Info("策略更新完成")
}

func (pw *PolicyWatcher) NotifyPolicyUpdate(event PolicyUpdateEvent) error {
    data, err := json.Marshal(event)
    if err != nil {
        return err
    }
    
    return pw.redisClient.Publish(context.Background(), "casbin_policy_update", data).Err()
}
```

### 角色继承实现

#### 层次化角色管理
```go
type RoleHierarchy struct {
    hierarchy   map[string][]string  // 角色 -> 子角色列表
    inheritance map[string][]string  // 角色 -> 继承的角色列表
    permissions map[string][]Permission // 角色 -> 直接权限列表
    mutex       sync.RWMutex
    logger      *logging.MiddlewareLogger
}

func (rh *RoleHierarchy) AddRoleInheritance(child, parent string) error {
    rh.mutex.Lock()
    defer rh.mutex.Unlock()
    
    // 检查是否会造成循环继承
    if rh.wouldCreateCycle(child, parent) {
        return fmt.Errorf("添加继承关系会造成循环依赖: %s -> %s", child, parent)
    }
    
    // 添加继承关系
    if rh.inheritance[child] == nil {
        rh.inheritance[child] = make([]string, 0)
    }
    
    // 检查是否已存在
    for _, inherited := range rh.inheritance[child] {
        if inherited == parent {
            return fmt.Errorf("继承关系已存在: %s -> %s", child, parent)
        }
    }
    
    rh.inheritance[child] = append(rh.inheritance[child], parent)
    
    // 更新层级关系
    if rh.hierarchy[parent] == nil {
        rh.hierarchy[parent] = make([]string, 0)
    }
    rh.hierarchy[parent] = append(rh.hierarchy[parent], child)
    
    rh.logger.WithField("child", child).WithField("parent", parent).Info("添加角色继承关系")
    
    return nil
}

func (rh *RoleHierarchy) GetEffectivePermissions(role string) []Permission {
    rh.mutex.RLock()
    defer rh.mutex.RUnlock()
    
    visited := make(map[string]bool)
    permissions := make(map[string]Permission)
    
    rh.collectPermissions(role, visited, permissions)
    
    // 转换为切片
    result := make([]Permission, 0, len(permissions))
    for _, perm := range permissions {
        result = append(result, perm)
    }
    
    return result
}

func (rh *RoleHierarchy) collectPermissions(role string, visited map[string]bool, permissions map[string]Permission) {
    if visited[role] {
        return // 避免循环
    }
    visited[role] = true
    
    // 添加直接权限
    if rolePerms, exists := rh.permissions[role]; exists {
        for _, perm := range rolePerms {
            permKey := fmt.Sprintf("%s:%s:%s", perm.Object, perm.Action, perm.Effect)
            
            // 权限冲突解决：拒绝优先
            if existing, exists := permissions[permKey]; exists {
                if existing.Effect == "deny" || perm.Effect == "deny" {
                    perm.Effect = "deny"
                }
            }
            
            permissions[permKey] = perm
        }
    }
    
    // 递归收集继承的权限
    if inherited, exists := rh.inheritance[role]; exists {
        for _, parentRole := range inherited {
            rh.collectPermissions(parentRole, visited, permissions)
        }
    }
}

func (rh *RoleHierarchy) wouldCreateCycle(child, parent string) bool {
    // 使用DFS检测循环
    visited := make(map[string]bool)
    return rh.hasCycleDFS(parent, child, visited)
}

func (rh *RoleHierarchy) hasCycleDFS(current, target string, visited map[string]bool) bool {
    if current == target {
        return true
    }
    
    if visited[current] {
        return false
    }
    visited[current] = true
    
    if inherited, exists := rh.inheritance[current]; exists {
        for _, parent := range inherited {
            if rh.hasCycleDFS(parent, target, visited) {
                return true
            }
        }
    }
    
    return false
}
```

---

## 权限模型设计

### 经典RBAC模型

#### 基础组件关系
```
用户(User) ──── 角色(Role) ──── 权限(Permission)
     │              │               │
     │              │               ├── 对象(Object)
     │              │               ├── 操作(Action)  
     │              │               └── 效果(Effect)
     │              │
     │              └── 角色继承(Role Inheritance)
     │
     └── 用户属性(User Attributes)
```

#### 数据模型定义
```go
type User struct {
    ID          uint64            `json:"id"`
    Username    string            `json:"username"`
    Roles       []string          `json:"roles"`
    Attributes  map[string]string `json:"attributes"`
    TenantID    string            `json:"tenant_id"`
    Status      string            `json:"status"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

type Role struct {
    Code        string            `json:"code"`
    Name        string            `json:"name"`
    Description string            `json:"description"`
    Permissions []Permission      `json:"permissions"`
    Children    []string          `json:"children"`    // 子角色
    Parents     []string          `json:"parents"`     // 父角色
    Attributes  map[string]string `json:"attributes"`
    TenantID    string            `json:"tenant_id"`
    Status      string            `json:"status"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

type Permission struct {
    ID          uint64            `json:"id"`
    Code        string            `json:"code"`
    Name        string            `json:"name"`
    Object      string            `json:"object"`      // 资源对象
    Action      string            `json:"action"`      // 操作类型
    Effect      string            `json:"effect"`      // allow/deny
    Conditions  []Condition       `json:"conditions"`  // 权限条件
    Attributes  map[string]string `json:"attributes"`
    TenantID    string            `json:"tenant_id"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

type Condition struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`
    Value    interface{} `json:"value"`
}
```

### 高级权限模型

#### ABAC（基于属性的访问控制）扩展
```go
type ABACPolicy struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Description string                 `json:"description"`
    Effect      string                 `json:"effect"`  // allow/deny
    Conditions  ABACCondition          `json:"conditions"`
    Priority    int                    `json:"priority"`
    Status      string                 `json:"status"`
}

type ABACCondition struct {
    Subject  SubjectCondition  `json:"subject"`
    Object   ObjectCondition   `json:"object"`
    Action   ActionCondition   `json:"action"`
    Context  ContextCondition  `json:"context"`
    Logic    string           `json:"logic"`  // AND/OR
}

type SubjectCondition struct {
    UserID       []string          `json:"user_id,omitempty"`
    Roles        []string          `json:"roles,omitempty"`
    Departments  []string          `json:"departments,omitempty"`
    Attributes   map[string]string `json:"attributes,omitempty"`
}

type ObjectCondition struct {
    Resources    []string          `json:"resources,omitempty"`
    ResourceType []string          `json:"resource_type,omitempty"`
    Owners       []string          `json:"owners,omitempty"`
    Attributes   map[string]string `json:"attributes,omitempty"`
}

type ActionCondition struct {
    Actions      []string          `json:"actions,omitempty"`
    Methods      []string          `json:"methods,omitempty"`
    Operations   []string          `json:"operations,omitempty"`
}

type ContextCondition struct {
    TimeRange    TimeRange         `json:"time_range,omitempty"`
    IPRange      []string          `json:"ip_range,omitempty"`
    Location     []string          `json:"location,omitempty"`
    Environment  string            `json:"environment,omitempty"`
    Attributes   map[string]string `json:"attributes,omitempty"`
}
```

#### 上下文感知权限检查
```go
type ContextAwarePermissionChecker struct {
    baseChecker    PermissionChecker
    contextExtractor ContextExtractor
    abacEvaluator  ABACEvaluator
    logger         *logging.MiddlewareLogger
}

func (checker *ContextAwarePermissionChecker) CheckPermission(ctx context.Context, subject, object, action string) (bool, error) {
    // 1. 提取上下文信息
    permissionContext := checker.contextExtractor.Extract(ctx)
    
    // 2. 基础RBAC检查
    rbacResult, err := checker.baseChecker.CheckPermission(ctx, subject, object, action)
    if err != nil {
        return false, err
    }
    
    // 3. ABAC条件检查
    abacResult := checker.abacEvaluator.Evaluate(permissionContext, subject, object, action)
    
    // 4. 组合结果
    finalResult := checker.combineResults(rbacResult, abacResult)
    
    checker.logger.WithField("subject", subject).
        WithField("object", object).
        WithField("action", action).
        WithField("rbac_result", rbacResult).
        WithField("abac_result", abacResult).
        WithField("final_result", finalResult).
        Debug("权限检查完成")
    
    return finalResult, nil
}

type PermissionContext struct {
    UserID      string            `json:"user_id"`
    Roles       []string          `json:"roles"`
    Departments []string          `json:"departments"`
    TenantID    string            `json:"tenant_id"`
    ClientIP    string            `json:"client_ip"`
    UserAgent   string            `json:"user_agent"`
    Timestamp   time.Time         `json:"timestamp"`
    Attributes  map[string]string `json:"attributes"`
}

func (extractor *ContextExtractor) Extract(ctx context.Context) *PermissionContext {
    permCtx := &PermissionContext{
        Timestamp:  time.Now(),
        Attributes: make(map[string]string),
    }
    
    // 从context中提取信息
    if userID, ok := ctx.Value("user_id").(string); ok {
        permCtx.UserID = userID
    }
    
    if roles, ok := ctx.Value("roles").([]string); ok {
        permCtx.Roles = roles
    }
    
    if tenantID, ok := ctx.Value("tenant_id").(string); ok {
        permCtx.TenantID = tenantID
    }
    
    // 从HTTP请求中提取信息
    if req, ok := ctx.Value("http_request").(*http.Request); ok {
        permCtx.ClientIP = extractClientIP(req)
        permCtx.UserAgent = req.UserAgent()
    }
    
    return permCtx
}
```

---

## 高级特性

### 权限缓存优化

#### 多级缓存架构
```go
type MultiLevelPermissionCache struct {
    l1Cache    *sync.Map           // 内存缓存（最快）
    l2Cache    redis.UniversalClient // Redis缓存（中等）
    l3Cache    AuditStorage        // 数据库缓存（最慢）
    config     CacheConfig
    stats      *CacheStats
    logger     *logging.MiddlewareLogger
}

func (cache *MultiLevelPermissionCache) Get(key string) (*PermissionResult, bool) {
    // L1缓存查找
    if value, ok := cache.l1Cache.Load(key); ok {
        cache.stats.L1Hits.Inc()
        return value.(*PermissionResult), true
    }
    
    // L2缓存查找
    if cache.l2Cache != nil {
        if value, err := cache.l2Cache.Get(context.Background(), key).Result(); err == nil {
            var result PermissionResult
            if json.Unmarshal([]byte(value), &result) == nil {
                // 回填L1缓存
                cache.l1Cache.Store(key, &result)
                cache.stats.L2Hits.Inc()
                return &result, true
            }
        }
    }
    
    cache.stats.CacheMisses.Inc()
    return nil, false
}

func (cache *MultiLevelPermissionCache) Set(key string, result *PermissionResult, ttl time.Duration) {
    // 设置L1缓存
    cache.l1Cache.Store(key, result)
    
    // 设置L2缓存
    if cache.l2Cache != nil {
        if data, err := json.Marshal(result); err == nil {
            cache.l2Cache.Set(context.Background(), key, data, ttl)
        }
    }
    
    cache.stats.CacheWrites.Inc()
}
```

#### 智能缓存失效
```go
type SmartCacheInvalidator struct {
    cache          *MultiLevelPermissionCache
    changeDetector *PermissionChangeDetector
    invalidationRules []InvalidationRule
    pubsub         redis.UniversalClient
    logger         *logging.MiddlewareLogger
}

type InvalidationRule struct {
    Pattern    string
    Scope      string  // user, role, permission, global
    TTL        time.Duration
    Conditions []InvalidationCondition
}

func (invalidator *SmartCacheInvalidator) OnPermissionChange(event *PermissionChangeEvent) {
    // 根据变更类型确定失效范围
    switch event.Type {
    case "user_role_change":
        invalidator.invalidateUserPermissions(event.UserID)
    case "role_permission_change":
        invalidator.invalidateRolePermissions(event.RoleCode)
    case "policy_change":
        invalidator.invalidatePatternPermissions(event.Pattern)
    case "global_reload":
        invalidator.invalidateAllPermissions()
    }
}

func (invalidator *SmartCacheInvalidator) invalidateUserPermissions(userID string) {
    // 生成用户相关的缓存键模式
    patterns := []string{
        fmt.Sprintf("perm:user:%s:*", userID),
        fmt.Sprintf("role:user:%s", userID),
    }
    
    for _, pattern := range patterns {
        invalidator.invalidateByPattern(pattern)
    }
    
    // 发布失效通知
    event := CacheInvalidationEvent{
        Type:    "user_permission_invalidation",
        UserID:  userID,
        Patterns: patterns,
        Timestamp: time.Now(),
    }
    
    invalidator.publishInvalidationEvent(event)
}

func (invalidator *SmartCacheInvalidator) invalidateByPattern(pattern string) {
    // L1缓存失效
    invalidator.cache.l1Cache.Range(func(key, value interface{}) bool {
        keyStr := key.(string)
        if matched, _ := filepath.Match(pattern, keyStr); matched {
            invalidator.cache.l1Cache.Delete(key)
        }
        return true
    })
    
    // L2缓存失效
    if invalidator.cache.l2Cache != nil {
        keys, err := invalidator.cache.l2Cache.Keys(context.Background(), pattern).Result()
        if err == nil && len(keys) > 0 {
            invalidator.cache.l2Cache.Del(context.Background(), keys...)
        }
    }
}
```

### 权限预加载

#### 智能预加载策略
```go
type PermissionPreloader struct {
    cache      *MultiLevelPermissionCache
    enforcer   *casbin.Enforcer
    predictor  *AccessPatternPredictor
    scheduler  *PreloadScheduler
    config     PreloadConfig
    logger     *logging.MiddlewareLogger
}

type PreloadConfig struct {
    Enabled         bool          `json:"enabled"`
    PreloadUsers    []string      `json:"preload_users"`    // 预加载的用户列表
    PreloadRoles    []string      `json:"preload_roles"`    // 预加载的角色列表
    PreloadPatterns []string      `json:"preload_patterns"` // 预加载的权限模式
    BatchSize       int           `json:"batch_size"`
    Interval        time.Duration `json:"interval"`
    MaxConcurrency  int           `json:"max_concurrency"`
}

func (preloader *PermissionPreloader) StartPreloading() {
    if !preloader.config.Enabled {
        return
    }
    
    // 启动定期预加载
    ticker := time.NewTicker(preloader.config.Interval)
    go func() {
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                preloader.performPreload()
            }
        }
    }()
}

func (preloader *PermissionPreloader) performPreload() {
    // 1. 获取预测的访问模式
    patterns := preloader.predictor.PredictAccessPatterns()
    
    // 2. 批量预加载权限
    semaphore := make(chan struct{}, preloader.config.MaxConcurrency)
    var wg sync.WaitGroup
    
    for _, pattern := range patterns {
        wg.Add(1)
        go func(p AccessPattern) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            
            preloader.preloadPattern(p)
        }(pattern)
    }
    
    wg.Wait()
    
    preloader.logger.WithField("patterns_loaded", len(patterns)).Info("权限预加载完成")
}

func (preloader *PermissionPreloader) preloadPattern(pattern AccessPattern) {
    cacheKey := fmt.Sprintf("perm:%s:%s:%s", pattern.Subject, pattern.Object, pattern.Action)
    
    // 检查缓存是否已存在
    if _, exists := preloader.cache.Get(cacheKey); exists {
        return
    }
    
    // 执行权限检查并缓存结果
    allowed, err := preloader.enforcer.Enforce(pattern.Subject, pattern.Object, pattern.Action)
    if err != nil {
        preloader.logger.WithError(err).WithField("pattern", pattern).Warn("预加载权限检查失败")
        return
    }
    
    result := &PermissionResult{
        Allowed:   allowed,
        Subject:   pattern.Subject,
        Object:    pattern.Object,
        Action:    pattern.Action,
        Timestamp: time.Now(),
        FromCache: false,
    }
    
    // 缓存结果
    preloader.cache.Set(cacheKey, result, preloader.config.Interval*2)
}
```

#### 访问模式预测
```go
type AccessPatternPredictor struct {
    historyAnalyzer *AccessHistoryAnalyzer
    mlModel         *AccessPredictionModel
    config          PredictorConfig
    logger          *logging.MiddlewareLogger
}

type AccessPattern struct {
    Subject     string    `json:"subject"`
    Object      string    `json:"object"`
    Action      string    `json:"action"`
    Frequency   int       `json:"frequency"`
    LastAccess  time.Time `json:"last_access"`
    Probability float64   `json:"probability"`
}

func (predictor *AccessPatternPredictor) PredictAccessPatterns() []AccessPattern {
    // 1. 分析历史访问数据
    historicalPatterns := predictor.historyAnalyzer.GetRecentPatterns(24 * time.Hour)
    
    // 2. 应用机器学习模型预测
    predictedPatterns := predictor.mlModel.Predict(historicalPatterns)
    
    // 3. 过滤和排序
    filteredPatterns := predictor.filterPatterns(predictedPatterns)
    
    // 4. 按概率排序
    sort.Slice(filteredPatterns, func(i, j int) bool {
        return filteredPatterns[i].Probability > filteredPatterns[j].Probability
    })
    
    // 5. 取前N个最可能的模式
    maxPatterns := predictor.config.MaxPredictions
    if len(filteredPatterns) > maxPatterns {
        filteredPatterns = filteredPatterns[:maxPatterns]
    }
    
    return filteredPatterns
}

func (predictor *AccessPatternPredictor) filterPatterns(patterns []AccessPattern) []AccessPattern {
    var filtered []AccessPattern
    
    for _, pattern := range patterns {
        // 过滤低概率的模式
        if pattern.Probability < predictor.config.MinProbability {
            continue
        }
        
        // 过滤太久没有访问的模式
        if time.Since(pattern.LastAccess) > predictor.config.MaxAge {
            continue
        }
        
        // 过滤频率太低的模式
        if pattern.Frequency < predictor.config.MinFrequency {
            continue
        }
        
        filtered = append(filtered, pattern)
    }
    
    return filtered
}
```

### 权限冲突检测

#### 冲突检测引擎
```go
type ConflictDetectionEngine struct {
    enforcer       *casbin.Enforcer
    policyAnalyzer *PolicyAnalyzer
    resolver       *ConflictResolver
    logger         *logging.MiddlewareLogger
}

type PermissionConflict struct {
    Type        ConflictType      `json:"type"`
    Severity    ConflictSeverity  `json:"severity"`
    Subject     string            `json:"subject"`
    Object      string            `json:"object"`
    Action      string            `json:"action"`
    Policies    []string          `json:"policies"`
    Description string            `json:"description"`
    Resolution  string            `json:"resolution"`
    DetectedAt  time.Time         `json:"detected_at"`
}

type ConflictType string

const (
    ConflictTypeRolePermission ConflictType = "role_permission"
    ConflictTypeInheritance    ConflictType = "inheritance"
    ConflictTypePolicyDuplicate ConflictType = "policy_duplicate"
    ConflictTypeCircularDependency ConflictType = "circular_dependency"
)

func (engine *ConflictDetectionEngine) DetectConflicts() []PermissionConflict {
    var conflicts []PermissionConflict
    
    // 1. 检测角色权限冲突
    roleConflicts := engine.detectRolePermissionConflicts()
    conflicts = append(conflicts, roleConflicts...)
    
    // 2. 检测继承冲突
    inheritanceConflicts := engine.detectInheritanceConflicts()
    conflicts = append(conflicts, inheritanceConflicts...)
    
    // 3. 检测策略重复
    duplicateConflicts := engine.detectDuplicatePolicies()
    conflicts = append(conflicts, duplicateConflicts...)
    
    // 4. 检测循环依赖
    circularConflicts := engine.detectCircularDependencies()
    conflicts = append(conflicts, circularConflicts...)
    
    return conflicts
}

func (engine *ConflictDetectionEngine) detectRolePermissionConflicts() []PermissionConflict {
    var conflicts []PermissionConflict
    
    // 获取所有策略
    policies := engine.enforcer.GetPolicy()
    
    // 按主体分组
    subjectPolicies := make(map[string][][]string)
    for _, policy := range policies {
        if len(policy) >= 3 {
            subject := policy[0]
            subjectPolicies[subject] = append(subjectPolicies[subject], policy)
        }
    }
    
    // 检测每个主体的冲突
    for subject, policiesList := range subjectPolicies {
        resourceActions := make(map[string][]string)
        
        for _, policy := range policiesList {
            resource := policy[1]
            action := policy[2]
            effect := "allow"
            if len(policy) > 3 {
                effect = policy[3]
            }
            
            key := fmt.Sprintf("%s:%s", resource, action)
            resourceActions[key] = append(resourceActions[key], effect)
        }
        
        // 检测allow和deny冲突
        for resourceAction, effects := range resourceActions {
            hasAllow := false
            hasDeny := false
            
            for _, effect := range effects {
                if effect == "allow" {
                    hasAllow = true
                } else if effect == "deny" {
                    hasDeny = true
                }
            }
            
            if hasAllow && hasDeny {
                parts := strings.Split(resourceAction, ":")
                conflict := PermissionConflict{
                    Type:        ConflictTypeRolePermission,
                    Severity:    ConflictSeverityHigh,
                    Subject:     subject,
                    Object:      parts[0],
                    Action:      parts[1],
                    Description: fmt.Sprintf("主体 %s 对资源 %s 的操作 %s 既有允许又有拒绝策略", subject, parts[0], parts[1]),
                    Resolution:  "建议明确优先级或删除冲突策略",
                    DetectedAt:  time.Now(),
                }
                conflicts = append(conflicts, conflict)
            }
        }
    }
    
    return conflicts
}

func (engine *ConflictDetectionEngine) detectCircularDependencies() []PermissionConflict {
    var conflicts []PermissionConflict
    
    // 获取所有角色继承关系
    groupingPolicies := engine.enforcer.GetGroupingPolicy()
    
    // 构建依赖图
    dependencies := make(map[string][]string)
    for _, policy := range groupingPolicies {
        if len(policy) >= 2 {
            child := policy[0]
            parent := policy[1]
            dependencies[child] = append(dependencies[child], parent)
        }
    }
    
    // 使用DFS检测循环
    visited := make(map[string]bool)
    recursionStack := make(map[string]bool)
    
    for node := range dependencies {
        if !visited[node] {
            if cycle := engine.findCycleDFS(node, dependencies, visited, recursionStack, []string{}); len(cycle) > 0 {
                conflict := PermissionConflict{
                    Type:        ConflictTypeCircularDependency,
                    Severity:    ConflictSeverityCritical,
                    Description: fmt.Sprintf("检测到循环依赖: %s", strings.Join(cycle, " -> ")),
                    Resolution:  "删除循环中的一个或多个继承关系",
                    DetectedAt:  time.Now(),
                }
                conflicts = append(conflicts, conflict)
            }
        }
    }
    
    return conflicts
}

func (engine *ConflictDetectionEngine) findCycleDFS(node string, dependencies map[string][]string, visited, recursionStack map[string]bool, path []string) []string {
    visited[node] = true
    recursionStack[node] = true
    path = append(path, node)
    
    for _, neighbor := range dependencies[node] {
        if !visited[neighbor] {
            if cycle := engine.findCycleDFS(neighbor, dependencies, visited, recursionStack, path); len(cycle) > 0 {
                return cycle
            }
        } else if recursionStack[neighbor] {
            // 找到循环
            cycleStart := -1
            for i, p := range path {
                if p == neighbor {
                    cycleStart = i
                    break
                }
            }
            if cycleStart >= 0 {
                return append(path[cycleStart:], neighbor)
            }
        }
    }
    
    recursionStack[node] = false
    return nil
}
```

---

## 性能优化

### 权限检查优化

#### 批量权限检查
```go
type BatchPermissionChecker struct {
    enforcer     *casbin.Enforcer
    cache        *MultiLevelPermissionCache
    config       BatchConfig
    workerPool   *WorkerPool
    resultAggregator *ResultAggregator
    logger       *logging.MiddlewareLogger
}

type BatchPermissionRequest struct {
    RequestID string             `json:"request_id"`
    Checks    []PermissionCheck  `json:"checks"`
    Context   context.Context    `json:"-"`
    Callback  func([]PermissionResult) `json:"-"`
}

type PermissionCheck struct {
    Subject string `json:"subject"`
    Object  string `json:"object"`
    Action  string `json:"action"`
}

func (checker *BatchPermissionChecker) CheckBatch(request *BatchPermissionRequest) error {
    // 1. 分离缓存命中和未命中的检查
    cached, uncached := checker.separateCachedChecks(request.Checks)
    
    // 2. 并行处理未缓存的检查
    uncachedResults := checker.processUncachedChecks(uncached)
    
    // 3. 合并结果
    allResults := checker.mergeResults(cached, uncachedResults)
    
    // 4. 执行回调
    if request.Callback != nil {
        request.Callback(allResults)
    }
    
    return nil
}

func (checker *BatchPermissionChecker) separateCachedChecks(checks []PermissionCheck) ([]PermissionResult, []PermissionCheck) {
    var cached []PermissionResult
    var uncached []PermissionCheck
    
    for _, check := range checks {
        cacheKey := checker.generateCacheKey(check.Subject, check.Object, check.Action)
        if result, exists := checker.cache.Get(cacheKey); exists {
            cached = append(cached, *result)
        } else {
            uncached = append(uncached, check)
        }
    }
    
    return cached, uncached
}

func (checker *BatchPermissionChecker) processUncachedChecks(checks []PermissionCheck) []PermissionResult {
    if len(checks) == 0 {
        return nil
    }
    
    results := make([]PermissionResult, len(checks))
    
    // 使用worker池并行处理
    jobs := make(chan BatchJob, len(checks))
    resultChan := make(chan BatchJobResult, len(checks))
    
    // 启动workers
    for i := 0; i < checker.config.WorkerCount; i++ {
        go checker.worker(jobs, resultChan)
    }
    
    // 提交任务
    for i, check := range checks {
        jobs <- BatchJob{
            Index: i,
            Check: check,
        }
    }
    close(jobs)
    
    // 收集结果
    for i := 0; i < len(checks); i++ {
        result := <-resultChan
        results[result.Index] = result.Result
        
        // 缓存结果
        cacheKey := checker.generateCacheKey(result.Result.Subject, result.Result.Object, result.Result.Action)
        checker.cache.Set(cacheKey, &result.Result, checker.config.CacheTTL)
    }
    
    return results
}

func (checker *BatchPermissionChecker) worker(jobs <-chan BatchJob, results chan<- BatchJobResult) {
    for job := range jobs {
        start := time.Now()
        
        allowed, err := checker.enforcer.Enforce(job.Check.Subject, job.Check.Object, job.Check.Action)
        
        result := BatchJobResult{
            Index: job.Index,
            Result: PermissionResult{
                Subject:     job.Check.Subject,
                Object:      job.Check.Object,
                Action:      job.Check.Action,
                Allowed:     allowed,
                Error:       err,
                CheckTime:   time.Now(),
                Duration:    time.Since(start),
                FromCache:   false,
            },
        }
        
        results <- result
    }
}
```

#### 权限预编译
```go
type PermissionCompiler struct {
    enforcer     *casbin.Enforcer
    compiler     *PolicyCompiler
    compiledCache *CompiledPolicyCache
    logger       *logging.MiddlewareLogger
}

type CompiledPolicy struct {
    Pattern     string               `json:"pattern"`
    Conditions  []CompiledCondition  `json:"conditions"`
    Effect      string               `json:"effect"`
    CompiledAt  time.Time            `json:"compiled_at"`
    Version     string               `json:"version"`
}

type CompiledCondition struct {
    Type      string      `json:"type"`
    Field     string      `json:"field"`
    Operator  string      `json:"operator"`
    Value     interface{} `json:"value"`
    Regex     *regexp.Regexp `json:"-"`
}

func (compiler *PermissionCompiler) CompilePolicies() error {
    // 1. 获取所有策略
    policies := compiler.enforcer.GetPolicy()
    
    // 2. 编译策略
    compiledPolicies := make([]CompiledPolicy, 0, len(policies))
    
    for _, policy := range policies {
        if len(policy) >= 3 {
            compiled, err := compiler.compilePolicy(policy)
            if err != nil {
                compiler.logger.WithError(err).WithField("policy", policy).Warn("策略编译失败")
                continue
            }
            compiledPolicies = append(compiledPolicies, compiled)
        }
    }
    
    // 3. 更新缓存
    compiler.compiledCache.UpdatePolicies(compiledPolicies)
    
    compiler.logger.WithField("compiled_count", len(compiledPolicies)).Info("策略编译完成")
    
    return nil
}

func (compiler *PermissionCompiler) compilePolicy(policy []string) (CompiledPolicy, error) {
    subject := policy[0]
    object := policy[1]
    action := policy[2]
    effect := "allow"
    if len(policy) > 3 {
        effect = policy[3]
    }
    
    compiled := CompiledPolicy{
        Pattern:    fmt.Sprintf("%s:%s:%s", subject, object, action),
        Effect:     effect,
        CompiledAt: time.Now(),
        Version:    compiler.generateVersion(policy),
    }
    
    // 编译条件
    conditions := make([]CompiledCondition, 0)
    
    // 编译对象匹配条件
    if strings.Contains(object, "*") || strings.Contains(object, "/") {
        condition := CompiledCondition{
            Type:     "path_match",
            Field:    "object",
            Operator: "match",
            Value:    object,
        }
        
        // 预编译正则表达式
        if regex, err := compiler.compilePathPattern(object); err == nil {
            condition.Regex = regex
        }
        
        conditions = append(conditions, condition)
    }
    
    // 编译动作匹配条件
    if strings.Contains(action, "*") {
        condition := CompiledCondition{
            Type:     "action_match",
            Field:    "action",
            Operator: "match",
            Value:    action,
        }
        
        if regex, err := compiler.compileActionPattern(action); err == nil {
            condition.Regex = regex
        }
        
        conditions = append(conditions, condition)
    }
    
    compiled.Conditions = conditions
    
    return compiled, nil
}

func (compiler *PermissionCompiler) compilePathPattern(pattern string) (*regexp.Regexp, error) {
    // 将路径模式转换为正则表达式
    escaped := regexp.QuoteMeta(pattern)
    escaped = strings.ReplaceAll(escaped, "\\*", ".*")
    escaped = strings.ReplaceAll(escaped, "\\?", ".")
    
    return regexp.Compile("^" + escaped + "$")
}
```

### 内存优化

#### 对象池化
```go
var (
    // 权限检查结果对象池
    permissionResultPool = sync.Pool{
        New: func() interface{} {
            return &PermissionResult{}
        },
    }
    
    // 权限检查请求对象池
    permissionCheckPool = sync.Pool{
        New: func() interface{} {
            return &PermissionCheck{}
        },
    }
    
    // 字符串构建器池
    stringBuilderPool = sync.Pool{
        New: func() interface{} {
            builder := &strings.Builder{}
            builder.Grow(256)
            return builder
        },
    }
)

func GetPermissionResult() *PermissionResult {
    result := permissionResultPool.Get().(*PermissionResult)
    result.Reset()
    return result
}

func PutPermissionResult(result *PermissionResult) {
    if result != nil {
        permissionResultPool.Put(result)
    }
}

func (r *PermissionResult) Reset() {
    r.Subject = ""
    r.Object = ""
    r.Action = ""
    r.Allowed = false
    r.Error = nil
    r.CheckTime = time.Time{}
    r.Duration = 0
    r.FromCache = false
    r.Metadata = nil
}
```

#### 内存监控
```go
type MemoryMonitor struct {
    permissionPlugin *RbacPlugin
    thresholds       MemoryThresholds
    alertManager     *AlertManager
    logger           *logging.MiddlewareLogger
}

type MemoryThresholds struct {
    Warning  uint64 `json:"warning"`   // 警告阈值
    Critical uint64 `json:"critical"`  // 严重阈值
    Max      uint64 `json:"max"`       // 最大内存限制
}

func (monitor *MemoryMonitor) StartMonitoring() {
    ticker := time.NewTicker(30 * time.Second)
    go func() {
        defer ticker.Stop()
        for range ticker.C {
            monitor.checkMemoryUsage()
        }
    }()
}

func (monitor *MemoryMonitor) checkMemoryUsage() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    currentUsage := m.Alloc
    
    // 检查阈值
    if currentUsage > monitor.thresholds.Critical {
        monitor.handleCriticalMemoryUsage(currentUsage)
    } else if currentUsage > monitor.thresholds.Warning {
        monitor.handleWarningMemoryUsage(currentUsage)
    }
    
    // 记录内存使用情况
    monitor.logger.WithField("memory_usage", currentUsage).
        WithField("heap_objects", m.HeapObjects).
        WithField("gc_cycles", m.NumGC).
        Debug("内存使用情况")
}

func (monitor *MemoryMonitor) handleCriticalMemoryUsage(usage uint64) {
    monitor.logger.WithField("memory_usage", usage).
        WithField("threshold", monitor.thresholds.Critical).
        Error("内存使用达到严重级别")
    
    // 紧急处理：清理缓存
    monitor.permissionPlugin.ClearCache()
    
    // 强制垃圾回收
    runtime.GC()
    
    // 发送告警
    monitor.alertManager.SendAlert(Alert{
        Type:     "memory_critical",
        Severity: "critical",
        Message:  fmt.Sprintf("权限模块内存使用达到严重级别: %d bytes", usage),
    })
}
```

---

## 最佳实践

### 权限模型设计原则

#### 1. 最小权限原则
```go
// ✅ 正确：按需分配权限
var DefaultRolePermissions = map[string][]Permission{
    "readonly": {
        {Object: "/user/profile", Action: "GET", Effect: "allow"},
        {Object: "/user/list", Action: "GET", Effect: "allow"},
    },
    "operator": {
        {Object: "/user/profile", Action: "GET", Effect: "allow"},
        {Object: "/user/profile", Action: "PUT", Effect: "allow"},
        {Object: "/user/list", Action: "GET", Effect: "allow"},
    },
    "admin": {
        {Object: "/user/*", Action: "*", Effect: "allow"},
        {Object: "/role/*", Action: "*", Effect: "allow"},
    },
}

// ❌ 错误：给予过多权限
var BadRolePermissions = map[string][]Permission{
    "operator": {
        {Object: "/*", Action: "*", Effect: "allow"}, // 危险：给操作员所有权限
    },
}
```

#### 2. 角色继承设计
```go
// ✅ 正确：合理的角色继承层次
type RoleHierarchy struct {
    // 基础角色
    "guest": {
        Parents: nil,
        Permissions: []string{"public:read"},
    },
    
    // 用户角色
    "user": {
        Parents: []string{"guest"},
        Permissions: []string{"profile:read", "profile:update"},
    },
    
    // 操作员角色
    "operator": {
        Parents: []string{"user"},
        Permissions: []string{"user:list", "user:search"},
    },
    
    // 管理员角色
    "admin": {
        Parents: []string{"operator"},
        Permissions: []string{"user:manage", "role:manage"},
    },
}

// ❌ 错误：复杂的继承关系
type BadRoleHierarchy struct {
    "role_a": {Parents: []string{"role_b", "role_c", "role_d"}}, // 多重继承容易冲突
    "role_b": {Parents: []string{"role_c"}},
    "role_c": {Parents: []string{"role_a"}}, // 循环继承
}
```

#### 3. 权限粒度控制
```go
// ✅ 正确：适当的权限粒度
type PermissionDesign struct {
    // 资源级权限
    UserResource: []Permission{
        {Object: "/user", Action: "create", Effect: "allow"},
        {Object: "/user", Action: "list", Effect: "allow"},
        {Object: "/user/:id", Action: "read", Effect: "allow"},
        {Object: "/user/:id", Action: "update", Effect: "allow"},
        {Object: "/user/:id", Action: "delete", Effect: "allow"},
    },
    
    // 功能级权限
    UserManagement: []Permission{
        {Object: "user_management", Action: "view_list", Effect: "allow"},
        {Object: "user_management", Action: "create_user", Effect: "allow"},
        {Object: "user_management", Action: "edit_user", Effect: "allow"},
    },
}

// ❌ 错误：权限粒度过细或过粗
type BadPermissionDesign struct {
    // 过细：每个字段都有权限
    TooFine: []Permission{
        {Object: "/user/name", Action: "read", Effect: "allow"},
        {Object: "/user/email", Action: "read", Effect: "allow"},
        {Object: "/user/phone", Action: "read", Effect: "allow"},
    },
    
    // 过粗：权限范围太大
    TooCoarse: []Permission{
        {Object: "/*", Action: "*", Effect: "allow"},
    },
}
```

### 安全最佳实践

#### 1. 防御性权限检查
```go
// ✅ 正确：多层权限验证
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
    userID := extractUserID(r)
    targetUserID := extractTargetUserID(r)
    
    // 1. 基础权限检查
    if !h.rbacChecker.HasPermission(userID, "/user/update", "PUT") {
        http.Error(w, "无权限", http.StatusForbidden)
        return
    }
    
    // 2. 资源级权限检查
    if !h.canUpdateUser(userID, targetUserID) {
        http.Error(w, "无权限修改此用户", http.StatusForbidden)
        return
    }
    
    // 3. 字段级权限检查
    allowedFields := h.getAllowedFields(userID, targetUserID)
    if !h.validateUpdateFields(r, allowedFields) {
        http.Error(w, "无权限修改某些字段", http.StatusForbidden)
        return
    }
    
    // 执行更新
    // ...
}

func (h *UserHandler) canUpdateUser(userID, targetUserID string) bool {
    // 检查是否为本人
    if userID == targetUserID {
        return true
    }
    
    // 检查是否有管理权限
    return h.rbacChecker.HasPermission(userID, "/user/manage", "*")
}

// ❌ 错误：单层权限检查
func (h *BadUserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
    userID := extractUserID(r)
    
    // 只检查接口权限，没有资源和字段级检查
    if !h.rbacChecker.HasPermission(userID, "/user/update", "PUT") {
        http.Error(w, "无权限", http.StatusForbidden)
        return
    }
    
    // 直接执行更新，存在安全风险
    // ...
}
```

#### 2. 权限缓存安全
```go
// ✅ 正确：安全的权限缓存
type SecurePermissionCache struct {
    cache       *sync.Map
    encryption  Encryptor
    ttl         time.Duration
    maxSize     int
    cleanupChan chan string
}

func (c *SecurePermissionCache) Set(key string, result *PermissionResult) {
    // 1. 敏感信息加密
    encryptedResult := c.encryption.Encrypt(result)
    
    // 2. 设置过期时间
    item := &CacheItem{
        Value:     encryptedResult,
        ExpireAt:  time.Now().Add(c.ttl),
        CreatedAt: time.Now(),
    }
    
    // 3. 检查缓存大小
    if c.size() >= c.maxSize {
        c.evictOldest()
    }
    
    c.cache.Store(key, item)
}

func (c *SecurePermissionCache) Get(key string) (*PermissionResult, bool) {
    value, ok := c.cache.Load(key)
    if !ok {
        return nil, false
    }
    
    item := value.(*CacheItem)
    
    // 检查过期
    if time.Now().After(item.ExpireAt) {
        c.cache.Delete(key)
        return nil, false
    }
    
    // 解密结果
    result := c.encryption.Decrypt(item.Value)
    return result, true
}

// ❌ 错误：不安全的权限缓存
type UnsafePermissionCache struct {
    cache map[string]*PermissionResult // 无加密，内存泄露
}

func (c *UnsafePermissionCache) Set(key string, result *PermissionResult) {
    c.cache[key] = result // 直接存储，无过期，无大小限制
}
```

### 性能优化实践

#### 1. 权限检查优化
```go
// ✅ 正确：批量和异步权限检查
type OptimizedPermissionService struct {
    batchChecker *BatchPermissionChecker
    asyncChecker *AsyncPermissionChecker
    cache        *PermissionCache
}

func (s *OptimizedPermissionService) CheckMultiplePermissions(userID string, permissions []Permission) map[string]bool {
    // 1. 批量检查减少网络开销
    checks := make([]PermissionCheck, len(permissions))
    for i, perm := range permissions {
        checks[i] = PermissionCheck{
            Subject: userID,
            Object:  perm.Object,
            Action:  perm.Action,
        }
    }
    
    results := s.batchChecker.CheckBatch(checks)
    
    // 2. 转换结果格式
    resultMap := make(map[string]bool)
    for i, result := range results {
        key := fmt.Sprintf("%s:%s", permissions[i].Object, permissions[i].Action)
        resultMap[key] = result.Allowed
    }
    
    return resultMap
}

func (s *OptimizedPermissionService) PreloadUserPermissions(userID string) {
    // 异步预加载用户常用权限
    go func() {
        commonPermissions := s.getCommonPermissions(userID)
        s.CheckMultiplePermissions(userID, commonPermissions)
    }()
}

// ❌ 错误：逐个同步检查
type SlowPermissionService struct {
    checker PermissionChecker
}

func (s *SlowPermissionService) CheckMultiplePermissions(userID string, permissions []Permission) map[string]bool {
    resultMap := make(map[string]bool)
    
    // 逐个检查，性能差
    for _, perm := range permissions {
        allowed := s.checker.Check(userID, perm.Object, perm.Action)
        key := fmt.Sprintf("%s:%s", perm.Object, perm.Action)
        resultMap[key] = allowed
    }
    
    return resultMap
}
```

#### 2. 缓存策略优化
```go
// ✅ 正确：智能缓存策略
type SmartCacheStrategy struct {
    frequencyTracker *AccessFrequencyTracker
    ttlCalculator    *DynamicTTLCalculator
    prefetcher       *PermissionPrefetcher
}

func (s *SmartCacheStrategy) GetCacheTTL(userID, object, action string) time.Duration {
    // 1. 基于访问频率动态调整TTL
    frequency := s.frequencyTracker.GetAccessFrequency(userID, object, action)
    
    if frequency > 100 { // 高频访问
        return 1 * time.Hour
    } else if frequency > 10 { // 中频访问
        return 30 * time.Minute
    } else { // 低频访问
        return 5 * time.Minute
    }
}

func (s *SmartCacheStrategy) ShouldPrefetch(userID string) bool {
    // 2. 基于用户行为决定是否预取
    return s.frequencyTracker.IsActiveUser(userID)
}

// ❌ 错误：固定缓存策略
type StaticCacheStrategy struct {
    fixedTTL time.Duration
}

func (s *StaticCacheStrategy) GetCacheTTL(userID, object, action string) time.Duration {
    return s.fixedTTL // 所有权限使用相同TTL，不够灵活
}
```

---

## 故障排除

### 常见问题诊断

#### 1. 权限检查失败

**症状**: 用户无法访问应有权限的资源
```log
2024-10-04 16:30:15 WARN rbac permission denied subject=user123 object=/user/list action=GET reason=no matching policy
```

**诊断步骤**:
```bash
# 1. 检查用户角色
curl -X GET "http://localhost:8000/admin/rbac/user/user123/roles" \
  -H "Authorization: Bearer <admin_token>"

# 2. 检查角色权限
curl -X GET "http://localhost:8000/admin/rbac/role/employee/permissions" \
  -H "Authorization: Bearer <admin_token>"

# 3. 检查Casbin策略
curl -X GET "http://localhost:8000/admin/rbac/policies" \
  -H "Authorization: Bearer <admin_token>"

# 4. 测试权限检查
curl -X POST "http://localhost:8000/admin/rbac/check" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"subject":"user123","object":"/user/list","action":"GET"}'
```

**解决方案**:
```go
// 添加缺失的权限策略
func (admin *RBACAdmin) AddPermission(roleCode, object, action string) error {
    enforcer := admin.rbacPlugin.GetEnforcer()
    
    success, err := enforcer.AddPolicy(roleCode, object, action)
    if err != nil {
        return fmt.Errorf("添加权限失败: %w", err)
    }
    
    if success {
        admin.logger.WithField("role", roleCode).
            WithField("object", object).
            WithField("action", action).
            Info("权限添加成功")
        
        // 清除相关缓存
        admin.clearRoleCache(roleCode)
    }
    
    return nil
}

// 或者添加用户角色
func (admin *RBACAdmin) AssignRole(userID, roleCode string) error {
    enforcer := admin.rbacPlugin.GetEnforcer()
    
    success, err := enforcer.AddGroupingPolicy(userID, roleCode)
    if err != nil {
        return fmt.Errorf("分配角色失败: %w", err)
    }
    
    if success {
        admin.logger.WithField("user_id", userID).
            WithField("role", roleCode).
            Info("角色分配成功")
        
        admin.clearUserCache(userID)
    }
    
    return nil
}
```

#### 2. 缓存不一致

**症状**: 权限更新后用户仍然使用旧权限
```log
2024-10-04 16:35:20 INFO rbac permission granted from_cache=true subject=user123 cache_age=1800s
```

**诊断和解决**:
```go
// 强制清除缓存
func (admin *RBACAdmin) RefreshUserPermissions(userID string) error {
    // 1. 清除本地缓存
    cacheKeys := admin.generateUserCacheKeys(userID)
    for _, key := range cacheKeys {
        admin.cache.Delete(key)
    }
    
    // 2. 清除Redis缓存
    if admin.redisClient != nil {
        pattern := fmt.Sprintf("rbac:user:%s:*", userID)
        keys, err := admin.redisClient.Keys(context.Background(), pattern).Result()
        if err == nil && len(keys) > 0 {
            admin.redisClient.Del(context.Background(), keys...)
        }
    }
    
    // 3. 重新加载Casbin策略
    if err := admin.rbacPlugin.GetEnforcer().LoadPolicy(); err != nil {
        return fmt.Errorf("重新加载策略失败: %w", err)
    }
    
    admin.logger.WithField("user_id", userID).Info("用户权限缓存已刷新")
    
    return nil
}

// 全局缓存刷新
func (admin *RBACAdmin) RefreshAllPermissions() error {
    // 1. 清除所有缓存
    admin.cache.Clear()
    
    if admin.redisClient != nil {
        keys, err := admin.redisClient.Keys(context.Background(), "rbac:*").Result()
        if err == nil && len(keys) > 0 {
            admin.redisClient.Del(context.Background(), keys...)
        }
    }
    
    // 2. 重新加载策略
    if err := admin.rbacPlugin.GetEnforcer().LoadPolicy(); err != nil {
        return fmt.Errorf("重新加载策略失败: %w", err)
    }
    
    admin.logger.Info("所有权限缓存已刷新")
    
    return nil
}
```

#### 3. 权限检查性能问题

**症状**: 权限检查耗时过长
```log
2024-10-04 16:40:30 WARN rbac permission check duration too long duration=2.5s threshold=100ms
```

**性能分析和优化**:
```go
// 性能分析工具
type RBACPerformanceAnalyzer struct {
    rbacPlugin *RbacPlugin
    profiler   *PerformanceProfiler
    logger     *logging.MiddlewareLogger
}

func (analyzer *RBACPerformanceAnalyzer) AnalyzePerformance() *PerformanceReport {
    report := &PerformanceReport{
        Timestamp: time.Now(),
        Metrics:   make(map[string]interface{}),
    }
    
    // 1. 分析缓存性能
    cacheStats := analyzer.rbacPlugin.GetCacheStats()
    report.Metrics["cache_hit_rate"] = cacheStats.HitRate
    report.Metrics["cache_size"] = cacheStats.Size
    
    // 2. 分析Casbin性能
    enforcerStats := analyzer.getEnforcerStats()
    report.Metrics["policy_count"] = enforcerStats.PolicyCount
    report.Metrics["avg_enforce_time"] = enforcerStats.AvgEnforceTime
    
    // 3. 识别性能瓶颈
    bottlenecks := analyzer.identifyBottlenecks(cacheStats, enforcerStats)
    report.Bottlenecks = bottlenecks
    
    // 4. 生成优化建议
    recommendations := analyzer.generateRecommendations(bottlenecks)
    report.Recommendations = recommendations
    
    return report
}

func (analyzer *RBACPerformanceAnalyzer) identifyBottlenecks(cacheStats *CacheStats, enforcerStats *EnforcerStats) []PerformanceBottleneck {
    var bottlenecks []PerformanceBottleneck
    
    // 缓存命中率低
    if cacheStats.HitRate < 0.8 {
        bottlenecks = append(bottlenecks, PerformanceBottleneck{
            Type:        "low_cache_hit_rate",
            Severity:    "high",
            Description: fmt.Sprintf("缓存命中率过低: %.2f%%", cacheStats.HitRate*100),
            Impact:      "权限检查性能下降",
        })
    }
    
    // 策略数量过多
    if enforcerStats.PolicyCount > 10000 {
        bottlenecks = append(bottlenecks, PerformanceBottleneck{
            Type:        "too_many_policies",
            Severity:    "medium",
            Description: fmt.Sprintf("策略数量过多: %d", enforcerStats.PolicyCount),
            Impact:      "策略匹配耗时增加",
        })
    }
    
    // 单次检查耗时过长
    if enforcerStats.AvgEnforceTime > 100*time.Millisecond {
        bottlenecks = append(bottlenecks, PerformanceBottleneck{
            Type:        "slow_enforce",
            Severity:    "high",
            Description: fmt.Sprintf("权限检查平均耗时: %v", enforcerStats.AvgEnforceTime),
            Impact:      "接口响应时间增加",
        })
    }
    
    return bottlenecks
}
```

### 调试工具

#### 权限检查跟踪器
```go
type PermissionTracer struct {
    rbacPlugin *RbacPlugin
    tracer     *PermissionTraceCollector
    logger     *logging.MiddlewareLogger
}

type PermissionTrace struct {
    TraceID     string                 `json:"trace_id"`
    Subject     string                 `json:"subject"`
    Object      string                 `json:"object"`
    Action      string                 `json:"action"`
    Result      bool                   `json:"result"`
    Steps       []PermissionTraceStep  `json:"steps"`
    StartTime   time.Time              `json:"start_time"`
    EndTime     time.Time              `json:"end_time"`
    Duration    time.Duration          `json:"duration"`
    FromCache   bool                   `json:"from_cache"`
    Metadata    map[string]interface{} `json:"metadata"`
}

type PermissionTraceStep struct {
    Step        string        `json:"step"`
    Description string        `json:"description"`
    Result      interface{}   `json:"result"`
    Duration    time.Duration `json:"duration"`
    Error       string        `json:"error,omitempty"`
}

func (tracer *PermissionTracer) TracePermissionCheck(subject, object, action string) *PermissionTrace {
    trace := &PermissionTrace{
        TraceID:   generateTraceID(),
        Subject:   subject,
        Object:    object,
        Action:    action,
        StartTime: time.Now(),
        Steps:     make([]PermissionTraceStep, 0),
        Metadata:  make(map[string]interface{}),
    }
    
    // 1. 缓存检查
    cacheStart := time.Now()
    cacheKey := fmt.Sprintf("rbac:%s:%s:%s", subject, object, action)
    cached, fromCache := tracer.rbacPlugin.GetFromCache(cacheKey)
    
    trace.Steps = append(trace.Steps, PermissionTraceStep{
        Step:        "cache_check",
        Description: "检查权限缓存",
        Result:      fromCache,
        Duration:    time.Since(cacheStart),
    })
    
    if fromCache {
        trace.Result = cached.(bool)
        trace.FromCache = true
        trace.EndTime = time.Now()
        trace.Duration = trace.EndTime.Sub(trace.StartTime)
        return trace
    }
    
    // 2. 用户角色查询
    roleStart := time.Now()
    roles, err := tracer.rbacPlugin.GetUserRoles(subject)
    
    step := PermissionTraceStep{
        Step:        "user_roles_query",
        Description: "查询用户角色",
        Result:      roles,
        Duration:    time.Since(roleStart),
    }
    if err != nil {
        step.Error = err.Error()
    }
    trace.Steps = append(trace.Steps, step)
    
    // 3. Casbin权限检查
    casbinStart := time.Now()
    allowed, err := tracer.rbacPlugin.GetEnforcer().Enforce(subject, object, action)
    
    step = PermissionTraceStep{
        Step:        "casbin_enforce",
        Description: "Casbin权限检查",
        Result:      allowed,
        Duration:    time.Since(casbinStart),
    }
    if err != nil {
        step.Error = err.Error()
    }
    trace.Steps = append(trace.Steps, step)
    
    // 4. 权限继承计算
    if len(roles) > 0 {
        inheritanceStart := time.Now()
        inheritedPermissions := tracer.calculateInheritedPermissions(roles, object, action)
        
        trace.Steps = append(trace.Steps, PermissionTraceStep{
            Step:        "permission_inheritance",
            Description: "权限继承计算",
            Result:      inheritedPermissions,
            Duration:    time.Since(inheritanceStart),
        })
    }
    
    trace.Result = allowed
    trace.FromCache = false
    trace.EndTime = time.Now()
    trace.Duration = trace.EndTime.Sub(trace.StartTime)
    
    // 5. 缓存结果
    tracer.rbacPlugin.SetCache(cacheKey, allowed, 10*time.Minute)
    
    return trace
}
```

#### 权限分析工具
```go
type PermissionAnalyzer struct {
    rbacPlugin *RbacPlugin
    analyzer   *PolicyAnalyzer
    reporter   *AnalysisReporter
}

func (analyzer *PermissionAnalyzer) AnalyzeUserPermissions(userID string) *UserPermissionAnalysis {
    analysis := &UserPermissionAnalysis{
        UserID:    userID,
        Timestamp: time.Now(),
    }
    
    // 1. 获取用户直接角色
    directRoles, err := analyzer.rbacPlugin.GetUserRoles(userID)
    if err != nil {
        analysis.Errors = append(analysis.Errors, fmt.Sprintf("获取用户角色失败: %v", err))
        return analysis
    }
    analysis.DirectRoles = directRoles
    
    // 2. 计算有效角色（包括继承）
    effectiveRoles := analyzer.calculateEffectiveRoles(directRoles)
    analysis.EffectiveRoles = effectiveRoles
    
    // 3. 获取所有权限
    allPermissions := analyzer.getAllPermissions(effectiveRoles)
    analysis.AllPermissions = allPermissions
    
    // 4. 分析权限冲突
    conflicts := analyzer.analyzePermissionConflicts(allPermissions)
    analysis.Conflicts = conflicts
    
    // 5. 分析权限覆盖度
    coverage := analyzer.analyzePermissionCoverage(allPermissions)
    analysis.Coverage = coverage
    
    // 6. 生成建议
    recommendations := analyzer.generateUserRecommendations(analysis)
    analysis.Recommendations = recommendations
    
    return analysis
}

func (analyzer *PermissionAnalyzer) GeneratePermissionReport() *PermissionReport {
    report := &PermissionReport{
        GeneratedAt: time.Now(),
    }
    
    // 1. 用户权限分布
    userDistribution := analyzer.analyzeUserPermissionDistribution()
    report.UserDistribution = userDistribution
    
    // 2. 角色使用情况
    roleUsage := analyzer.analyzeRoleUsage()
    report.RoleUsage = roleUsage
    
    // 3. 权限热点分析
    hotspots := analyzer.analyzePermissionHotspots()
    report.Hotspots = hotspots
    
    // 4. 安全风险评估
    securityRisks := analyzer.assessSecurityRisks()
    report.SecurityRisks = securityRisks
    
    // 5. 优化建议
    optimizations := analyzer.generateOptimizationRecommendations()
    report.Optimizations = optimizations
    
    return report
}
```

---

## API参考

### 核心接口

#### RbacPlugin
```go
// NewRbacPlugin 创建RBAC插件
func NewRbacPlugin() framework.MiddlewarePlugin
func NewRbacPluginWithProvider(p EnforcerProvider) framework.MiddlewarePlugin
func NewRbacPluginWithEnforcer(e *casbin.Enforcer) framework.MiddlewarePlugin

// 权限检查
func (p *RbacPlugin) CheckPermission(subject, object, action string) (bool, error)
func (p *RbacPlugin) CheckPermissionWithContext(ctx context.Context, subject, object, action string) (bool, error)
func (p *RbacPlugin) BatchCheckPermissions(checks []PermissionCheck) ([]PermissionResult, error)

// 策略管理
func (p *RbacPlugin) AddPolicy(subject, object, action string) error
func (p *RbacPlugin) RemovePolicy(subject, object, action string) error
func (p *RbacPlugin) GetPolicy() [][]string
func (p *RbacPlugin) HasPolicy(subject, object, action string) bool

// 角色管理
func (p *RbacPlugin) AddRole(user, role string) error
func (p *RbacPlugin) RemoveRole(user, role string) error
func (p *RbacPlugin) GetRolesForUser(user string) ([]string, error)
func (p *RbacPlugin) GetUsersForRole(role string) ([]string, error)
func (p *RbacPlugin) HasRole(user, role string) bool

// 缓存管理
func (p *RbacPlugin) ClearCache() error
func (p *RbacPlugin) ClearUserCache(userID string) error
func (p *RbacPlugin) GetCacheStats() *CacheStats
func (p *RbacPlugin) PreloadPermissions(patterns []string) error

// 监控和统计
func (p *RbacPlugin) GetMetrics() *RBACMetrics
func (p *RbacPlugin) GetPerformanceStats() *PerformanceStats
func (p *RbacPlugin) GetHealthStatus() *HealthStatus
```

#### EnforcerProvider
```go
type EnforcerProvider interface {
    GetCasbinEnforcer() interface{}
}

// 默认实现
type DefaultEnforcerProvider struct {
    enforcer *casbin.Enforcer
}

func NewEnforcerProvider(modelPath, policyPath string) (EnforcerProvider, error)
func NewEnforcerProviderWithDB(modelPath, driverName, dataSource string) (EnforcerProvider, error)
```

### 数据结构

#### 权限检查
```go
type PermissionCheck struct {
    Subject string `json:"subject"`
    Object  string `json:"object"`
    Action  string `json:"action"`
    Context map[string]interface{} `json:"context,omitempty"`
}

type PermissionResult struct {
    Subject     string                 `json:"subject"`
    Object      string                 `json:"object"`
    Action      string                 `json:"action"`
    Allowed     bool                   `json:"allowed"`
    Reason      string                 `json:"reason,omitempty"`
    Error       error                  `json:"error,omitempty"`
    CheckTime   time.Time              `json:"check_time"`
    Duration    time.Duration          `json:"duration"`
    FromCache   bool                   `json:"from_cache"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

#### 角色和权限
```go
type Role struct {
    Code        string            `json:"code"`
    Name        string            `json:"name"`
    Description string            `json:"description"`
    Permissions []Permission      `json:"permissions"`
    Children    []string          `json:"children"`
    Parents     []string          `json:"parents"`
    Attributes  map[string]string `json:"attributes"`
    Status      string            `json:"status"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

type Permission struct {
    Subject    string            `json:"subject"`
    Object     string            `json:"object"`
    Action     string            `json:"action"`
    Effect     string            `json:"effect"`  // allow/deny
    Conditions []Condition       `json:"conditions,omitempty"`
    Attributes map[string]string `json:"attributes,omitempty"`
}

type Condition struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`
    Value    interface{} `json:"value"`
}
```

#### 配置结构
```go
type PermissionConfig struct {
    Enabled       bool     `json:"enabled"`
    CasbinEnabled bool     `json:"casbin_enabled"`
    SkipPaths     []string `json:"skip_paths"`
    
    Casbin        CasbinConfig           `json:"casbin"`
    Cache         PermissionCacheConfig  `json:"cache"`
    RoleHierarchy RoleHierarchyConfig    `json:"role_hierarchy"`
    Performance   PerformanceConfig      `json:"performance"`
    Monitoring    MonitoringConfig       `json:"monitoring"`
}
```

### 错误类型

#### 权限相关错误
```go
// 权限拒绝错误
type PermissionDeniedError struct {
    Subject string
    Object  string
    Action  string
    Reason  string
}

func (e *PermissionDeniedError) Error() string {
    return fmt.Sprintf("权限拒绝: %s 无权对 %s 执行 %s 操作 (%s)", e.Subject, e.Object, e.Action, e.Reason)
}

// 配置错误
type RBACConfigError struct {
    Field   string
    Value   interface{}
    Message string
}

func (e *RBACConfigError) Error() string {
    return fmt.Sprintf("RBAC配置错误 [%s=%v]: %s", e.Field, e.Value, e.Message)
}

// 策略错误
type PolicyError struct {
    Operation string
    Policy    []string
    Cause     error
}

func (e *PolicyError) Error() string {
    return fmt.Sprintf("策略操作失败 [%s] %v: %v", e.Operation, e.Policy, e.Cause)
}
```

---

## 迁移指南

### 从旧版本迁移

#### 版本1.x到2.x迁移

**主要变更**:
1. 新增Casbin集成支持
2. 权限缓存架构重构
3. 新增角色继承功能
4. 性能优化和监控增强

**迁移步骤**:

**Step 1: 更新依赖**
```go
// go.mod
replace github.com/coder-lulu/newbee-common v1.x.x => github.com/coder-lulu/newbee-common v2.x.x

// 新增Casbin依赖
require (
    github.com/casbin/casbin/v2 v2.77.2
)
```

**Step 2: 配置文件更新**
```yaml
# 旧配置
Permission:
  Enabled: true
  SkipPaths: ["/health"]

# 新配置
Permission:
  Enabled: true
  CasbinEnabled: true  # 新增
  SkipPaths: ["/health"]
  
  # 新增Casbin配置
  Casbin:
    ModelPath: "./conf/rbac_model.conf"
    PolicyPath: "./conf/policy.csv"
    AutoLoad: true
    AutoSave: true
    
  # 新增缓存配置
  Cache:
    Enabled: true
    TTL: "30m"
    LocalCacheSize: 10000
    RedisCacheEnabled: true
```

**Step 3: 代码更新**
```go
// 旧代码
func NewServiceContext(c config.Config) *ServiceContext {
    rbacPlugin := permission.NewRbacPlugin()
    return &ServiceContext{
        RbacPlugin: rbacPlugin,
    }
}

// 新代码
func NewServiceContext(c config.Config) *ServiceContext {
    // 创建Casbin enforcer
    enforcer, err := casbin.NewEnforcer(
        c.Permission.Casbin.ModelPath,
        c.Permission.Casbin.PolicyPath,
    )
    if err != nil {
        panic("初始化Casbin失败: " + err.Error())
    }
    
    // 创建RBAC插件
    rbacPlugin := permission.NewRbacPluginWithEnforcer(enforcer)
    
    return &ServiceContext{
        RbacPlugin: rbacPlugin,
        Enforcer:   enforcer, // 可选：直接暴露enforcer
    }
}
```

#### 权限策略迁移

**从硬编码权限到Casbin策略**:

```go
// 旧方式：硬编码权限检查
func (h *UserHandler) checkPermission(userID, action string) bool {
    userRoles := h.getUserRoles(userID)
    
    switch action {
    case "create_user":
        return h.hasRole(userRoles, "admin") || h.hasRole(userRoles, "manager")
    case "delete_user":
        return h.hasRole(userRoles, "admin")
    case "view_user":
        return h.hasRole(userRoles, "admin") || h.hasRole(userRoles, "manager") || h.hasRole(userRoles, "employee")
    default:
        return false
    }
}

// 新方式：使用Casbin策略
func (h *UserHandler) checkPermission(userID, object, action string) bool {
    return h.rbacPlugin.CheckPermission(userID, object, action)
}

// 权限策略文件 (policy.csv)
// p, admin, /user, *
// p, manager, /user, create
// p, manager, /user, read
// p, manager, /user, update
// p, employee, /user/profile, read
// p, employee, /user/profile, update
//
// g, alice, admin
// g, bob, manager
// g, charlie, employee
```

### 数据迁移

#### 权限数据迁移脚本
```go
type PermissionMigrator struct {
    oldDB    *sql.DB
    newDB    *sql.DB
    enforcer *casbin.Enforcer
    logger   *logging.Logger
}

func (m *PermissionMigrator) MigratePermissions() error {
    // 1. 迁移角色数据
    if err := m.migrateRoles(); err != nil {
        return fmt.Errorf("迁移角色失败: %w", err)
    }
    
    // 2. 迁移用户角色关系
    if err := m.migrateUserRoles(); err != nil {
        return fmt.Errorf("迁移用户角色关系失败: %w", err)
    }
    
    // 3. 迁移权限策略
    if err := m.migratePermissionPolicies(); err != nil {
        return fmt.Errorf("迁移权限策略失败: %w", err)
    }
    
    // 4. 验证迁移结果
    if err := m.validateMigration(); err != nil {
        return fmt.Errorf("迁移验证失败: %w", err)
    }
    
    return nil
}

func (m *PermissionMigrator) migrateRoles() error {
    // 从旧数据库查询角色
    rows, err := m.oldDB.Query("SELECT code, name, permissions FROM roles WHERE status = 'active'")
    if err != nil {
        return err
    }
    defer rows.Close()
    
    for rows.Next() {
        var roleCode, roleName, permissions string
        if err := rows.Scan(&roleCode, &roleName, &permissions); err != nil {
            continue
        }
        
        // 解析权限字符串
        perms := strings.Split(permissions, ",")
        
        // 转换为Casbin策略
        for _, perm := range perms {
            parts := strings.Split(perm, ":")
            if len(parts) >= 2 {
                object := parts[0]
                action := parts[1]
                
                // 添加策略
                success, err := m.enforcer.AddPolicy(roleCode, object, action)
                if err != nil {
                    m.logger.WithError(err).WithField("policy", perm).Warn("添加策略失败")
                    continue
                }
                
                if success {
                    m.logger.WithField("role", roleCode).WithField("policy", perm).Info("策略迁移成功")
                }
            }
        }
    }
    
    return nil
}

func (m *PermissionMigrator) migrateUserRoles() error {
    rows, err := m.oldDB.Query("SELECT user_id, role_codes FROM user_roles")
    if err != nil {
        return err
    }
    defer rows.Close()
    
    for rows.Next() {
        var userID, roleCodes string
        if err := rows.Scan(&userID, &roleCodes); err != nil {
            continue
        }
        
        roles := strings.Split(roleCodes, ",")
        for _, role := range roles {
            role = strings.TrimSpace(role)
            if role != "" {
                success, err := m.enforcer.AddGroupingPolicy(userID, role)
                if err != nil {
                    m.logger.WithError(err).WithField("user_id", userID).WithField("role", role).Warn("添加用户角色失败")
                    continue
                }
                
                if success {
                    m.logger.WithField("user_id", userID).WithField("role", role).Info("用户角色迁移成功")
                }
            }
        }
    }
    
    return nil
}
```

### 性能比较

#### 迁移前后性能对比
```bash
# 权限检查性能对比
旧版本 (硬编码):
- 单次检查: 0.1ms
- 批量检查: 不支持
- 缓存支持: 基础

新版本 (Casbin):
- 单次检查: 0.05ms (优化后)
- 批量检查: 支持，10倍性能提升
- 缓存支持: 多级智能缓存

# 内存使用对比
旧版本: 基础内存占用
新版本: +15MB (Casbin引擎 + 缓存)

# 功能对比
旧版本: 基础RBAC
新版本: RBAC + 角色继承 + 动态策略 + 监控
```

---

## 总结

统一RBAC权限中间件是NewBee架构中实现**细粒度访问控制**的核心组件。通过本指南，您应该能够：

### 核心收益

1. **强大的权限控制** - 基于Casbin的灵活权限模型
2. **高性能设计** - 多级缓存和批量处理优化
3. **易于管理** - 可视化权限管理和冲突检测
4. **安全保障** - 默认拒绝和防御性权限检查

### 技术优势

- 🔐 **灵活的权限模型**：支持RBAC、ABAC等多种模型
- 🧠 **智能权限引擎**：基于Casbin的高性能权限匹配
- 🚀 **优化的性能**：多级缓存和批量权限检查
- 📊 **丰富的管理功能**：权限可视化和冲突检测

### 下一步行动

1. 根据业务需求设计权限模型和角色体系
2. 配置Casbin策略和角色继承关系
3. 实施权限缓存和性能优化策略
4. 建立权限监控和管理流程

如需更多技术支持，请参考：
- [统一权限中间件使用指南](./统一权限中间件使用指南.md)
- [统一认证中间件详细指南](./统一认证中间件详细指南.md)
- [统一租户中间件详细指南](./统一租户中间件详细指南.md)
- [统一数据权限中间件详细指南](./统一数据权限中间件详细指南.md)
- [统一审计中间件详细指南](./统一审计中间件详细指南.md)

---

**文档版本**: v2.0  
**最后更新**: 2024-10-04  
**维护团队**: NewBee架构组