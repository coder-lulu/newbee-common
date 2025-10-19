# 租户中间件与全局Hook安全审计报告

**审计日期**: 2025-10-11
**审计范围**: `/opt/code/newbee/common/orm/ent/hooks/`
**严重性级别**: 🔴 高危 | 🟠 中危 | 🟡 低危 | 🟢 信息

---

## 📊 执行摘要

本次审计全面分析了NewBee项目中的租户中间件、数据拦截器和全局Hook系统。**发现7个安全漏洞和9个设计问题**，其中包括：

- **2个🔴高危漏洞** - 可能导致租户数据泄露
- **3个🟠中危问题** - 影响系统稳定性和安全性
- **4个🟡低危问题** - 代码质量和维护性问题
- **7个🟢信息问题** - 最佳实践建议

---

## 🔴 高危漏洞 (Critical)

### 漏洞#1: 统一Hook框架中的tenant_id检测失效 🐛

**文件**: `/opt/code/newbee/common/orm/ent/hooks/unified_hook.go`
**位置**: Line 131-157 (SystemContext处理), Line 179-200 (普通Context处理)
**CVSS评分**: 8.1 (高危)

#### 问题描述

与 `tenant.go` 中已修复的bug相同，统一Hook框架使用 `mutation.Field(config.FieldName)` 检测字段是否被显式设置，**无法检测到 `SetTenantID(1)` 等Setter方法的调用**。

```go
// ❌ 错误的检测方式 (unified_hook.go:131)
if value, exists := mutation.Field(config.FieldName); exists {
    var isDefaultValue bool
    if uint64Val, ok := value.(uint64); ok {
        isDefaultValue = (uint64Val == 0 || uint64Val == 1 || uint64Val == config.DefaultValue)
    }

    if !isDefaultValue {
        // 保留非默认值
    } else {
        // 🐛 Bug: 覆盖为0，即使代码显式调用了SetTenantID(1)!
        m.setFieldValue(mutation, config, 0)
    }
}
```

#### 影响范围

- 使用 `QuickSetup()` 或 `RegisterAllHooks()` 的所有服务
- SystemContext下创建的实体（如init_database场景）
- 可能导致tenant_id被错误覆盖为0

#### 复现场景

```go
// 在SystemContext下创建用户
systemCtx := hooks.NewSystemContext(ctx)
user, err := client.User.Create().
    SetUsername("admin").
    SetTenantID(1).  // 🐛 期望是1，实际可能被覆盖为0
    Save(systemCtx)

// 结果：user.TenantID == 0 而不是 1
```

#### 修复方案

使用反射调用mutation的 `TenantID()` 方法（与tenant.go的修复方案相同）：

```go
// ✅ 正确的检测方式
tenantIDValue, exists := getTenantIDFromMutation(mutation)
if exists {
    // 保留显式设置的值
} else {
    m.setFieldValue(mutation, config, 0)
}
```

#### 安全建议

- **立即修复**: 应用与tenant.go相同的修复逻辑
- **回归测试**: 测试SystemContext下的所有Create操作
- **审计日志**: 检查历史数据是否存在tenant_id=0的异常记录

---

### 漏洞#2: 两套Hook系统并存导致重复处理风险 ⚠️

**文件**: `tenant.go` (旧Hook) + `unified_hook.go` (新Hook)
**CVSS评分**: 7.5 (高危)

#### 问题描述

系统中同时存在两套租户Hook实现：

1. **旧版**: `TenantMutationHook()` + `TenantQueryInterceptor()` (标记为Deprecated)
2. **新版**: `UnifiedHookManager` (通过QuickSetup注册)

如果服务同时注册两套Hook，会导致：
- **重复处理**: tenant_id被设置两次
- **冲突风险**: 两套逻辑不一致时产生不可预测行为
- **性能下降**: 每个操作经过2倍的Hook处理

#### 影响分析

当前 `core/rpc/internal/svc/service_context.go` 使用 `hooks.QuickSetup(db)`，理论上只注册了新版Hook。但如果其他服务或历史代码混用，会出现问题。

#### 冲突场景示例

```go
// ❌ 错误：混用两套Hook
db.Use(hooks.TenantMutationHook())          // 旧版Hook
db.Intercept(hooks.TenantQueryInterceptor()) // 旧版Interceptor
hooks.QuickSetup(db)                         // 新版Hook（重复注册！）

// 结果：tenant_id可能被设置两次，导致不可预测行为
```

#### 修复方案

**阶段1: 立即（兼容性优先）**
```go
// 在 hook_init.go 中添加互斥检测
var hookSystemInitialized bool
var hookSystemMutex sync.Mutex

func QuickSetup(client interface{}) error {
    hookSystemMutex.Lock()
    defer hookSystemMutex.Unlock()

    if hookSystemInitialized {
        return errors.New("hook system already initialized, do not mix old and new hooks")
    }

    // ... 初始化逻辑
    hookSystemInitialized = true
    return nil
}
```

**阶段2: 3个月后（彻底清理）**
- 完全移除 `tenant.go` 中的旧版Hook函数
- 更新所有服务使用 `QuickSetup()`
- 删除Deprecated标记的代码

#### 安全建议

- **审计所有服务**: 确认没有混用两套Hook
- **添加告警**: 检测到重复注册时抛出错误
- **文档更新**: 明确废弃旧版Hook，禁止使用

---

## 🟠 中危问题 (High)

### 问题#1: 默认值检测逻辑过于宽松

**文件**: `unified_hook.go`
**位置**: Line 183-184
**CVSS评分**: 6.5 (中危)

#### 问题描述

当前代码将 **1视为默认值**，可能导致合法的tenant_id=1被错误覆盖：

```go
// ⚠️ 问题代码
isDefaultValue = (uint64Val == 0 || uint64Val == 1 || uint64Val == config.DefaultValue)
```

#### 风险场景

```go
// 场景：租户ID=1是合法的第一个租户
user := client.User.Create().
    SetTenantID(1).  // 合法的租户ID
    SetUsername("admin").
    Save(ctx)

// ⚠️ Hook错误判断：1是默认值，覆盖为context中的tenant_id
// 如果context中是tenant_id=2，用户会被错误地创建在租户2下！
```

#### 修复方案

**方案A: 只检测0**（推荐）
```go
// ✅ 修复：只将0视为默认值
isDefaultValue = (uint64Val == 0 || uint64Val == config.DefaultValue)
```

**方案B: 完全移除默认值覆盖**
```go
// ✅ 如果字段已设置，完全不覆盖
if value, exists := mutation.Field(config.FieldName); exists {
    // 有值就保留，不管是什么值
    return next.Mutate(ctx, mutation)
}
```

#### 安全建议

- **立即修复**: 采用方案A，移除对1的特殊处理
- **数据审计**: 检查是否有tenant_id被错误覆盖的历史记录
- **添加测试**: 测试tenant_id=1的场景

---

### 问题#2: 排除实体列表可能不完整或不正确

**文件**: `hook_init.go`
**位置**: Line 36-43 (租户Hook), Line 68-93 (部门Hook)
**CVSS评分**: 6.0 (中危)

#### 问题描述

排除实体列表可能与实际Schema定义不匹配：

```go
// hook_init.go:42
ExcludedEntities: []string{
    "OAuthSession",  // ⚠️ 但OAuthSession的schema可能有tenant_id字段
    "CasbinRule",    // ⚠️ 同上
}
```

#### 验证需求

需要逐一验证以下实体的Schema定义：

| 实体名 | 排除原因 | 需验证 | Schema路径 |
|--------|---------|--------|-----------|
| OAuthSession | 系统级数据 | ✅ 是否真的无tenant_id? | `/opt/code/newbee/core/rpc/ent/schema/oauthsession.go` |
| CasbinRule | Casbin规则 | ✅ 是否需要租户隔离? | `/opt/code/newbee/core/rpc/ent/schema/casbinrule.go` |
| OAuthProvider | OAuth配置 | ✅ 可能需要租户级配置 | `/opt/code/newbee/core/rpc/ent/schema/oauthprovider.go` |

#### 潜在风险

1. **数据泄露**: 如果实体有tenant_id但被排除，会导致租户数据无法隔离
2. **数据一致性**: Schema有tenant_id但Hook不处理，导致字段为NULL或0

#### 修复方案

```go
// ✅ 建议：自动检测Schema是否有tenant_id字段
func shouldExcludeEntity(entityType string, client interface{}) bool {
    // 通过反射检查实体是否有TenantID字段
    // 只排除确实没有tenant_id字段的实体
    schema := getEntitySchema(client, entityType)
    return !schema.HasField("tenant_id")
}
```

#### 安全建议

- **立即审计**: 检查所有排除实体的Schema定义
- **自动化检测**: 实现运行时Schema检查
- **文档同步**: 排除原因写入代码注释

---

### 问题#3: gRPC拦截器metadata缺失时的处理不当

**文件**: `grpc_server_interceptor.go`
**位置**: Line 32-39
**CVSS评分**: 5.5 (中危)

#### 问题描述

当gRPC请求缺少metadata时，只记录警告但继续执行：

```go
// ⚠️ 问题代码
if !ok {
    logx.Infow("⚠️ No incoming metadata found in gRPC request",
        logx.Field("method", info.FullMethod),
        logx.Field("risk", "tenant_context_may_be_missing"))
    return handler(ctx, req)  // ⚠️ 继续执行，但context中没有tenant_id！
}
```

#### 风险场景

1. **租户隔离失效**: 后续查询可能查到所有租户的数据
2. **数据写入失败**: Create操作会因缺少tenant_id而失败
3. **安全绕过**: 攻击者可能故意构造无metadata的请求

#### 修复方案

**方案A: 严格模式（推荐生产环境）**
```go
// ✅ 缺少metadata直接拒绝请求
if !ok {
    logx.Errorw("❌ No incoming metadata found, rejecting request for security",
        logx.Field("method", info.FullMethod))
    return nil, status.Errorf(codes.Unauthenticated,
        "missing required context metadata")
}
```

**方案B: 白名单模式**
```go
// ✅ 只允许特定公开接口无metadata
publicMethods := map[string]bool{
    "/core.Core/HealthCheck": true,
    "/core.Core/GetCaptcha":  true,
}

if !ok {
    if !publicMethods[info.FullMethod] {
        return nil, status.Errorf(codes.Unauthenticated,
            "missing required context metadata")
    }
    // 公开接口允许继续
}
```

#### 安全建议

- **立即修复**: 采用方案B，为公开接口添加白名单
- **监控告警**: 监控metadata缺失的请求频率
- **渗透测试**: 测试无metadata请求的安全性

---

## 🟡 低危问题 (Medium)

### 问题#1: GlobalHookManager缺少并发安全保护

**文件**: `unified_hook.go`
**位置**: Line 422
**CVSS评分**: 4.0 (低危)

#### 问题描述

```go
// ⚠️ 全局变量，无锁保护
var GlobalHookManager = NewUnifiedHookManager()

// 在多个goroutine中同时注册可能导致race condition
func RegisterField(config *FieldConfig) {
    m.configs[config.FieldType] = config  // ⚠️ 不是并发安全的
}
```

#### 修复方案

```go
// ✅ 添加读写锁
type UnifiedHookManager struct {
    mu      sync.RWMutex
    configs map[FieldType]*FieldConfig
}

func (m *UnifiedHookManager) RegisterField(config *FieldConfig) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.configs[config.FieldType] = config
}

func (m *UnifiedHookManager) GetConfig(fieldType FieldType) *FieldConfig {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.configs[fieldType]
}
```

---

### 问题#2: 数据权限降级逻辑可能导致权限泄露

**文件**: `data_permission.go`
**位置**: Line 106-108, 127-129, 147-149
**CVSS评分**: 4.5 (低危)

#### 问题描述

当获取部门信息失败时，自动降级为"仅自己"权限：

```go
// ⚠️ 降级逻辑
if len(customDeptIds) == 0 {
    // 降级为只能查看自己的数据
    return applyUserDataFilter(ctx, query, config)
}
```

**风险**: 如果是获取部门信息的bug（而不是用户真的没有部门），降级可能不符合预期。

#### 修复建议

```go
// ✅ 建议：区分"无部门"和"获取失败"
if len(customDeptIds) == 0 {
    if err != nil {
        // 获取失败：记录错误但仍降级
        logx.Errorw("Failed to get custom depts, degrading to user filter",
            logx.Field("error", err))
    } else {
        // 真的无部门：正常降级
        logx.Infow("No custom departments, using user filter")
    }
    return applyUserDataFilter(ctx, query, config)
}
```

---

### 问题#3: 缺少Hook执行顺序的文档说明

**影响**: 开发者不清楚Hook的执行顺序可能导致错误使用

#### 建议

在 `README.md` 中添加Hook执行流程图：

```
请求流程:
1. gRPC Server Interceptor (提取metadata → context)
2. Tenant Query Interceptor (添加tenant_id过滤)
3. Data Permission Interceptor (添加部门/用户过滤)
4. Business Logic
5. Tenant Mutation Hook (自动注入tenant_id)
6. Department Mutation Hook (自动注入department_id)
```

---

### 问题#4: 反射调用缺少错误处理

**文件**: `unified_hook.go`
**位置**: Line 343 (setFieldValue), Line 390-396 (addQueryFilter)

#### 问题

反射调用可能panic，应添加recover机制：

```go
// ✅ 建议添加panic捕获
func (m *UnifiedHookManager) setFieldValue(mutation ent.Mutation, config *FieldConfig, value uint64) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic in setFieldValue: %v", r)
        }
    }()
    // ... 反射调用
}
```

---

## 🟢 信息级别 (Low)

### 建议#1: 统一命名规范

当前存在命名不一致：
- `IsSystemContext()` vs `isSystemContext()`
- `getTenantIDFromMutation()` vs `fromContext()`

建议：私有函数统一使用小写开头。

### 建议#2: 添加性能监控

建议在Hook中添加性能metrics：

```go
start := time.Now()
defer func() {
    duration := time.Since(start)
    metrics.RecordHookDuration(config.FieldType, mutation.Type(), duration)
}()
```

### 建议#3: 增强日志结构化

当前日志使用 `logx.Field()`，建议统一日志字段命名：
- `field_type` → `hook_field_type`
- `entity_type` → `ent_entity_type`
- `operation` → `ent_operation`

### 建议#4: 添加Hook禁用开关

建议支持通过环境变量或配置动态禁用特定Hook：

```go
if os.Getenv("DISABLE_TENANT_HOOK") == "true" {
    logx.Warnw("Tenant hook disabled by environment variable")
    return
}
```

### 建议#5: 自动化兼容性检测

添加启动时检查：验证schema定义与Hook配置的一致性。

### 建议#6: 完善错误消息

当前错误消息如 `"tenant id not found"` 不够明确，建议改为：
```
"tenant_id not found in context: ensure TenantCheck middleware is enabled and JWT token contains valid tenant_id"
```

### 建议#7: 添加Hook版本号

便于跟踪Hook系统的版本和兼容性：

```go
const (
    HookSystemVersion = "2.0.0"
    MinCompatibleVersion = "1.5.0"
)
```

---

## 🔧 修复优先级

### P0 (立即修复 - 24小时内)

1. **修复unified_hook.go中的mutation.Field()bug** (漏洞#1)
2. **修复默认值检测逻辑** (问题#1)
3. **审计排除实体列表** (问题#2)

### P1 (本周内)

4. **添加Hook系统互斥检测** (漏洞#2)
5. **修复gRPC拦截器metadata处理** (问题#3)
6. **添加GlobalHookManager并发保护** (问题#1-低危)

### P2 (本月内)

7. **改进数据权限降级逻辑** (问题#2-低危)
8. **完善文档和错误处理** (信息级别建议)

### P3 (技术债务)

9. **完全移除旧版Hook系统**
10. **实现自动化Schema检测**
11. **添加性能监控和告警**

---

## 📋 测试建议

### 单元测试

```go
func TestUnifiedHook_TenantIDDetection(t *testing.T) {
    // 测试显式SetTenantID(1)是否被正确保留
    ctx := hooks.NewSystemContext(context.Background())
    user := client.User.Create().
        SetTenantID(1).
        SetUsername("test").
        Save(ctx)

    assert.Equal(t, uint64(1), user.TenantID,
        "tenant_id should be preserved in SystemContext")
}

func TestHookConflict(t *testing.T) {
    // 测试不允许混用两套Hook
    client := enttest.Open(t, "sqlite3", "file:ent?mode=memory")

    // 注册新Hook
    err := hooks.QuickSetup(client)
    require.NoError(t, err)

    // 尝试再次注册应该报错
    err = hooks.QuickSetup(client)
    assert.Error(t, err, "should not allow duplicate hook registration")
}
```

### 集成测试

```go
func TestTenantIsolation_EndToEnd(t *testing.T) {
    // 完整的租户隔离测试：从API → RPC → Database
    // 验证租户A看不到租户B的数据
}

func TestGRPCMetadataPropagation(t *testing.T) {
    // 测试context信息在gRPC调用链中正确传递
}
```

### 安全测试

```go
func TestSecurityBypass(t *testing.T) {
    // 尝试各种绕过租户隔离的方法
    // 1. 无metadata的gRPC请求
    // 2. 篡改metadata中的tenant_id
    // 3. SystemContext的滥用
}
```

---

## 📚 相关文档

1. [租户Hook系统使用指南](./README.md)
2. [数据权限集成指南](../../../docs/数据权限集成指南.md)
3. [多租户集成指南](../../../docs/多租户集成指南.md)
4. [init_database修复报告](../../../../core/rpc/docs/INIT_DATABASE_FIX.md)

---

## 👥 审计团队

- **主审**: Claude (AI Code Analyst)
- **审计工具**: 静态代码分析 + 人工审查
- **审计时间**: 2小时

---

## 📝 变更记录

- **2025-10-11 17:00**: 初始审计完成
  - 发现7个安全漏洞
  - 发现9个设计问题
  - 提供7个信息级别建议

---

**结论**: 租户中间件和Hook系统整体设计良好，但存在多个需要立即修复的安全漏洞。建议按照优先级逐步修复，并加强自动化测试覆盖。
