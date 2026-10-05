# 统一Hook系统速查表

## 一分钟快速开始

```go
import "github.com/coder-lulu/newbee-common/orm/ent/hooks"

// 在ServiceContext中
func NewServiceContext(c config.Config) *ServiceContext {
    // ... 初始化数据库连接 ...

    // 一键设置所有hooks（推荐）
    if err := hooks.QuickSetup(db); err != nil {
        panic(err)
    }

    return &ServiceContext{DB: db}
}
```

## 常用API速查

| 功能 | API | 说明 |
|------|-----|------|
| 一键设置 | `hooks.QuickSetup(db)` | 初始化配置+注册所有hooks |
| 初始化配置 | `hooks.InitDefaultHookConfigs()` | 仅初始化配置，不注册 |
| 注册所有hooks | `hooks.RegisterAllHooks(db)` | 注册所有已配置的hooks |
| 仅租户Hook | `hooks.RegisterTenantHooks(db)` | 仅注册租户相关hooks |
| 仅部门Hook | `hooks.RegisterDepartmentHooksUnified(db)` | 仅注册部门相关hooks |
| 系统上下文 | `hooks.NewSystemContext(ctx)` | 创建系统上下文（跳过过滤） |
| 诊断上下文 | `hooks.DiagnoseTenantContext(ctx)` | 诊断租户上下文状态 |

## 配置字段类型

| 字段类型 | 常量 | 说明 |
|----------|------|------|
| 租户ID | `hooks.FieldTypeTenant` | `tenant_id` |
| 部门ID | `hooks.FieldTypeDepartment` | `department_id` |
| 用户ID | `hooks.FieldTypeUser` | `user_id` |
| 创建者 | `hooks.FieldTypeCreatedBy` | `created_by` |

## 默认行为

### 租户Hook (严格模式)
- ✅ Create时**必须**有tenant_id
- ✅ Query时**自动**添加 `WHERE tenant_id = ?`
- ✅ 系统上下文设置tenant_id=0
- ❌ 缺少tenant_id时**报错**

### 部门Hook (宽松模式)
- ✅ Create时如果有department_id则自动注入
- ❌ Query时**不自动**过滤（由数据权限中间件处理）
- ✅ 系统上下文设置department_id=0
- ✅ 缺少department_id时**跳过**

## 核心概念

### 严格模式 vs 宽松模式

```go
// 严格模式 (RequireValue=true)
config := &hooks.FieldConfig{
    RequireValue: true,  // 字段值必须存在
    DefaultValue: 0,     // 被忽略
}
// 结果：缺少字段值时返回错误

// 宽松模式 (RequireValue=false)
config := &hooks.FieldConfig{
    RequireValue: false,  // 字段值可选
    DefaultValue: 0,      // 使用默认值
}
// 结果：缺少字段值时使用默认值或跳过
```

### 系统上下文

```go
// 普通上下文 - 受Hook限制
ctx := context.Background()
users, err := db.User.Query().All(ctx)
// SQL: SELECT * FROM users WHERE tenant_id = 2

// 系统上下文 - 跳过Hook限制
systemCtx := hooks.NewSystemContext(ctx)
users, err := db.User.Query().All(systemCtx)
// SQL: SELECT * FROM users
```

## 迁移对照表

| 旧版API | 新版API (推荐) | 说明 |
|---------|----------------|------|
| `db.Use(hooks.TenantMutationHook())` | `hooks.QuickSetup(db)` | 一键设置所有 |
| `db.Intercept(hooks.TenantQueryInterceptor())` | 同上 | 包含在QuickSetup中 |
| `hooks.RegisterDepartmentHooks(db)` | `hooks.QuickSetup(db)` | 包含部门Hook |
| 手动注册每个Hook | `hooks.QuickSetup(db)` | 自动注册所有 |

## 添加自定义Hook三步走

### 步骤1：定义字段类型
```go
const FieldTypeCreatedBy hooks.FieldType = "created_by"
```

### 步骤2：注册配置
```go
hooks.GlobalHookManager.RegisterField(&hooks.FieldConfig{
    FieldName:    "created_by",
    FieldType:    FieldTypeCreatedBy,
    SetterMethod: "SetCreatedBy",
    GetterMethod: "CreatedBy",
    ContextExtractor: func(ctx context.Context) (uint64, error) {
        userID := GetUserIDFromContext(ctx)
        if userID == 0 {
            return 0, errors.New("user not found")
        }
        return userID, nil
    },
    ShouldApplyFilter: func(tableName string) bool {
        return false  // 不在query时过滤
    },
    IsSystemContext:  hooks.IsSystemContext,
    ExcludedEntities: []string{},
    RequireValue:     true,
    DefaultValue:     0,
})
```

### 步骤3：注册到client
```go
hooks.RegisterHooksToClient(db, FieldTypeCreatedBy)
```

## 调试技巧

### 检查context状态
```go
import "github.com/zeromicro/go-zero/core/logx"

// 诊断租户context
info := hooks.DiagnoseTenantContext(ctx)
logx.Infow("Tenant context diagnosis", logx.Field("info", info))

// 输出：
// {
//   "is_system_context": false,
//   "is_public_context": false,
//   "has_string_tenant_id": true,
//   "string_tenant_id": "2",
//   "tenant_id_from_helper": 2,
//   "is_valid_tenant_context": true
// }
```

### 查看Hook日志
```
[INFO] Registered unified hook field field_type=tenant_id
[INFO] Registered mutation hook field_type=tenant_id
[INFO] Registered query interceptor field_type=tenant_id
[INFO] Auto-injected field value field_type=tenant_id entity=User value=2
[INFO] Applying field filter field_type=tenant_id query=*ent.UserQuery value=2
```

### 常见错误

#### Error: "tenant id not found in context"
**原因**: context中没有租户ID
**解决**: 检查认证中间件是否正确设置context

#### Error: "Field config not found"
**原因**: 忘记调用`InitDefaultHookConfigs()`
**解决**: 在注册hooks前调用初始化函数

#### Query没有过滤
**原因1**: 表在排除列表中
**原因2**: 使用了系统上下文
**解决**: 检查日志输出或调用`ShouldApplyFilter(tableName)`测试

## 性能参考

| 操作 | 延迟增加 | 说明 |
|------|----------|------|
| Mutation Hook | ~2-5μs | 反射调用setter方法 |
| Query Interceptor | ~5-10μs | 反射+unsafe修改modifiers |
| 系统上下文检查 | ~1μs | 简单的context查询 |

## 文件清单

```
common/orm/ent/hooks/
├── unified_hook.go          # 核心框架（378行）
├── hook_init.go             # 配置初始化（95行）
├── tenant.go                # 保留：工具函数
├── tenant_helper.go         # 保留：向后兼容
├── department_hook.go       # 保留：向后兼容
├── README_UNIFIED_HOOK.md   # 完整文档
├── MIGRATION_SUMMARY.md     # 迁移总结
└── QUICK_REFERENCE.md       # 本速查表
```

## 典型使用场景

### 场景1：新项目启动
```go
func NewServiceContext(c config.Config) *ServiceContext {
    db := ent.NewClient(...)
    hooks.QuickSetup(db)  // 一行搞定！
    return &ServiceContext{DB: db}
}
```

### 场景2：只需要租户隔离
```go
hooks.InitDefaultHookConfigs()
hooks.RegisterTenantHooks(db)
```

### 场景3：租户+部门+自定义字段
```go
hooks.InitDefaultHookConfigs()

// 添加自定义字段
hooks.GlobalHookManager.RegisterField(&hooks.FieldConfig{...})

// 注册所有（包括自定义字段）
hooks.RegisterAllHooks(db)
```

### 场景4：系统级操作
```go
// 需要访问所有租户数据
systemCtx := hooks.NewSystemContext(ctx)
allUsers, _ := db.User.Query().All(systemCtx)

// 创建系统级实体（tenant_id=0）
_, err := db.Role.Create().
    SetName("SuperAdmin").
    Save(systemCtx)
```

## 联系支持

- 📖 完整文档: `README_UNIFIED_HOOK.md`
- 📊 迁移指南: `MIGRATION_SUMMARY.md`
- 🐛 问题反馈: GitHub Issues
- 💬 技术讨论: 团队技术群

---

**提示**: 大多数情况下，只需要调用 `hooks.QuickSetup(db)` 即可！
