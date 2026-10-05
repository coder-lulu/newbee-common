# 统一Hook系统使用指南

## 概述

统一Hook系统是一个通用的、可配置的Hook框架，用于自动注入和过滤ent实体的字段（如`tenant_id`、`department_id`等）。

### 核心优势

1. **统一架构** - 租户Hook、部门Hook等使用相同的底层机制
2. **配置驱动** - 通过配置对象定义Hook行为，无需重复编写类似代码
3. **反射优化** - 使用高效的反射机制，支持所有ent生成的实体
4. **灵活过滤** - 支持表级别的过滤规则配置
5. **向后兼容** - 提供兼容旧版API的便捷函数

## 快速开始

### 最简单的用法（推荐）

```go
import "github.com/coder-lulu/newbee-common/orm/ent/hooks"

// 在服务启动时，初始化ent client后立即调用
db := ent.NewClient(ent.Driver(drv))

// 一键设置：初始化配置 + 注册所有hooks
if err := hooks.QuickSetup(db); err != nil {
    panic(err)
}
```

这将自动：
- 初始化租户Hook配置（严格模式）
- 初始化部门Hook配置（宽松模式）
- 注册所有mutation hooks和query interceptors

### 分步设置（自定义）

如果需要自定义配置：

```go
import "github.com/coder-lulu/newbee-common/orm/ent/hooks"

// 步骤1：初始化默认配置
hooks.InitDefaultHookConfigs()

// 步骤2：（可选）修改配置
// 例如：修改租户Hook为宽松模式
tenantConfig := hooks.GlobalHookManager.GetConfig(hooks.FieldTypeTenant)
tenantConfig.RequireValue = false
tenantConfig.DefaultValue = 1

// 步骤3：注册hooks到client
if err := hooks.RegisterAllHooks(db); err != nil {
    panic(err)
}
```

### 仅注册特定Hook

```go
// 仅注册租户Hook
hooks.InitDefaultHookConfigs()
hooks.RegisterTenantHooks(db)

// 或仅注册部门Hook
hooks.InitDefaultHookConfigs()
hooks.RegisterDepartmentHooksUnified(db)
```

## 字段配置详解

### FieldConfig结构

```go
type FieldConfig struct {
    // 数据库字段名
    FieldName string

    // 字段类型标识
    FieldType FieldType

    // Mutation中的Setter方法名（如 "SetTenantID"）
    SetterMethod string

    // Mutation中的Getter方法名（如 "TenantID"）
    GetterMethod string

    // 从context提取字段值的函数
    ContextExtractor func(context.Context) (uint64, error)

    // 判断表是否需要应用过滤的函数
    ShouldApplyFilter func(tableName string) bool

    // 判断是否为系统上下文的函数
    IsSystemContext func(context.Context) bool

    // 不需要Hook处理的实体类型（如 ["Tenant"]）
    ExcludedEntities []string

    // 是否要求字段值必须存在
    // true = 严格模式：缺少字段值时返回错误
    // false = 宽松模式：缺少字段值时使用DefaultValue
    RequireValue bool

    // 默认值（仅在RequireValue=false时使用）
    DefaultValue uint64
}
```

## 工作原理

### Mutation Hook（Create操作）

1. 检查是否为系统上下文 → 设置字段为0
2. 检查实体是否在排除列表 → 跳过
3. 检查是否已设置字段值 → 跳过
4. 从context提取字段值
5. 自动注入字段值

### Query Interceptor（Query操作）

1. 检查是否为系统上下文 → 跳过过滤
2. 从context提取字段值
3. 使用反射添加SQL WHERE条件：`WHERE field_name = value`
4. 根据`ShouldApplyFilter`决定是否应用到特定表

## 高级用法

### 添加自定义字段Hook

```go
import "github.com/coder-lulu/newbee-common/orm/ent/hooks"

// 定义新的字段类型
const FieldTypeCreatedBy hooks.FieldType = "created_by"

// 注册配置
hooks.GlobalHookManager.RegisterField(&hooks.FieldConfig{
    FieldName:    "created_by",
    FieldType:    FieldTypeCreatedBy,
    SetterMethod: "SetCreatedBy",
    GetterMethod: "CreatedBy",
    ContextExtractor: func(ctx context.Context) (uint64, error) {
        // 从context提取当前用户ID
        userID := GetUserIDFromContext(ctx)
        if userID == 0 {
            return 0, errors.New("user ID not found")
        }
        return userID, nil
    },
    ShouldApplyFilter: func(tableName string) bool {
        // 不在query时过滤，只在create时注入
        return false
    },
    IsSystemContext: hooks.IsSystemContext,
    ExcludedEntities: []string{},
    RequireValue:     true,
    DefaultValue:     0,
})

// 注册到client
hooks.RegisterHooksToClient(db, FieldTypeCreatedBy)
```

### 动态配置过滤规则

```go
// 获取租户配置
tenantConfig := hooks.GlobalHookManager.GetConfig(hooks.FieldTypeTenant)

// 添加新的排除表
originalFilter := tenantConfig.ShouldApplyFilter
tenantConfig.ShouldApplyFilter = func(tableName string) bool {
    // 添加自定义排除逻辑
    if tableName == "my_custom_table" {
        return false
    }
    return originalFilter(tableName)
}
```

## 迁移指南

### 从旧版租户Hook迁移

**旧版代码：**
```go
db.Use(hooks.TenantMutationHook())
db.Intercept(hooks.TenantQueryInterceptor())
```

**新版代码（方式1 - 推荐）：**
```go
hooks.QuickSetup(db)
```

**新版代码（方式2 - 兼容）：**
```go
hooks.InitDefaultHookConfigs()
hooks.RegisterTenantHooks(db)
```

### 从旧版部门Hook迁移

**旧版代码：**
```go
hooks.RegisterDepartmentHooks(db)
```

**新版代码（方式1 - 推荐）：**
```go
hooks.QuickSetup(db)
```

**新版代码（方式2 - 兼容）：**
```go
hooks.InitDefaultHookConfigs()
hooks.RegisterDepartmentHooksUnified(db)
```

## 注意事项

1. **初始化顺序**：必须先调用`InitDefaultHookConfigs()`再注册hooks
2. **系统上下文**：使用`hooks.NewSystemContext(ctx)`创建系统上下文，会设置字段为0
3. **性能考虑**：Query interceptor使用反射+unsafe，性能已优化但仍有开销
4. **字段值验证**：
   - 租户ID：默认严格模式，必须存在且 > 0
   - 部门ID：默认宽松模式，可以为空
5. **排除表配置**：通过`ShouldApplyFilter`函数控制，支持通配符（在tenant.go中实现）

## API参考

### 核心函数

- `QuickSetup(client)` - 一键设置（推荐）
- `InitDefaultHookConfigs()` - 初始化默认配置
- `RegisterAllHooks(client)` - 注册所有hooks
- `RegisterTenantHooks(client)` - 仅注册租户hooks
- `RegisterDepartmentHooksUnified(client)` - 仅注册部门hooks
- `RegisterHooksToClient(client, ...fieldTypes)` - 注册指定类型的hooks

### 配置对象

- `GlobalHookManager` - 全局Hook管理器实例
- `FieldTypeTenant` - 租户字段类型常量
- `FieldTypeDepartment` - 部门字段类型常量

## 日志输出

系统会输出详细的日志用于调试：

```
[INFO] Registered unified hook field field_type=tenant_id field_name=tenant_id
[INFO] Registered mutation hook field_type=tenant_id
[INFO] Registered query interceptor field_type=tenant_id
[INFO] Auto-injected field value field_type=tenant_id entity_type=User value=2
[INFO] Applying field filter field_type=tenant_id query_type=*ent.UserQuery value=2
[DEBUG] Field filter check field_type=tenant_id table=users should_filter=true
[INFO] Field filter APPLIED field_type=tenant_id table=users value=2
```

## 常见问题

**Q: 为什么创建实体时没有自动注入tenant_id？**

A: 检查以下几点：
1. 是否调用了`InitDefaultHookConfigs()`
2. 是否注册了hooks到client
3. context中是否有tenant_id（使用`hooks.DiagnoseTenantContext(ctx)`诊断）
4. 实体是否在排除列表中

**Q: 查询时没有自动过滤租户数据？**

A: 检查：
1. 是否注册了query interceptor
2. 表是否在`ShouldApplyFilter`的排除列表中
3. 查看日志确认interceptor是否被触发

**Q: 如何临时跳过Hook？**

A: 使用系统上下文：
```go
systemCtx := hooks.NewSystemContext(ctx)
// 使用systemCtx进行操作
```

## 版本历史

- **v2.0** - 2025-10-07 - 统一Hook架构首次发布
- **v1.0** - 旧版独立的TenantHook和DepartmentHook实现

## 技术支持

如遇到问题，请提供：
1. 完整的错误日志
2. context诊断信息（使用`hooks.DiagnoseTenantContext(ctx)`）
3. Hook配置代码
4. ent schema定义
