# 多租户中间件集成指南

这是一个通用的多租户数据隔离中间件，支持在多个微服务中零侵入集成。

## 🚀 快速开始

### 基础集成（推荐）

适用于大多数微服务，只需2行代码：

```go
package main

import (
    "github.com/coder-lulu/newbee-core/rpc/ent"
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
)

func main() {
    // 初始化数据库连接
    db, err := ent.Open("mysql", "your-dsn")
    if err != nil {
        panic(err)
    }
    
    // 集成租户中间件（只需这2行）
    db.Use(hooks.TenantMutationHook())     // 自动添加租户ID到创建操作
    db.Intercept(hooks.TenantQueryInterceptor()) // 自动过滤查询结果
    
    // 正常使用数据库...
}
```

## 🎛️ 高级配置

### 微服务自定义配置

如果你的微服务有特殊的表需要排除租户过滤：

```go
package main

import (
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
)

func init() {
    // 为当前微服务自定义租户过滤配置
    config := &hooks.TenantFilterConfig{
        // 直接排除的表名
        ExcludedTables: map[string]bool{
            "order_global_settings": true,  // 订单服务全局设置表
            "order_system_cache":    true,  // 订单服务系统缓存表
        },
        
        // 通配符模式排除
        ExcludedPatterns: []string{
            "*_tenants",         // 所有租户表
            "*_audit_logs",      // 所有审计日志表
            "order_temp_*",      // 订单服务所有临时表
            "*_cache",           // 所有缓存表
            "*_migrations",      // 所有迁移表
        },
        
        // 全局表类型（按后缀匹配）
        GlobalTables: []string{
            "tenants", "migrations", "cache", "config", "logs",
        },
    }
    
    // 应用配置
    hooks.SetTenantFilterConfig(config)
}
```

### 运行时动态配置

在应用运行过程中动态添加排除表：

```go
// 动态添加需要排除的表
hooks.AddExcludedTable("special_global_table")
hooks.AddExcludedTable("runtime_cache_table")

// 测试表是否会被过滤（可选，主要用于调试）
needFilter := hooks.ShouldApplyTenantFilter("my_table")
fmt.Printf("my_table 需要租户过滤: %v\n", needFilter)
```

## 📋 默认排除规则

中间件默认会排除以下类型的表，无需额外配置：

### 通配符排除
- `*_tenants` - 所有租户表
- `*_audit_logs` - 所有审计日志表  
- `*_oauth_providers` - 所有OAuth提供商表
- `*_apis` - 所有API表
- `*_migrations` - 所有数据库迁移表
- `*_schema_*` - 所有数据库schema表

### 全局表类型排除
- 包含 `tenants` 的表名
- 包含 `audit_logs` 的表名
- 包含 `oauth_providers` 的表名
- 包含 `apis` 的表名
- 包含 `migrations` 的表名

## 🔧 使用租户上下文

### 在业务代码中使用

```go
import (
    "context"
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
)

func BusinessLogic(ctx context.Context, db *ent.Client) {
    // 1. 设置租户上下文（通常从JWT token或请求头获取租户ID）
    tenantID := uint64(123) // 从认证信息获取
    tenantCtx := hooks.SetTenantIDToContext(ctx, tenantID)
    
    // 2. 使用租户上下文进行数据库操作
    // 查询会自动过滤当前租户的数据
    users, err := db.User.Query().All(tenantCtx)
    
    // 创建会自动添加租户ID
    newUser, err := db.User.Create().
        SetName("张三").
        SetEmail("zhangsan@example.com").
        Save(tenantCtx)
        
    // 3. 系统级操作（可以访问所有租户数据）
    systemCtx := hooks.NewSystemContext(ctx)
    allUsers, err := db.User.Query().All(systemCtx)
}
```

### 在HTTP中间件中设置租户上下文

```go
func TenantMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // 从JWT token或请求头获取租户ID
        tenantID := extractTenantIDFromRequest(c)
        
        // 设置租户上下文
        tenantCtx := hooks.SetTenantIDToContext(c.Request.Context(), tenantID)
        
        // 更新请求上下文
        c.Request = c.Request.WithContext(tenantCtx)
        
        c.Next()
    }
}
```

## 🛡️ 系统管理操作

对于需要跨租户访问的系统管理操作：

```go
func AdminOperation(ctx context.Context, db *ent.Client) {
    // 创建系统上下文，可以访问所有租户数据
    systemCtx := hooks.NewSystemContext(ctx)
    
    // 查询所有租户的用户
    allUsers, err := db.User.Query().All(systemCtx)
    
    // 创建系统级数据（租户ID为0）
    systemConfig, err := db.Configuration.Create().
        SetKey("global_setting").
        SetValue("system_value").
        Save(systemCtx)
}
```

## 📊 验证租户隔离

可以使用提供的测试函数验证租户隔离是否正常工作：

```go
func TestTenantIsolation(t *testing.T) {
    // 测试表是否会被租户过滤
    assert.True(t, hooks.ShouldApplyTenantFilter("user_orders"))
    assert.False(t, hooks.ShouldApplyTenantFilter("sys_tenants"))
    
    // 测试租户上下文
    ctx := context.Background()
    tenantCtx := hooks.SetTenantIDToContext(ctx, 123)
    
    // 验证租户数据隔离...
}
```

## ⚠️ 注意事项

1. **表结构要求**: 需要租户隔离的表必须有 `tenant_id` 字段（建议使用TenantMixin）

2. **性能考虑**: 中间件使用unsafe包访问私有字段，在生产环境中性能良好

3. **安全性**: SystemContext会记录审计日志，避免滥用

4. **兼容性**: 支持所有Ent生成的查询类型，适用于任何微服务架构

## 🔍 故障排除

### 租户隔离不生效

1. 检查表是否有 `tenant_id` 字段
2. 确认表名未被配置为排除表
3. 验证租户上下文是否正确设置

### 某些表不应该被过滤

使用配置或动态添加方式排除该表：

```go
// 方式1: 配置排除
hooks.AddExcludedTable("global_table_name")

// 方式2: 检查当前配置
needFilter := hooks.ShouldApplyTenantFilter("table_name")
```

## 📚 更多示例

查看项目中的测试文件获取更多使用示例：
- `test_tenant_isolation.go` - 完整的租户隔离测试
- `test_multi_service_config.go` - 多微服务配置示例
- `test_simple_tenant.go` - 基础使用示例