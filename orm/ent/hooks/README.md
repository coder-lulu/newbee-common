# 多租户Hook和辅助函数

本包提供了统一的多租户数据隔离实现，确保所有使用ent的服务都能安全、一致地支持多租户功能。

## 核心组件

### 1. TenantMutationHook()
自动为创建操作设置租户ID的Hook。

### 2. TenantQueryInterceptor()  
自动为查询操作添加租户过滤的拦截器。

### 3. NewSystemContext()
创建系统级别的上下文，用于绕过租户检查的系统操作。

### 4. 辅助函数
- `GetCurrentTenantID()`: 获取当前租户ID
- `IsValidTenantContext()`: 检查租户上下文有效性
- `SetTenantIDToContext()`: 手动设置租户上下文

## 使用方法

### 1. 在服务初始化时注册Hook

```go
import (
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
)

func NewEntClient() *ent.Client {
    client := ent.NewClient(ent.Driver(drv))
    
    // 注册租户Hook（必需）
    client.Use(hooks.TenantMutationHook())
    client.Intercept(hooks.TenantQueryInterceptor())
    
    return client
}
```

### 2. 系统级操作

```go
import (
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
)

func (l *InitLogic) InitSystemData() error {
    // 创建系统上下文（会记录审计日志）
    systemCtx := hooks.NewSystemContext(l.ctx)
    
    // 使用系统上下文进行操作
    _, err := l.svcCtx.DB.Entity.Create().
        SetName("system").
        Save(systemCtx)
    
    return err
}
```

### 3. 获取租户信息

```go
import (
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
)

func (l *BusinessLogic) GetTenantData() {
    // 获取当前租户ID
    tenantID := hooks.GetCurrentTenantID(l.ctx)
    
    // 检查租户上下文有效性
    if !hooks.IsValidTenantContext(l.ctx) {
        return errors.New("invalid tenant context")
    }
    
    // 正常的业务逻辑，Hook会自动处理租户过滤
    entities, err := l.svcCtx.DB.Entity.Query().All(l.ctx)
}
```

## 安全注意事项

1. **必须使用这些公共Hook**：所有新服务都必须使用本包提供的Hook，不能自己实现
2. **SystemContext谨慎使用**：只有真正的系统级操作才能使用SystemContext
3. **不要绕过Hook**：严禁使用原生SQL绕过ent的Hook机制
4. **审计日志**：SystemContext的使用会自动记录审计日志

## 测试

每个使用这些Hook的服务都应该包含租户隔离测试：

```go
func TestTenantIsolation(t *testing.T) {
    // 测试租户A的数据不能被租户B访问
    ctxA := hooks.SetTenantIDToContext(context.Background(), 1)
    ctxB := hooks.SetTenantIDToContext(context.Background(), 2)
    
    // 租户A创建数据
    _, err := client.Entity.Create().SetName("test").Save(ctxA)
    require.NoError(t, err)
    
    // 租户B查询不应该看到租户A的数据
    entities, err := client.Entity.Query().All(ctxB)
    require.NoError(t, err)
    assert.Empty(t, entities)
}
```
