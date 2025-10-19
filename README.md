# NewBee Common

[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.24-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.1-brightgreen)](https://github.com/coder-lulu/newbee-common/releases)

NewBee Common 是一个企业级 Go 语言公共库，为 NewBee 微服务生态系统提供统一的中间件、工具和基础设施组件。

## 核心特性

### 🔐 统一认证与授权
- **JWT 认证** - 高性能 JWT Token 验证，支持 Redis 缓存
- **RBAC 权限控制** - 基于 Casbin 的角色权限管理
- **多租户隔离** - 完整的 SaaS 多租户架构支持
- **数据权限** - 五级数据权限控制（全部/自定义部门/本部门及下级/本部门/仅本人）

### 🛡️ 安全与加密
- **AES-256-GCM 加密** - API 请求/响应端到端加密
- **字段掩码** - 敏感字段动态脱敏（手机号、身份证、邮箱等）
- **审计日志** - 完整的操作审计追踪
- **防注入保护** - 严格的输入验证和 SQL 安全

### ⚡ 性能优化
- **智能缓存** - Redis 多级缓存策略
- **连接池管理** - 高效的数据库和 Redis 连接池
- **批量操作** - 支持批量权限检查和数据操作
- **异步处理** - 异步日志写入和事件处理

### 🏗️ ORM 与数据库
- **Ent ORM 集成** - 强类型 ORM，支持自动迁移
- **租户 Hook** - 自动租户字段注入和查询过滤
- **数据权限拦截器** - 透明的数据权限过滤
- **GORM 支持** - 兼容 GORM 的多租户实现

## 快速开始

### 安装

```bash
go get github.com/coder-lulu/newbee-common@v2.0.1
```

### 基础使用

#### 1. 统一中间件集成

```go
import "github.com/coder-lulu/newbee-common/middleware/integration"

// 初始化统一中间件
result, err := integration.Setup(&integration.Config{
    Redis:     redisClient,
    JWTSecret: "your-jwt-secret",
    Mode:      integration.Production, // Production/Development/Testing
})
if err != nil {
    panic(err)
}

// 应用到 go-zero 服务
integration.ApplyToServer(server, result)
```

#### 2. Ent ORM 多租户集成

```go
import (
    "github.com/coder-lulu/newbee-common/orm/ent/hooks"
    "github.com/coder-lulu/newbee-common/orm/ent/mixins"
)

// Schema 定义
func (User) Mixin() []ent.Mixin {
    return []ent.Mixin{
        mixins.IDMixin{},
        mixins.StatusMixin{},
        mixins.TenantMixin{}, // 必须包含
    }
}

// 注册 Hook 和拦截器
db := ent.NewClient(...)
db.Use(hooks.TenantMutationHook())
db.Intercept(hooks.TenantQueryInterceptor())

// 注册数据权限拦截器
hooks.RegisterDataPermissionInterceptorsWithTenant(db,
    "users", "departments", "positions", "roles")
```

#### 3. JWT 工具使用

```go
import "github.com/coder-lulu/newbee-common/utils/jwt"

// 生成 Token
token, err := jwt.GenerateToken(jwt.Claims{
    UserID:   1,
    TenantID: 1,
    RoleCode: "admin",
})

// 验证 Token
claims, err := jwt.ParseToken(token)
```

#### 4. 加密中间件

```go
import "github.com/coder-lulu/newbee-common/middleware/encryption"

// 配置加密中间件
encryptionPlugin := encryption.NewPlugin(&encryption.Config{
    Enabled:    true,
    MasterKey:  "your-32-byte-master-key-here!",
    Algorithm:  "AES-256-GCM",
})
```

## 目录结构

```
newbee-common/
├── audit/              # 审计日志组件
├── casbin/             # Casbin 权限适配器
├── config/             # 统一配置管理
├── enum/               # 枚举定义
├── errors/             # 错误处理
├── i18n/               # 国际化支持
├── middleware/         # 统一中间件框架
│   ├── auth/          # JWT 认证中间件
│   ├── tenant/        # 多租户中间件
│   ├── dataperm/      # 数据权限中间件
│   ├── permission/    # RBAC 权限中间件
│   ├── audit/         # 审计日志中间件
│   ├── encryption/    # 加密中间件
│   ├── integration/   # 统一集成框架
│   └── ...
├── msg/                # 消息定义
│   ├── errormsg/      # 错误消息
│   └── logmsg/        # 日志消息
├── orm/                # ORM 集成
│   ├── ent/           # Ent ORM Hook 和 Mixin
│   └── gorm/          # GORM 多租户支持
├── plugins/            # 插件系统
│   ├── casbin/        # Casbin 插件
│   ├── mq/            # 消息队列插件
│   └── storage/       # 存储插件
├── state/              # 状态管理
├── tenant/             # 租户管理
├── types/              # 公共类型定义
└── utils/              # 工具库
    ├── captcha/       # 验证码
    ├── crypto/        # 加密工具
    ├── encrypt/       # 加密/解密
    ├── jwt/           # JWT 工具
    ├── pointy/        # 指针工具
    ├── uuidx/         # UUID 生成
    └── validator/     # 数据验证
```

## 核心组件

### 中间件系统

| 中间件 | 优先级 | 功能 | 文档 |
|--------|--------|------|------|
| Auth | 10 | JWT 认证和用户信息提取 | [详细指南](docs/统一认证中间件详细指南.md) |
| TenantCheck | 20 | 租户验证和限流 | [详细指南](docs/统一租户中间件详细指南.md) |
| DataPerm | 30 | 数据权限过滤 | [详细指南](docs/统一数据权限中间件详细指南.md) |
| Permission | 35 | RBAC 权限检查 | [详细指南](docs/统一RBAC权限中间件详细指南.md) |
| Audit | 40 | 审计日志记录 | [详细指南](docs/统一审计中间件详细指南.md) |
| Encryption | 50 | 请求/响应加密 | [详细指南](docs/加密中间件使用指南.md) |

### ORM Hook 系统

| Hook | 类型 | 功能 | 文档 |
|------|------|------|------|
| TenantMutationHook | Mutation | 自动注入租户 ID | [Hook 指南](docs/统一Hook系统使用指南.md) |
| TenantQueryInterceptor | Query | 自动过滤租户数据 | [Hook 指南](docs/统一Hook系统使用指南.md) |
| DataPermissionInterceptor | Query | 数据权限过滤 | [Hook 指南](docs/统一Hook系统使用指南.md) |

### 工具库

| 工具 | 功能 | 示例 |
|------|------|------|
| jwt | JWT Token 生成和验证 | `jwt.GenerateToken(claims)` |
| crypto | AES-GCM 加密/解密 | `crypto.Encrypt(data, key)` |
| encrypt | 密码哈希和验证 | `encrypt.BcryptHash(password)` |
| pointy | 指针工具 | `pointy.GetPointer(value)` |
| uuidx | UUID 生成 | `uuidx.NewUUID()` |
| validator | 数据验证 | `validator.Validate(struct)` |

## 文档

### 📚 完整文档
- [中间件文档索引](docs/README.md) - 所有文档的导航入口
- [快速参考手册](docs/统一权限中间件快速参考.md) - 常用配置和代码片段
- [配置示例大全](docs/统一权限中间件配置示例.md) - 各种场景的配置模板

### 🎯 专题指南
- [统一认证中间件](docs/统一认证中间件详细指南.md) - JWT 认证和缓存优化
- [统一租户中间件](docs/统一租户中间件详细指南.md) - 多租户隔离和限流
- [统一数据权限中间件](docs/统一数据权限中间件详细指南.md) - 数据权限控制
- [统一RBAC权限中间件](docs/统一RBAC权限中间件详细指南.md) - 角色权限管理
- [统一审计中间件](docs/统一审计中间件详细指南.md) - 审计日志系统
- [加密中间件](docs/加密中间件使用指南.md) - API 加密传输
- [Hook 系统](docs/统一Hook系统使用指南.md) - ORM Hook 使用

### 🚀 快速开始
1. [5分钟快速集成](docs/统一权限中间件快速参考.md#-5分钟快速集成)
2. [架构设计原理](docs/统一权限中间件使用指南.md#架构设计)
3. [生产环境部署](docs/统一权限中间件配置示例.md#-生产环境配置)

## 版本要求

- Go >= 1.24
- Redis >= 6.0
- MySQL >= 8.0 (或其他兼容数据库)

## 依赖项

主要依赖：
- `entgo.io/ent` - ORM 框架
- `github.com/casbin/casbin/v2` - 权限管理
- `github.com/zeromicro/go-zero` - 微服务框架
- `github.com/redis/go-redis/v9` - Redis 客户端
- `github.com/golang-jwt/jwt/v5` - JWT 实现

## 贡献指南

欢迎贡献代码和文档！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 Apache 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件

## 联系方式

- 项目主页: https://github.com/coder-lulu/newbee-common
- 问题反馈: https://github.com/coder-lulu/newbee-common/issues
- 文档: [docs/README.md](docs/README.md)

## 致谢

感谢以下开源项目：
- [Ent](https://entgo.io/) - 强大的 Go ORM 框架
- [Casbin](https://casbin.org/) - 权限管理框架
- [go-zero](https://go-zero.dev/) - 微服务框架
- [go-redis](https://github.com/redis/go-redis) - Redis 客户端

---

**开始您的企业级微服务开发之旅！** 🚀
