# 新蜂资产管理平台 — 公共基础库

为平台核心、CMDB、统一 I/O 和运维中心提供共享 Go 组件，包括多租户上下文、数据权限、中间件、审计及 ORM 集成。该仓库是库模块，不提供独立服务进程。

仓库：[coder-lulu/newbee-common](https://github.com/coder-lulu/newbee-common) · [平台工作区](https://github.com/coder-lulu/newbee)

## 获取代码

推荐通过完整工作区开发，保留兄弟模块目录及本地 `replace` 依赖。以下命令使用 Bash；Go 工作区要求 Go 1.25.1 或更高版本。

```bash
git clone --recurse-submodules https://github.com/coder-lulu/newbee.git
cd newbee/common
```

已有工作区执行 `git submodule update --init --recursive`。单独克隆模块时，需要自行补齐 `go.mod` 中的本地依赖路径。

## 模块与目录

Go 模块路径为 `github.com/coder-lulu/newbee-common/v2`，引用时保留 `/v2`。

| 目录 | 用途 |
| --- | --- |
| `middleware/` | 认证、租户、数据权限及集成中间件 |
| `tenant/`、`orm/` | 租户上下文、Ent/GORM 支持 |
| `audit/`、`casbin/` | 审计与权限适配 |
| `config/`、`errors/`、`i18n/` | 配置、错误和国际化 |
| `utils/`、`types/` | 共享工具和类型 |

## 开发与验证

```bash
go test ./...
go vet ./...
go build ./...
```

配置由引用该库的服务提供；修改租户或数据权限组件时，同时验证调用方，避免绕过隔离检查。以上是本地验证命令，不代表当前全部测试已通过。

## 文档

- [公共库文档](docs/README.md)
- [数据权限中间件](middleware/dataperm/README.md)
- [加密中间件](middleware/encryption/README.md)
- [监控中间件](middleware/monitoring/README.md)

## 许可证与来源

本仓库采用 [Apache-2.0](LICENSE)。基于 [simple-admin-common](https://github.com/suyuan32/simple-admin-common) 演进，保留 Ryan SU 等上游作者版权。第三方依赖遵循各自许可证，保留原有版权与许可声明。
