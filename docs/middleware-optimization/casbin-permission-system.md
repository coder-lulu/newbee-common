# Casbin权限管理系统实施方案

> **Version**: 1.0  
> **Created**: 2024-12-20  
> **Author**: @NewBee架构团队  
> **Status**: 实施中

## 🎯 项目概述

基于Casbin实现企业级权限管理系统，解决当前数据权限中间件的功能局限性，支持CMDB复杂的多层级权限控制和运维脚本权限管理。严格遵循CLAUDE.md编码规则，确保多租户安全和数据权限集成。

### 核心目标
- ✅ 统一权限管理：一套Casbin策略解决所有权限需求
- ✅ 多层级控制：支持全局→CI类型→CI实例→属性→字段5层权限
- ✅ 动态配置：权限规则实时配置和热更新
- ✅ 高性能：多级缓存+策略预计算，10倍性能提升
- ✅ 租户隔离：严格的多租户权限隔离机制

## 🏗️ 系统架构设计

### 分层架构
```
┌─────────────────────────────────────────────────────────┐
│                    业务服务层                             │
├─────────────────┬─────────────────┬─────────────────────┤
│   Core API      │   CMDB API      │   其他业务服务       │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────┐ │
│ │权限管理界面  │ │ │CI权限界面   │ │ │业务专用权限界面  │ │
│ │- 用户管理   │ │ │- CI类型权限 │ │ │- 特定业务规则   │ │
│ │- 角色管理   │ │ │- 实例权限   │ │ │- 自定义策略     │ │
│ │- 基础权限   │ │ │- 字段权限   │ │ │- 流程审批       │ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────────┘ │
└─────────────────┴─────────────────┴─────────────────────┘
                            │
├─────────────────────────────────────────────────────────┤
│                   统一权限中间件层                        │
│ ┌─────────────────────────────────────────────────────┐ │
│ │           Enhanced DataPerm Plugin                  │ │
│ │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │ │
│ │  │ Casbin Core │  │ Policy Cache│  │Rule Manager │ │ │
│ │  └─────────────┘  └─────────────┘  └─────────────┘ │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                            │
├─────────────────────────────────────────────────────────┤
│                   权限存储和通信层                        │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│ │ Redis Cache │  │ Database    │  │ Message Queue   │ │
│ │- 规则缓存   │  │- 规则持久化 │  │- 规则变更通知   │ │
│ │- 决策缓存   │  │- 审计日志   │  │- 集群同步       │ │
│ └─────────────┘  └─────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## 📊 实施计划

### 总体时间表：10周（2.5个月）

| 阶段 | 任务 | 时间 | 关键交付物 |
|------|------|------|-----------|
| 阶段一 | 数据模型设计与RPC接口 | 2周 | ent Schema, RPC Proto, 代码生成 |
| 阶段二 | Core RPC服务实现 | 2周 | Casbin适配器, 权限检查逻辑, RPC服务 |
| 阶段三 | Core API服务集成 | 1周 | API路由, Handler, 中间件集成 |
| 阶段四 | 数据权限中间件增强 | 2周 | 增强插件, 规则同步, 兼容性保证 |
| 阶段五 | 前端管理界面 | 2周 | 规则管理页面, 权限测试界面 |
| 阶段六 | 性能优化和监控 | 1周 | 缓存优化, 监控指标, 性能测试 |

## 🔧 阶段一：数据模型设计与RPC接口（2周）

### 1.1 ent Schema设计

**严格遵循CLAUDE.md规则**：
- ✅ 必须包含 `TenantMixin` 实现租户隔离
- ✅ 使用标准的Mixin结构
- ✅ 合适的索引设计

```go
// core/rpc/ent/schema/casbin_rule.go
package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "entgo.io/ent/schema/index"
    "github.com/coder-lulu/newbee-common/orm/ent/mixins"
)

type CasbinRule struct {
    ent.Schema
}

func (CasbinRule) Mixin() []ent.Mixin {
    return []ent.Mixin{
        mixins.IDMixin{},
        mixins.StatusMixin{},
        mixins.TenantMixin{}, // 🔥 必须包含租户隔离
    }
}

func (CasbinRule) Fields() []ent.Field {
    return []ent.Field{
        // Casbin标准字段
        field.String("ptype").Comment("策略类型: p, g, g2等"),
        field.String("v0").Optional().Comment("主体"),
        field.String("v1").Optional().Comment("资源"),
        field.String("v2").Optional().Comment("操作"),
        field.String("v3").Optional().Comment("效果"),
        field.Text("v4").Optional().Comment("条件表达式JSON"),
        field.String("v5").Optional().Comment("优先级"),
        
        // 业务扩展字段
        field.String("service_name").Comment("服务名称"),
        field.String("rule_name").Optional().Comment("规则名称"),
        field.Text("description").Optional().Comment("规则描述"),
        field.String("category").Default("custom").Comment("规则分类"),
        field.String("version").Default("1.0.0").Comment("规则版本"),
        
        // 审批流程字段
        field.Bool("require_approval").Default(false).Comment("是否需要审批"),
        field.Enum("approval_status").Values("pending", "approved", "rejected").Default("approved"),
        field.Uint64("approved_by").Optional().Comment("审批人ID"),
        field.Time("approved_at").Optional().Comment("审批时间"),
        
        // 时间控制字段
        field.Time("effective_from").Optional().Comment("生效开始时间"),
        field.Time("effective_to").Optional().Comment("生效结束时间"),
        field.Bool("is_temporary").Default(false).Comment("是否为临时权限"),
    }
}

func (CasbinRule) Indexes() []ent.Index {
    return []ent.Index{
        // 租户+服务查询优化
        index.Fields("tenant_id", "service_name", "status"),
        // Casbin策略查询优化
        index.Fields("ptype", "v0", "v1"),
        // 审批状态查询
        index.Fields("approval_status", "require_approval"),
        // 时间范围查询
        index.Fields("effective_from", "effective_to"),
    }
}
```

### 1.2 RPC接口定义

```protobuf
// core/rpc/desc/casbin.proto
syntax = "proto3";

package core;

// Casbin规则信息
message CasbinRuleInfo {
    optional uint64 id = 1;
    optional int64 created_at = 2;
    optional int64 updated_at = 3;
    optional uint64 tenant_id = 4; // 🔥 租户ID必须
    
    // Casbin标准字段
    string ptype = 5;
    optional string v0 = 6;
    optional string v1 = 7; 
    optional string v2 = 8;
    optional string v3 = 9;
    optional string v4 = 10;
    optional string v5 = 11;
    
    // 业务字段
    string service_name = 12;
    optional string rule_name = 13;
    optional string description = 14;
    optional string category = 15;
    optional string version = 16;
    
    // 审批字段
    optional bool require_approval = 17;
    optional string approval_status = 18;
    optional uint64 approved_by = 19;
    optional int64 approved_at = 20;
    
    // 时间控制
    optional int64 effective_from = 21;
    optional int64 effective_to = 22;
    optional bool is_temporary = 23;
    
    optional uint32 status = 24;
}

message CasbinRuleListReq {
    uint64 page = 1;
    uint64 page_size = 2;
    optional string service_name = 3;
    optional string ptype = 4;
    optional string v0 = 5;
    optional uint32 status = 6;
    optional string approval_status = 7;
}

message CasbinRuleListResp {
    uint64 total = 1;
    repeated CasbinRuleInfo data = 2;
}

// 权限检查请求
message PermissionCheckReq {
    string service_name = 1;
    string subject = 2;      // 用户ID或角色
    string object = 3;       // 资源路径
    string action = 4;       // 操作类型
    map<string, string> context = 5; // 上下文信息
}

message PermissionCheckResp {
    bool allowed = 1;
    string reason = 2;
    repeated string applied_rules = 3;
    map<string, string> data_filters = 4; // 数据过滤条件
}

service Core {
    // Casbin规则管理 - 🔥 必须包含TenantCheck,DataPerm中间件
    rpc createCasbinRule (CasbinRuleInfo) returns (BaseIDResp);
    rpc updateCasbinRule (CasbinRuleInfo) returns (BaseResp);
    rpc deleteCasbinRule (IDsReq) returns (BaseResp);
    rpc getCasbinRuleList (CasbinRuleListReq) returns (CasbinRuleListResp);
    rpc getCasbinRuleById (IDReq) returns (CasbinRuleInfo);
    
    // 权限验证
    rpc checkPermission (PermissionCheckReq) returns (PermissionCheckResp);
    
    // 规则同步
    rpc syncCasbinRules (StringReq) returns (BaseResp); // service_name
    rpc refreshCasbinCache (BaseReq) returns (BaseResp);
}
```

### 1.3 开发流程命令

**严格遵循CLAUDE.md开发流程**：

```bash
# 步骤1: 修改ent Schema
# 编辑 core/rpc/ent/schema/casbin_rule.go

# 步骤2: 生成ent代码
cd /opt/code/newbee/core/rpc
go run entgo.io/ent/cmd/ent generate --template glob="./ent/template/*.tmpl" ./ent/schema --feature sql/execquery,intercept

# 步骤3: 生成RPC代码
make gen-rpc
```

## 🔧 阶段二：Core RPC服务实现（2周）

### 2.1 ServiceContext增强

```go
// core/rpc/internal/svc/service_context.go
type ServiceContext struct {
    Config config.Config
    DB     *ent.Client
    Redis  redis.UniversalClient
    
    // 🔥 新增Casbin相关服务
    CasbinEnforcer    *casbin.Enforcer
    CasbinAdapter     *EntAdapter      // 自定义ent适配器
    PolicyManager     *PolicyManager   // 策略管理器
    PermissionChecker *PermissionChecker
}

func NewServiceContext(c config.Config) *ServiceContext {
    // 数据库初始化
    db := ent.NewClient(...)
    
    // 🔥 必须注册租户Hook
    db.Use(hooks.TenantMutationHook())
    db.Intercept(hooks.TenantQueryInterceptor())
    
    // 初始化Casbin
    adapter := NewEntAdapter(db)
    enforcer, err := casbin.NewEnforcer("etc/casbin_model.conf", adapter)
    if err != nil {
        panic(fmt.Sprintf("Failed to create casbin enforcer: %v", err))
    }
    
    return &ServiceContext{
        Config:            c,
        DB:                db,
        CasbinEnforcer:    enforcer,
        CasbinAdapter:     adapter,
        PolicyManager:     NewPolicyManager(db, enforcer),
        PermissionChecker: NewPermissionChecker(enforcer),
    }
}
```

### 2.2 租户隔离的Casbin适配器

**核心特性**：
- 租户级策略隔离
- 系统上下文的安全操作
- 策略的动态加载和保存

### 2.3 权限检查逻辑

**功能包括**：
- 租户化的权限验证
- 权限决策缓存
- 数据过滤条件生成
- 审计日志记录

## 🌐 阶段三：Core API服务集成（1周）

### 3.1 API路由定义

**严格遵循中间件要求**：
```go
@server(
    jwt: Auth
    middleware: Authority,TenantCheck,DataPerm  // 🔥 必须包含
    group: casbin
)
```

### 3.2 API功能

- 权限规则CRUD操作
- 权限验证接口
- 规则同步和缓存管理
- 权限测试和调试

## 🔧 阶段四：数据权限中间件增强（2周）

### 4.1 向后兼容保证

**重要原则**：
- ✅ 保持现有DataScope枚举类型不变
- ✅ 现有角色权限逻辑继续工作  
- ✅ 渐进式升级，避免破坏性变更

### 4.2 增强功能

- 集成Casbin权限引擎
- 规则实时同步机制
- 多级权限决策缓存
- 性能监控和告警

## 📱 阶段五：前端管理界面（2周）

### 5.1 核心功能

- 权限规则可视化管理
- 规则编辑器和验证
- 权限测试工具
- 审计日志查看
- 性能监控面板

### 5.2 用户体验

- 直观的权限配置界面
- 实时的权限测试反馈
- 权限规则模板支持
- 批量操作功能

## ⚡ 阶段六：性能优化和监控（1周）

### 6.1 性能优化

**多级缓存架构**：
- L1: 内存LRU缓存（最快访问）
- L2: Redis缓存（分布式共享）
- L3: 数据库（持久化存储）

**预期性能**：
- 权限检查响应时间：50ms → 5ms
- 并发处理能力：支持10,000+ QPS
- 缓存命中率：95%+

### 6.2 监控指标

- 权限检查次数和耗时
- 缓存命中率统计
- 权限拒绝次数和原因
- 规则变更频率
- 系统资源使用情况

## 🔒 安全和合规保证

### 多租户安全
- ✅ 严格的租户数据隔离
- ✅ 所有表包含TenantMixin
- ✅ 租户上下文验证
- ✅ 跨租户访问防护

### 权限安全
- ✅ 默认拒绝策略
- ✅ 权限最小化原则
- ✅ 详细的审计日志
- ✅ 权限变更审批流程

### 数据权限集成
- ✅ 与现有DataPerm完全兼容
- ✅ 支持五级数据权限
- ✅ 租户级权限隔离
- ✅ 实时权限生效

## 📊 预期效果

### 功能增强
- **权限粒度**：支持5层级精细权限控制
- **动态配置**：权限规则实时配置和热更新
- **统一管理**：一套系统管理所有权限需求
- **条件化权限**：基于业务规则的动态权限判断

### 性能提升
- **响应时间**：权限检查从50ms降低到5ms
- **并发能力**：支持10,000+ QPS的权限检查
- **资源优化**：内存使用减少60%
- **缓存效率**：95%+的缓存命中率

### 运维友好
- **可视化管理**：直观的权限配置界面
- **实时监控**：完整的权限使用监控
- **审计完整**：详细的权限操作审计
- **故障恢复**：完善的降级和恢复机制

## 🚀 实施里程碑

### 第1-2周：数据模型和RPC
- [ ] CasbinRule ent schema设计完成
- [ ] RPC接口定义完成
- [ ] ent和RPC代码生成成功
- [ ] 基础数据结构验证通过

### 第3-4周：Core RPC服务
- [ ] Casbin适配器实现完成
- [ ] 权限检查逻辑实现完成
- [ ] 规则管理功能实现完成
- [ ] 租户隔离验证通过

### 第5周：Core API集成
- [ ] API路由和Handler完成
- [ ] 中间件集成验证通过
- [ ] API功能测试通过
- [ ] 接口文档完成

### 第6-7周：中间件增强
- [ ] DataPermPlugin增强完成
- [ ] 规则同步机制完成
- [ ] 向后兼容性验证通过
- [ ] 性能基准测试通过

### 第8-9周：前端界面
- [ ] 权限管理页面完成
- [ ] 规则编辑器完成
- [ ] 权限测试工具完成
- [ ] 用户体验测试通过

### 第10周：优化和监控
- [ ] 性能优化完成
- [ ] 监控指标部署完成
- [ ] 压力测试通过
- [ ] 文档和培训完成

## 📋 验收标准

### 功能验收
- [ ] 支持5层级权限控制（全局→CI类型→CI实例→属性→字段）
- [ ] 权限规则动态配置和实时生效
- [ ] 完整的审批工作流支持
- [ ] 多租户权限严格隔离
- [ ] 与现有系统完全兼容

### 性能验收
- [ ] 权限检查响应时间≤5ms
- [ ] 支持并发QPS≥10,000
- [ ] 缓存命中率≥95%
- [ ] 内存使用优化≥60%
- [ ] 系统稳定性≥99.9%

### 安全验收
- [ ] 租户数据完全隔离
- [ ] 权限提升攻击防护
- [ ] 完整的审计日志
- [ ] 权限异常监控告警
- [ ] 安全漏洞扫描通过

## 🎯 成功标准

本项目成功的标志是：

1. **完全替代现有权限系统**：新系统能够处理所有现有权限需求
2. **支持CMDB复杂需求**：满足CI权限的精细化管理要求
3. **性能显著提升**：权限检查性能提升10倍以上
4. **运维体验优化**：管理员能够轻松配置和维护权限规则
5. **零停机升级**：系统升级过程中业务不受影响

这个Casbin权限管理系统将成为NewBee平台权限管理的核心基础设施，为所有业务服务提供统一、高效、安全的权限控制能力。

---

**项目状态**: 🚀 准备开始实施  
**负责团队**: NewBee架构团队  
**优先级**: P0（核心基础设施）  
**风险评估**: 低（基于成熟技术栈，有完整实施计划）