// Copyright 2023 The Ryan SU Authors (https://github.com/suyuan32). All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import "context"

// CasbinRuleEntity 定义Casbin规则实体的通用接口
// 用于解耦EntAdapter和具体的ent实现
type CasbinRuleEntity interface {
	// GetID 获取规则ID
	GetID() uint64

	// GetPtype 获取策略类型 (p, g等)
	GetPtype() string

	// GetV0-V5 获取规则参数
	// RBAC with Domains模型中：
	// - Policy (p): v0=sub, v1=domain, v2=obj, v3=act, v4=eft
	// - Role (g): v0=user, v1=domain, v2=role
	GetV0() string
	GetV1() string
	GetV2() string
	GetV3() string
	GetV4() string
	GetV5() string

	// GetTenantID 获取租户ID（用于多租户隔离）
	GetTenantID() uint64

	// GetStatus 获取状态 (1=启用, 0=禁用)
	GetStatus() uint8

	// 企业特性字段
	GetRequireApproval() bool
	GetApprovalStatus() string

	// 时间窗口字段检查
	HasEffectiveFrom() bool
	HasEffectiveTo() bool
}

// CasbinRuleQuerier 定义Casbin规则查询器接口
// 不同的服务可以提供不同的实现（直接数据库查询 或 RPC调用）
type CasbinRuleQuerier interface {
	// QueryCasbinRules 查询指定租户的所有Casbin规则
	// ctx: 上下文
	// tenantID: 租户ID
	// 返回: 规则实体列表和错误
	QueryCasbinRules(ctx context.Context, tenantID uint64) ([]CasbinRuleEntity, error)
}
