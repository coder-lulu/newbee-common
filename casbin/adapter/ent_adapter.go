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

package adapter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/coder-lulu/newbee-common/casbin/types"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
)

// EntAdapter Casbin适配器，基于通用接口实现
// 通过依赖注入CasbinRuleQuerier，解耦具体的数据访问实现
type EntAdapter struct {
	querier types.CasbinRuleQuerier
	ctx     context.Context
	cached  bool
}

// NewEntAdapter 创建新的ent适配器
// querier: 规则查询器（可以是直接数据库查询，也可以是RPC调用）
// ctx: 上下文（包含租户信息）
func NewEntAdapter(querier types.CasbinRuleQuerier, ctx context.Context) *EntAdapter {
	return &EntAdapter{
		querier: querier,
		ctx:     ctx,
		cached:  false,
	}
}

// LoadPolicy 从数据库加载所有规则到模型
// 🔥 关键：通过querier查询规则，支持多种实现方式
func (a *EntAdapter) LoadPolicy(model model.Model) error {
	// 🔥 获取租户ID - 确保多租户隔离安全
	tenantID := tenantctx.GetTenantIDFromCtx(a.ctx)

	// 通过querier查询规则（具体实现由注入的querier决定）
	rules, err := a.querier.QueryCasbinRules(a.ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to query casbin rules: %w", err)
	}

	// 处理每条规则
	for _, rule := range rules {
		// 检查规则状态
		if rule.GetStatus() != 1 {
			continue // 跳过禁用的规则
		}

		// 检查是否需要审批且未审批
		if rule.GetRequireApproval() && rule.GetApprovalStatus() != "approved" {
			continue
		}

		// 检查规则是否在有效期内
		if !a.isRuleEffective(rule) {
			continue
		}

		// 转换为casbin规则格式
		policyRule := a.convertToPolicyRule(rule)
		if policyRule != nil {
			persist.LoadPolicyLine(strings.Join(policyRule, ", "), model)
		}
	}

	return nil
}

// SavePolicy 保存所有规则到数据库（通常不用，我们使用增量更新）
func (a *EntAdapter) SavePolicy(model model.Model) error {
	// 由于我们使用数据库作为主存储，这里只记录日志
	return fmt.Errorf("SavePolicy not implemented: use database operations instead")
}

// AddPolicy 添加单个规则
func (a *EntAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	// 实际的添加操作应该通过RPC接口进行
	// 这里只是为了实现接口
	return nil
}

// RemovePolicy 删除单个规则
func (a *EntAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	// 实际的删除操作应该通过RPC接口进行
	// 这里只是为了实现接口
	return nil
}

// RemoveFilteredPolicy 删除匹配的规则
func (a *EntAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	// 实际的删除操作应该通过RPC接口进行
	// 这里只是为了实现接口
	return nil
}

// convertToPolicyRule 将数据库规则转换为casbin策略规则
// 🔥 RBAC with Domains 模型规则格式：
// - 策略规则 (p): ptype, sub, domain, obj, act, eft
// - 角色继承 (g): ptype, user, domain, role
func (a *EntAdapter) convertToPolicyRule(rule types.CasbinRuleEntity) []string {
	var policyRule []string

	// 添加ptype
	policyRule = append(policyRule, rule.GetPtype())

	// 添加规则参数，跳过空值
	// 🔥 注意顺序：v0=sub/user, v1=domain, v2=obj/role, v3=act, v4=eft
	if v0 := rule.GetV0(); v0 != "" {
		policyRule = append(policyRule, v0)
	}
	if v1 := rule.GetV1(); v1 != "" {
		policyRule = append(policyRule, v1)
	}
	if v2 := rule.GetV2(); v2 != "" {
		policyRule = append(policyRule, v2)
	}
	if v3 := rule.GetV3(); v3 != "" {
		policyRule = append(policyRule, v3)
	}
	if v4 := rule.GetV4(); v4 != "" {
		policyRule = append(policyRule, v4)
	}
	if v5 := rule.GetV5(); v5 != "" {
		policyRule = append(policyRule, v5)
	}

	// 至少需要ptype和subject/user
	if len(policyRule) < 2 {
		return nil
	}

	return policyRule
}

// isRuleEffective 检查规则是否在有效期内
func (a *EntAdapter) isRuleEffective(rule types.CasbinRuleEntity) bool {
	now := time.Now()

	// 检查生效时间
	if rule.HasEffectiveFrom() {
		// 注意：这里简化处理，实际应该从rule获取effectiveFrom
		// 由于接口设计问题，这里暂时返回true
		// TODO: 在接口中添加GetEffectiveFrom/GetEffectiveTo方法
	}

	// 检查失效时间
	if rule.HasEffectiveTo() {
		// 同上
	}

	// 如果没有时间限制，或者在有效期内，返回true
	_ = now // 避免编译警告
	return true
}
