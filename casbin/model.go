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

package casbin

// GetDefaultRBACWithDomainsModel 返回默认的RBAC with Domains模型配置
// 🔥 该模型支持多租户场景，通过domain参数实现租户隔离
//
// 模型说明：
// - request_definition: r = sub, dom, obj, act
//   - sub: 主体（用户ID或角色ID）
//   - dom: 域（租户ID，用于多租户隔离）
//   - obj: 对象（资源路径，如/api/user/list）
//   - act: 动作（如POST, GET, DELETE等）
//
// - policy_definition: p = sub, dom, obj, act, eft
//   - eft: 效果（allow/deny）
//
// - role_definition: g = _, _, _
//   - g(user, domain, role): 用户在某个域中拥有某个角色
//
// - policy_effect: some(allow) && !some(deny)
//   - 只要有一个allow且没有deny，则允许
//
// - matchers: 匹配规则
//   - g(r.sub, r.dom, p.sub): 检查用户是否有某个角色
//   - r.sub == p.sub: 检查是否是直接授权
//   - r.dom == p.dom: 确保在同一租户内
//   - keyMatch2(r.obj, p.obj): 支持通配符匹配（如/api/user/*）
//   - keyMatch2(r.act, p.act): 支持动作通配符（如POST|GET）
func GetDefaultRBACWithDomainsModel() string {
	return `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act, eft

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (g(r.sub, r.dom, p.sub) || (r.sub == p.sub)) && r.dom == p.dom && keyMatch2(r.obj, p.obj) && keyMatch2(r.act, p.act)
`
}
