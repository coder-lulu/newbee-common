// Copyright 2024 The NewBee Authors. All Rights Reserved.
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

import (
	"net/http"
)

// Middleware 中间件统一接口
type Middleware interface {
	// Handle 处理HTTP请求
	Handle(next http.HandlerFunc) http.HandlerFunc

	// Name 返回中间件名称
	Name() string

	// Priority 返回中间件优先级（数字越小优先级越高）
	Priority() int

	// IsEnabled 返回中间件是否启用
	IsEnabled() bool
}

// EnableableMiddleware 可启用/禁用的中间件接口
type EnableableMiddleware interface {
	Middleware

	// SetEnabled 设置中间件启用状态
	SetEnabled(enabled bool)
}

// MiddlewareFactory 中间件工厂接口
type MiddlewareFactory interface {
	// Create 创建中间件实例
	Create(config map[string]interface{}) (Middleware, error)

	// GetType 获取中间件类型
	GetType() string
}

// BaseMiddleware 基础中间件实现
type BaseMiddleware struct {
	name     string
	priority int
	enabled  bool
}

// NewBaseMiddleware 创建基础中间件
func NewBaseMiddleware(name string, priority int, enabled bool) *BaseMiddleware {
	return &BaseMiddleware{
		name:     name,
		priority: priority,
		enabled:  enabled,
	}
}

// Name 返回中间件名称
func (bm *BaseMiddleware) Name() string {
	return bm.name
}

// Priority 返回中间件优先级
func (bm *BaseMiddleware) Priority() int {
	return bm.priority
}

// IsEnabled 返回中间件是否启用
func (bm *BaseMiddleware) IsEnabled() bool {
	return bm.enabled
}

// SetEnabled 设置中间件启用状态
func (bm *BaseMiddleware) SetEnabled(enabled bool) {
	bm.enabled = enabled
}

// 中间件优先级常量
const (
	PriorityTenant     = 10 // 租户中间件
	PriorityAuth       = 20 // 认证中间件
	PriorityPermission = 30 // 权限中间件
	PriorityDataPerm   = 40 // 数据权限中间件
	PriorityAudit      = 50 // 审计中间件
	PriorityMonitoring = 60 // 监控中间件
	PriorityLogging    = 70 // 日志中间件
)

// 中间件类型常量
const (
	TypeAuth       = "auth"
	TypeAudit      = "audit"
	TypeDataPerm   = "dataperm"
	TypeTenant     = "tenant"
	TypeMonitoring = "monitoring"
	TypeSecurity   = "security"
	TypeCaching    = "caching"
)
