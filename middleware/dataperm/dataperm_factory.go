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

package dataperm

import (
	"fmt"
	"net/http"
	"github.com/coder-lulu/newbee-common/middleware/types"
)

// DataPermMiddlewareFactory 数据权限中间件工厂
type DataPermMiddlewareFactory struct{}

// NewDataPermMiddlewareFactory 创建数据权限中间件工厂
func NewDataPermMiddlewareFactory() types.MiddlewareFactory {
	return &DataPermMiddlewareFactory{}
}

// Create 创建数据权限中间件实例
func (f *DataPermMiddlewareFactory) Create(config map[string]interface{}) (types.Middleware, error) {
	// 解析配置
	dataPermConfig, err := parseDataPermConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dataperm config: %w", err)
	}
	
	// 创建数据权限中间件
	return NewSimpleDataPermMiddleware(dataPermConfig), nil
}

// GetType 获取中间件类型
func (f *DataPermMiddlewareFactory) GetType() string {
	return types.TypeDataPerm
}

// DataPermConfig 数据权限配置
type DataPermConfig struct {
	// 是否启用
	Enabled bool `json:"enabled"`
	
	// 部门字段名
	DepartmentField string `json:"department_field"`
	
	// 用户字段名
	UserField string `json:"user_field"`
	
	// 是否跳过系统上下文
	SkipSystemContext bool `json:"skip_system_context"`
	
	// 缓存配置
	CacheEnabled bool `json:"cache_enabled"`
	CacheTTL     int  `json:"cache_ttl"`
}

// parseDataPermConfig 解析数据权限配置
func parseDataPermConfig(config map[string]interface{}) (*DataPermConfig, error) {
	dataPermConfig := &DataPermConfig{
		Enabled:           true,
		DepartmentField:   "department_id",
		UserField:         "created_by",
		SkipSystemContext: true,
		CacheEnabled:      true,
		CacheTTL:          300, // 5分钟
	}
	
	if enabled, ok := config["enabled"].(bool); ok {
		dataPermConfig.Enabled = enabled
	}
	
	if deptField, ok := config["department_field"].(string); ok {
		dataPermConfig.DepartmentField = deptField
	}
	
	if userField, ok := config["user_field"].(string); ok {
		dataPermConfig.UserField = userField
	}
	
	if skipSystem, ok := config["skip_system_context"].(bool); ok {
		dataPermConfig.SkipSystemContext = skipSystem
	}
	
	if cacheEnabled, ok := config["cache_enabled"].(bool); ok {
		dataPermConfig.CacheEnabled = cacheEnabled
	}
	
	if cacheTTL, ok := config["cache_ttl"].(int); ok {
		dataPermConfig.CacheTTL = cacheTTL
	}
	
	return dataPermConfig, nil
}

// NewSimpleDataPermMiddleware 创建简单数据权限中间件（工厂模式）
func NewSimpleDataPermMiddleware(config *DataPermConfig) types.Middleware {
	base := types.NewBaseMiddleware("dataperm", types.PriorityDataPerm, config.Enabled)
	return &simpleDataPermMiddleware{
		BaseMiddleware: base,
		config:         config,
	}
}

// simpleDataPermMiddleware 简单数据权限中间件实现
type simpleDataPermMiddleware struct {
	*types.BaseMiddleware
	config *DataPermConfig
}

// Handle 处理HTTP请求
func (m *simpleDataPermMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 检查是否启用
		if !m.IsEnabled() {
			next(w, r)
			return
		}
		
		// 这里应该实现实际的数据权限逻辑
		// 暂时直接调用下一个处理器
		next(w, r)
	}
}