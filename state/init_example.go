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

package state

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ExampleInitializer 示例初始化器
type ExampleInitializer struct {
	redisClient redis.UniversalClient
	keyPrefix   string
	ttl         time.Duration
}

// NewExampleInitializer 创建示例初始化器
func NewExampleInitializer(redisClient redis.UniversalClient, keyPrefix string, ttl time.Duration) *ExampleInitializer {
	return &ExampleInitializer{
		redisClient: redisClient,
		keyPrefix:   keyPrefix,
		ttl:         ttl,
	}
}

// Initialize 初始化状态管理系统
func (ei *ExampleInitializer) Initialize(ctx context.Context) error {
	// 1. 初始化默认状态管理器
	InitializeDefaultStateManager(ei.redisClient, ei.keyPrefix, ei.ttl)

	// 2. 初始化状态适配器
	stateManager := GetDefaultStateManager()
	InitializeStateAdapter(stateManager)

	// 3. 初始化枚举兼容性
	adapter := GetDefaultStateAdapter()
	InitializeEnumCompat(adapter)

	// 4. 设置一些默认值
	if err := ei.setDefaultValues(ctx, stateManager); err != nil {
		return err
	}

	return nil
}

// setDefaultValues 设置默认值
func (ei *ExampleInitializer) setDefaultValues(ctx context.Context, stateManager *UnifiedStateManager) error {
	// 设置默认租户ID
	if err := stateManager.SetDefaultTenantID(ctx, 1); err != nil {
		return err
	}

	// 设置一些示例数据权限范围
	testUserID := "test_user"
	if err := stateManager.SetDataPermissionScope(ctx, testUserID, uint8(DataPermOwnDept)); err != nil {
		return err
	}

	// 设置示例用户部门
	if err := stateManager.SetUserDepartment(ctx, testUserID, 100); err != nil {
		return err
	}

	// 设置示例子部门
	if err := stateManager.SetSubDepartments(ctx, 100, []uint64{101, 102, 103}); err != nil {
		return err
	}

	return nil
}

// StateManagerUsageExample 状态管理器使用示例
func StateManagerUsageExample(ctx context.Context) error {
	// 获取状态管理器
	stateManager := GetDefaultStateManager()
	if stateManager == nil {
		return fmt.Errorf("state manager not initialized")
	}

	// 示例1: 基本状态操作
	if err := stateManager.SetState(ctx, "app:version", "1.0.0"); err != nil {
		return err
	}

	version, err := stateManager.GetState(ctx, "app:version")
	if err != nil {
		return err
	}
	println("App version:", version.(string))

	// 示例2: 数据权限操作
	userID := "user123"
	scope, err := stateManager.GetDataPermissionScope(ctx, userID)
	if err != nil {
		// 如果没有设置，使用默认值
		scope = uint8(DataPermOwn)
	}
	println("User data permission scope:", scope)

	// 示例3: 租户操作
	tenantID, err := stateManager.GetActiveTenantID(ctx, userID)
	if err != nil {
		return err
	}
	println("Active tenant ID:", tenantID)

	// 示例4: 批量操作
	states := map[string]interface{}{
		"feature:auth_enabled":     true,
		"feature:audit_enabled":    true,
		"feature:dataperm_enabled": true,
		"config:max_connections":   100,
		"config:timeout_seconds":   30,
	}

	if err := stateManager.SetStates(ctx, states); err != nil {
		return err
	}

	// 获取多个状态
	keys := []string{"feature:auth_enabled", "config:max_connections"}
	results, err := stateManager.GetStates(ctx, keys)
	if err != nil {
		return err
	}

	for key, value := range results {
		println(key, ":", value)
	}

	return nil
}

// BackwardCompatibilityExample 向后兼容性示例
func BackwardCompatibilityExample(ctx context.Context) error {
	// 使用适配器获取值（与原有API兼容）
	adapter := GetDefaultStateAdapter()
	if adapter == nil {
		return fmt.Errorf("state adapter not initialized")
	}

	// 获取默认租户ID（原来使用 entenum.TenantDefaultId）
	defaultTenantID := adapter.GetDefaultTenantID(ctx)
	println("Default tenant ID:", defaultTenantID)

	// 获取数据权限范围（原来使用硬编码常量）
	userID := "user456"
	scope := adapter.GetDataPermissionScope(ctx, userID)
	println("User data permission scope:", scope)

	// 获取用户部门（原来可能需要直接查询数据库）
	deptID := adapter.GetUserDepartment(ctx, userID)
	println("User department ID:", deptID)

	return nil
}

// StateObserverExample 状态观察者示例
type LoggingStateObserver struct {
	name string
}

func (lso *LoggingStateObserver) OnStateChanged(ctx context.Context, key string, oldValue, newValue interface{}) {
	println(lso.name, "- State changed:", key, "from", oldValue, "to", newValue)
}

func (lso *LoggingStateObserver) OnStateDeleted(ctx context.Context, key string, oldValue interface{}) {
	println(lso.name, "- State deleted:", key, "was", oldValue)
}

// ObserverUsageExample 观察者使用示例
func ObserverUsageExample(ctx context.Context) error {
	stateManager := GetDefaultStateManager()
	if stateManager == nil {
		return fmt.Errorf("state manager not initialized")
	}

	// 添加观察者
	observer := &LoggingStateObserver{name: "AuditObserver"}
	stateManager.AddObserver(observer)

	// 进行一些状态操作（会触发观察者）
	if err := stateManager.SetState(ctx, "user:login_count", 10); err != nil {
		return err
	}

	if err := stateManager.SetState(ctx, "user:login_count", 11); err != nil {
		return err
	}

	if err := stateManager.DeleteState(ctx, "user:login_count"); err != nil {
		return err
	}

	// 移除观察者
	stateManager.RemoveObserver(observer)

	return nil
}

// 便捷的初始化函数
func QuickInit(redisClient redis.UniversalClient) error {
	initializer := NewExampleInitializer(redisClient, "newbee:state", 24*time.Hour)
	return initializer.Initialize(context.Background())
}
