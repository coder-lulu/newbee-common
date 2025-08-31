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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStateManager Redis状态管理器实现
type RedisStateManager struct {
	client    redis.UniversalClient
	keyPrefix string
	ttl       time.Duration
}

// NewRedisStateManager 创建Redis状态管理器
func NewRedisStateManager(client redis.UniversalClient, keyPrefix string, ttl time.Duration) *RedisStateManager {
	return &RedisStateManager{
		client:    client,
		keyPrefix: keyPrefix,
		ttl:       ttl,
	}
}

// buildKey 构建Redis键
func (rsm *RedisStateManager) buildKey(key string) string {
	if rsm.keyPrefix == "" {
		return key
	}
	return rsm.keyPrefix + ":" + key
}

// GetState 获取状态
func (rsm *RedisStateManager) GetState(ctx context.Context, key string) (interface{}, error) {
	redisKey := rsm.buildKey(key)
	result, err := rsm.client.Get(ctx, redisKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("state %s not found", key)
		}
		return nil, fmt.Errorf("failed to get state %s: %w", key, err)
	}

	// 尝试解析JSON
	var value interface{}
	if err := json.Unmarshal([]byte(result), &value); err != nil {
		// 如果不是JSON，返回原始字符串
		return result, nil
	}

	return value, nil
}

// SetState 设置状态
func (rsm *RedisStateManager) SetState(ctx context.Context, key string, value interface{}) error {
	redisKey := rsm.buildKey(key)

	// 序列化值
	var data string
	switch v := value.(type) {
	case string:
		data = v
	case []byte:
		data = string(v)
	default:
		bytes, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal state %s: %w", key, err)
		}
		data = string(bytes)
	}

	err := rsm.client.Set(ctx, redisKey, data, rsm.ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set state %s: %w", key, err)
	}

	return nil
}

// DeleteState 删除状态
func (rsm *RedisStateManager) DeleteState(ctx context.Context, key string) error {
	redisKey := rsm.buildKey(key)
	err := rsm.client.Del(ctx, redisKey).Err()
	if err != nil {
		return fmt.Errorf("failed to delete state %s: %w", key, err)
	}

	return nil
}

// GetStates 批量获取状态
func (rsm *RedisStateManager) GetStates(ctx context.Context, keys []string) (map[string]interface{}, error) {
	if len(keys) == 0 {
		return make(map[string]interface{}), nil
	}

	redisKeys := make([]string, len(keys))
	for i, key := range keys {
		redisKeys[i] = rsm.buildKey(key)
	}

	results, err := rsm.client.MGet(ctx, redisKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get states: %w", err)
	}

	states := make(map[string]interface{})
	for i, result := range results {
		if result == nil {
			continue // 跳过不存在的键
		}

		originalKey := keys[i]
		resultStr := result.(string)

		// 尝试解析JSON
		var value interface{}
		if err := json.Unmarshal([]byte(resultStr), &value); err != nil {
			// 如果不是JSON，使用原始字符串
			value = resultStr
		}

		states[originalKey] = value
	}

	return states, nil
}

// SetStates 批量设置状态
func (rsm *RedisStateManager) SetStates(ctx context.Context, states map[string]interface{}) error {
	if len(states) == 0 {
		return nil
	}

	pipe := rsm.client.Pipeline()

	for key, value := range states {
		redisKey := rsm.buildKey(key)

		// 序列化值
		var data string
		switch v := value.(type) {
		case string:
			data = v
		case []byte:
			data = string(v)
		default:
			bytes, err := json.Marshal(value)
			if err != nil {
				return fmt.Errorf("failed to marshal state %s: %w", key, err)
			}
			data = string(bytes)
		}

		pipe.Set(ctx, redisKey, data, rsm.ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to set states: %w", err)
	}

	return nil
}

// ListStates 列出状态键
func (rsm *RedisStateManager) ListStates(ctx context.Context, prefix string) ([]string, error) {
	pattern := rsm.buildKey(prefix + "*")

	keys, err := rsm.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list states: %w", err)
	}

	// 移除键前缀
	result := make([]string, len(keys))
	for i, key := range keys {
		if rsm.keyPrefix != "" && strings.HasPrefix(key, rsm.keyPrefix+":") {
			result[i] = strings.TrimPrefix(key, rsm.keyPrefix+":")
		} else {
			result[i] = key
		}
	}

	return result, nil
}

// RedisDataPermissionStateManager Redis数据权限状态管理器
type RedisDataPermissionStateManager struct {
	*RedisStateManager
	keyGen *StateKeyGenerator
}

// NewRedisDataPermissionStateManager 创建Redis数据权限状态管理器
func NewRedisDataPermissionStateManager(client redis.UniversalClient, keyPrefix string, ttl time.Duration) *RedisDataPermissionStateManager {
	return &RedisDataPermissionStateManager{
		RedisStateManager: NewRedisStateManager(client, keyPrefix, ttl),
		keyGen:            NewStateKeyGenerator("dataperm"),
	}
}

// GetDataPermissionScope 获取数据权限范围
func (rdpsm *RedisDataPermissionStateManager) GetDataPermissionScope(ctx context.Context, userID string) (uint8, error) {
	key := rdpsm.keyGen.GenerateUserKey(userID, "scope")
	value, err := rdpsm.GetState(ctx, key)
	if err != nil {
		return uint8(DataPermOwn), nil // 默认最严格权限
	}

	switch v := value.(type) {
	case float64:
		return uint8(v), nil
	case int:
		return uint8(v), nil
	case string:
		scope, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return uint8(DataPermOwn), nil
		}
		return uint8(scope), nil
	default:
		return uint8(DataPermOwn), nil
	}
}

// SetDataPermissionScope 设置数据权限范围
func (rdpsm *RedisDataPermissionStateManager) SetDataPermissionScope(ctx context.Context, userID string, scope uint8) error {
	key := rdpsm.keyGen.GenerateUserKey(userID, "scope")
	return rdpsm.SetState(ctx, key, scope)
}

// GetCustomDepartments 获取自定义部门权限
func (rdpsm *RedisDataPermissionStateManager) GetCustomDepartments(ctx context.Context, userID string) ([]uint64, error) {
	key := rdpsm.keyGen.GenerateUserKey(userID, "custom_depts")
	value, err := rdpsm.GetState(ctx, key)
	if err != nil {
		return []uint64{}, nil
	}

	switch v := value.(type) {
	case []interface{}:
		depts := make([]uint64, len(v))
		for i, dept := range v {
			switch d := dept.(type) {
			case float64:
				depts[i] = uint64(d)
			case int:
				depts[i] = uint64(d)
			case string:
				id, err := strconv.ParseUint(d, 10, 64)
				if err != nil {
					continue
				}
				depts[i] = id
			}
		}
		return depts, nil
	default:
		return []uint64{}, nil
	}
}

// SetCustomDepartments 设置自定义部门权限
func (rdpsm *RedisDataPermissionStateManager) SetCustomDepartments(ctx context.Context, userID string, deptIDs []uint64) error {
	key := rdpsm.keyGen.GenerateUserKey(userID, "custom_depts")
	return rdpsm.SetState(ctx, key, deptIDs)
}

// GetSubDepartments 获取子部门权限
func (rdpsm *RedisDataPermissionStateManager) GetSubDepartments(ctx context.Context, deptID uint64) ([]uint64, error) {
	key := rdpsm.keyGen.GenerateDeptKey(strconv.FormatUint(deptID, 10), "sub_depts")
	value, err := rdpsm.GetState(ctx, key)
	if err != nil {
		return []uint64{}, nil
	}

	switch v := value.(type) {
	case []interface{}:
		depts := make([]uint64, len(v))
		for i, dept := range v {
			switch d := dept.(type) {
			case float64:
				depts[i] = uint64(d)
			case int:
				depts[i] = uint64(d)
			case string:
				id, err := strconv.ParseUint(d, 10, 64)
				if err != nil {
					continue
				}
				depts[i] = id
			}
		}
		return depts, nil
	default:
		return []uint64{}, nil
	}
}

// SetSubDepartments 设置子部门权限
func (rdpsm *RedisDataPermissionStateManager) SetSubDepartments(ctx context.Context, deptID uint64, subDeptIDs []uint64) error {
	key := rdpsm.keyGen.GenerateDeptKey(strconv.FormatUint(deptID, 10), "sub_depts")
	return rdpsm.SetState(ctx, key, subDeptIDs)
}

// GetUserDepartment 获取用户所属部门
func (rdpsm *RedisDataPermissionStateManager) GetUserDepartment(ctx context.Context, userID string) (uint64, error) {
	key := rdpsm.keyGen.GenerateUserKey(userID, "dept")
	value, err := rdpsm.GetState(ctx, key)
	if err != nil {
		return 0, err
	}

	switch v := value.(type) {
	case float64:
		return uint64(v), nil
	case int:
		return uint64(v), nil
	case string:
		deptID, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid department ID: %s", v)
		}
		return deptID, nil
	default:
		return 0, fmt.Errorf("invalid department ID type")
	}
}

// SetUserDepartment 设置用户所属部门
func (rdpsm *RedisDataPermissionStateManager) SetUserDepartment(ctx context.Context, userID string, deptID uint64) error {
	key := rdpsm.keyGen.GenerateUserKey(userID, "dept")
	return rdpsm.SetState(ctx, key, deptID)
}
