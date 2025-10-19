// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisClientAdapter Redis客户端适配器，将framework.CoreServices中的Redis适配为RedisClient接口
type RedisClientAdapter struct {
	client interface{} // 支持不同类型的Redis客户端
}

// Get 实现RedisClient接口的Get方法
func (r *RedisClientAdapter) Get(ctx context.Context, key string) *redis.StringCmd {
	// 尝试断言为不同类型的Redis客户端
	switch client := r.client.(type) {
	case redis.UniversalClient:
		return client.Get(ctx, key)
	case redis.Cmdable:
		// 对于Cmdable接口，需要创建StringCmd
		if universalClient, ok := client.(redis.UniversalClient); ok {
			return universalClient.Get(ctx, key)
		}
		// 如果无法转换，创建一个默认的失败命令
		cmd := redis.NewStringCmd(ctx, "get", key)
		cmd.SetErr(redis.Nil)
		return cmd
	default:
		// 如果类型不匹配，返回失败命令
		cmd := redis.NewStringCmd(ctx, "get", key)
		cmd.SetErr(redis.Nil)
		return cmd
	}
}

// Set 实现RedisClient接口的Set方法
func (r *RedisClientAdapter) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	// 尝试断言为不同类型的Redis客户端
	switch client := r.client.(type) {
	case redis.UniversalClient:
		return client.Set(ctx, key, value, expiration)
	case redis.Cmdable:
		// 对于Cmdable接口，需要创建StatusCmd
		if universalClient, ok := client.(redis.UniversalClient); ok {
			return universalClient.Set(ctx, key, value, expiration)
		}
		// 如果无法转换，创建一个默认的失败命令
		cmd := redis.NewStatusCmd(ctx, "set", key, value)
		cmd.SetErr(redis.Nil)
		return cmd
	default:
		// 如果类型不匹配，返回失败命令
		cmd := redis.NewStatusCmd(ctx, "set", key, value)
		cmd.SetErr(redis.Nil)
		return cmd
	}
}

// Del 实现RedisClient接口的Del方法
func (r *RedisClientAdapter) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	// 尝试断言为不同类型的Redis客户端
	switch client := r.client.(type) {
	case redis.UniversalClient:
		return client.Del(ctx, keys...)
	case redis.Cmdable:
		// 对于Cmdable接口，需要创建IntCmd
		if universalClient, ok := client.(redis.UniversalClient); ok {
			return universalClient.Del(ctx, keys...)
		}
		// 如果无法转换，创建一个默认的失败命令
		args := make([]interface{}, len(keys)+1)
		args[0] = "del"
		for i, key := range keys {
			args[i+1] = key
		}
		cmd := redis.NewIntCmd(ctx, args...)
		cmd.SetErr(redis.Nil)
		return cmd
	default:
		// 如果类型不匹配，返回失败命令
		args := make([]interface{}, len(keys)+1)
		args[0] = "del"
		for i, key := range keys {
			args[i+1] = key
		}
		cmd := redis.NewIntCmd(ctx, args...)
		cmd.SetErr(redis.Nil)
		return cmd
	}
}