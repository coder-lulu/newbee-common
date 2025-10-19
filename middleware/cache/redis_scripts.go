// Copyright 2024 The NewBee Authors. All Rights Reserved.

package cache

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// HighPerformanceRedisClient 高性能Redis客户端包装器
type HighPerformanceRedisClient struct {
	client redis.UniversalClient
	
	// 预编译的Lua脚本
	rateLimitScript *redis.Script
	cacheGetSetScript *redis.Script
	batchGetScript *redis.Script
}

// NewHighPerformanceRedisClient 创建高性能Redis客户端
func NewHighPerformanceRedisClient(client redis.UniversalClient) *HighPerformanceRedisClient {
	hc := &HighPerformanceRedisClient{
		client: client,
	}
	
	// 预编译Lua脚本
	hc.rateLimitScript = redis.NewScript(rateLimitLuaScript)
	hc.cacheGetSetScript = redis.NewScript(cacheGetSetLuaScript)
	hc.batchGetScript = redis.NewScript(batchGetLuaScript)
	
	return hc
}

// RateLimitResult 限流结果
type RateLimitResult struct {
	Allowed   bool  `json:"allowed"`
	Remaining int   `json:"remaining"`
	ResetTime int64 `json:"reset_time"`
}

// SlidingWindowRateLimit 滑动窗口限流 - 使用Lua脚本原子化操作
func (c *HighPerformanceRedisClient) SlidingWindowRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error) {
	now := time.Now()
	windowStart := now.Add(-window)
	
	// 调用Lua脚本，一次性完成所有操作
	result, err := c.rateLimitScript.Run(ctx, c.client, []string{key}, 
		windowStart.UnixNano(), 
		limit, 
		now.UnixNano(), 
		int(window.Seconds())).Result()
	
	if err != nil {
		return nil, err
	}
	
	// 解析结果
	resultArray, ok := result.([]interface{})
	if !ok || len(resultArray) < 3 {
		return &RateLimitResult{Allowed: false}, nil
	}
	
	allowed, _ := resultArray[0].(int64)
	remaining, _ := resultArray[1].(int64)
	resetTime, _ := resultArray[2].(int64)
	
	return &RateLimitResult{
		Allowed:   allowed == 1,
		Remaining: int(remaining),
		ResetTime: resetTime,
	}, nil
}

// FastCacheGetSet 高效的缓存获取和设置 - 使用Lua脚本
func (c *HighPerformanceRedisClient) FastCacheGetSet(ctx context.Context, key string, value string, ttlSeconds int) (string, bool, error) {
	result, err := c.cacheGetSetScript.Run(ctx, c.client, []string{key}, value, ttlSeconds).Result()
	if err != nil {
		return "", false, err
	}
	
	if result == nil {
		return "", false, nil
	}
	
	return result.(string), true, nil
}

// BatchGet 批量获取 - 使用Pipeline优化
func (c *HighPerformanceRedisClient) BatchGet(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return make(map[string]string), nil
	}
	
	// 使用Pipeline进行批量操作
	pipe := c.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	
	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, key)
	}
	
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, err
	}
	
	result := make(map[string]string, len(keys))
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if err == nil {
			result[keys[i]] = val
		}
	}
	
	return result, nil
}

// BatchSetWithTTL 批量设置带TTL
func (c *HighPerformanceRedisClient) BatchSetWithTTL(ctx context.Context, data map[string]string, ttl time.Duration) error {
	if len(data) == 0 {
		return nil
	}
	
	pipe := c.client.Pipeline()
	
	for key, value := range data {
		pipe.Set(ctx, key, value, ttl)
	}
	
	_, err := pipe.Exec(ctx)
	return err
}

// Lua脚本定义

// 滑动窗口限流Lua脚本
const rateLimitLuaScript = `
local key = KEYS[1]
local window_start = ARGV[1]
local limit = tonumber(ARGV[2])
local now = ARGV[3]
local expire_seconds = tonumber(ARGV[4])

-- 删除窗口外的记录
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- 获取当前窗口内的请求数
local current = redis.call('ZCARD', key)

local allowed = 0
local remaining = limit - current
local reset_time = tonumber(now) + (expire_seconds * 1000000000)

if current < limit then
    -- 允许请求，添加到滑动窗口
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, expire_seconds * 2)
    allowed = 1
    remaining = remaining - 1
end

-- 返回结果: [allowed, remaining, reset_time]
return {allowed, remaining, reset_time}
`

// 缓存获取设置Lua脚本
const cacheGetSetLuaScript = `
local key = KEYS[1]
local new_value = ARGV[1]
local ttl = tonumber(ARGV[2])

-- 尝试获取当前值
local current_value = redis.call('GET', key)

if current_value then
    -- 如果存在，检查TTL
    local remaining_ttl = redis.call('TTL', key)
    if remaining_ttl > 0 then
        -- 未过期，返回当前值
        return current_value
    end
end

-- 不存在或已过期，设置新值
redis.call('SETEX', key, ttl, new_value)
return nil
`

// 批量获取Lua脚本
const batchGetLuaScript = `
local keys = KEYS
local result = {}

for i, key in ipairs(keys) do
    local value = redis.call('GET', key)
    if value then
        result[key] = value
    end
end

return result
`

// RedisMetrics Redis操作指标
type RedisMetrics struct {
	TotalOps    int64
	SuccessOps  int64
	FailedOps   int64
	AvgLatency  time.Duration
	CacheHits   int64
	CacheMisses int64
}

// GetMetrics 获取Redis操作指标
func (c *HighPerformanceRedisClient) GetMetrics() *RedisMetrics {
	// 简化实现，实际应该使用原子计数器
	return &RedisMetrics{
		TotalOps:   0,
		SuccessOps: 0,
		FailedOps:  0,
		AvgLatency: 0,
		CacheHits:  0,
		CacheMisses: 0,
	}
}

// DistributedLock 分布式锁实现
type DistributedLock struct {
	client redis.UniversalClient
	key    string
	token  string
	ttl    time.Duration
}

// NewDistributedLock 创建分布式锁
func (c *HighPerformanceRedisClient) NewDistributedLock(key string, ttl time.Duration) *DistributedLock {
	return &DistributedLock{
		client: c.client,
		key:    key,
		token:  strconv.FormatInt(time.Now().UnixNano(), 36),
		ttl:    ttl,
	}
}

// TryLock 尝试获取锁
func (l *DistributedLock) TryLock(ctx context.Context) (bool, error) {
	result, err := l.client.SetNX(ctx, l.key, l.token, l.ttl).Result()
	return result, err
}

// Unlock 释放锁
func (l *DistributedLock) Unlock(ctx context.Context) error {
	script := `
	if redis.call("GET", KEYS[1]) == ARGV[1] then
		return redis.call("DEL", KEYS[1])
	else
		return 0
	end
	`
	_, err := redis.NewScript(script).Run(ctx, l.client, []string{l.key}, l.token).Result()
	return err
}

// CircuitBreaker 熔断器模式
type CircuitBreaker struct {
	failureCount    int64
	successCount    int64
	failureThreshold int64
	resetTimeout     time.Duration
	lastFailureTime  time.Time
	state           string // "CLOSED", "OPEN", "HALF_OPEN"
}

// NewCircuitBreaker 创建熔断器
func NewCircuitBreaker(failureThreshold int64, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		state:            "CLOSED",
	}
}

// Call 通过熔断器执行操作
func (cb *CircuitBreaker) Call(fn func() error) error {
	if cb.state == "OPEN" {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = "HALF_OPEN"
		} else {
			return &CircuitBreakerError{Message: "Circuit breaker is OPEN"}
		}
	}
	
	err := fn()
	
	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
	
	return err
}

func (cb *CircuitBreaker) onFailure() {
	cb.failureCount++
	cb.lastFailureTime = time.Now()
	
	if cb.failureCount >= cb.failureThreshold {
		cb.state = "OPEN"
	}
}

func (cb *CircuitBreaker) onSuccess() {
	cb.successCount++
	if cb.state == "HALF_OPEN" {
		cb.state = "CLOSED"
		cb.failureCount = 0
	}
}

// CircuitBreakerError 熔断器错误
type CircuitBreakerError struct {
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}

// ConnectionPoolConfig 连接池配置
type ConnectionPoolConfig struct {
	MaxIdle     int
	MaxActive   int
	IdleTimeout time.Duration
	Wait        bool
}

// OptimizedRedisClient 进一步优化的Redis客户端
type OptimizedRedisClient struct {
	*HighPerformanceRedisClient
	circuitBreaker *CircuitBreaker
	metrics        *RedisMetrics
}

// NewOptimizedRedisClient 创建优化的Redis客户端
func NewOptimizedRedisClient(client redis.UniversalClient) *OptimizedRedisClient {
	return &OptimizedRedisClient{
		HighPerformanceRedisClient: NewHighPerformanceRedisClient(client),
		circuitBreaker:             NewCircuitBreaker(5, 30*time.Second),
		metrics:                    &RedisMetrics{},
	}
}

// Execute 带熔断器的Redis操作执行
func (c *OptimizedRedisClient) Execute(operation func() error) error {
	return c.circuitBreaker.Call(operation)
}

// HealthCheck Redis健康检查
func (c *OptimizedRedisClient) HealthCheck(ctx context.Context) error {
	return c.Execute(func() error {
		return c.client.Ping(ctx).Err()
	})
}

// Close 关闭高性能Redis客户端
func (c *HighPerformanceRedisClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Close 关闭优化的Redis客户端
func (c *OptimizedRedisClient) Close() error {
	return c.HighPerformanceRedisClient.Close()
}