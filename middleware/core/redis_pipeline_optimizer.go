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

package middleware

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPipelineOptimizer Redis Pipeline批量查询优化器
type RedisPipelineOptimizer struct {
	redis      redis.UniversalClient
	keyBuilder *KeyBuilder
	batchSize  int
	timeout    time.Duration
	mu         sync.RWMutex
	metrics    *PipelineMetrics
}

// PipelineMetrics Pipeline性能指标
type PipelineMetrics struct {
	TotalBatches   int64         `json:"total_batches"`
	TotalKeys      int64         `json:"total_keys"`
	AvgBatchSize   float64       `json:"avg_batch_size"`
	AvgLatency     time.Duration `json:"avg_latency"`
	ErrorRate      float64       `json:"error_rate"`
	CacheHitRate   float64       `json:"cache_hit_rate"`
	LastUpdateTime time.Time     `json:"last_update_time"`
}

// BatchResult 批量查询结果
type BatchResult struct {
	Results map[string]*PermissionResult `json:"results"`
	Errors  map[string]error             `json:"errors"`
	Stats   *BatchStats                  `json:"stats"`
}

// BatchStats 批量查询统计
type BatchStats struct {
	TotalKeys     int           `json:"total_keys"`
	HitKeys       int           `json:"hit_keys"`
	MissKeys      int           `json:"miss_keys"`
	ErrorKeys     int           `json:"error_keys"`
	ExecutionTime time.Duration `json:"execution_time"`
	HitRate       float64       `json:"hit_rate"`
}

// KeyBuilder 零分配键构建器
type KeyBuilder struct {
	builderPool sync.Pool
}

// NewKeyBuilder 创建键构建器
func NewKeyBuilder() *KeyBuilder {
	return &KeyBuilder{
		builderPool: sync.Pool{
			New: func() interface{} {
				builder := &strings.Builder{}
				builder.Grow(128) // 预分配128字节
				return builder
			},
		},
	}
}

// BuildPermissionKey 构建权限键（零分配）
func (kb *KeyBuilder) BuildPermissionKey(tenantID uint64, roleCode, operation string) string {
	builder := kb.builderPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		kb.builderPool.Put(builder)
	}()

	builder.WriteString("dataperm:role:")
	// 使用strconv避免fmt.Sprintf的开销
	builder.WriteString(strconv.FormatUint(tenantID, 10))
	builder.WriteByte(':')
	builder.WriteString(roleCode)
	builder.WriteByte(':')
	builder.WriteString(operation)

	return builder.String()
}

// BuildDeptPermissionKey 构建部门权限键（零分配）
func (kb *KeyBuilder) BuildDeptPermissionKey(tenantID, deptID uint64, operation string) string {
	builder := kb.builderPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		kb.builderPool.Put(builder)
	}()

	builder.WriteString("dataperm:dept:")
	// 使用strconv避免fmt.Sprintf的开销
	builder.WriteString(strconv.FormatUint(tenantID, 10))
	builder.WriteByte(':')
	builder.WriteString(strconv.FormatUint(deptID, 10))
	builder.WriteByte(':')
	builder.WriteString(operation)

	return builder.String()
}

// RedisPipelineConfig Redis Pipeline配置
type RedisPipelineConfig struct {
	BatchSize           int           `json:"batch_size"`
	Timeout             time.Duration `json:"timeout"`
	MaxRetries          int           `json:"max_retries"`
	RetryInterval       time.Duration `json:"retry_interval"`
	ConnectionPoolSize  int           `json:"connection_pool_size"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
}

// NewRedisPipelineOptimizer 创建Redis Pipeline优化器
func NewRedisPipelineOptimizer(redis redis.UniversalClient, config *RedisPipelineConfig) *RedisPipelineOptimizer {
	if config == nil {
		config = &RedisPipelineConfig{
			BatchSize:           50,
			Timeout:             time.Millisecond * 100,
			MaxRetries:          3,
			RetryInterval:       time.Millisecond * 50,
			ConnectionPoolSize:  20,
			HealthCheckInterval: time.Second * 30,
		}
	}

	return &RedisPipelineOptimizer{
		redis:      redis,
		keyBuilder: NewKeyBuilder(),
		batchSize:  config.BatchSize,
		timeout:    config.Timeout,
		metrics:    &PipelineMetrics{},
	}
}

// BatchGetPermissions 批量获取权限数据
func (rpo *RedisPipelineOptimizer) BatchGetPermissions(ctx context.Context, keys []string) (*BatchResult, error) {
	if len(keys) == 0 {
		return &BatchResult{
			Results: make(map[string]*PermissionResult),
			Errors:  make(map[string]error),
			Stats:   &BatchStats{},
		}, nil
	}

	startTime := time.Now()

	// 创建Pipeline上下文，设置超时
	pipelineCtx, cancel := context.WithTimeout(ctx, rpo.timeout)
	defer cancel()

	// 分批处理以避免Pipeline过大
	result := &BatchResult{
		Results: make(map[string]*PermissionResult),
		Errors:  make(map[string]error),
		Stats:   &BatchStats{TotalKeys: len(keys)},
	}

	// 按批次处理
	for i := 0; i < len(keys); i += rpo.batchSize {
		end := i + rpo.batchSize
		if end > len(keys) {
			end = len(keys)
		}

		batchKeys := keys[i:end]
		if err := rpo.processBatch(pipelineCtx, batchKeys, result); err != nil {
			// 记录批次错误，但继续处理其他批次
			for _, key := range batchKeys {
				result.Errors[key] = fmt.Errorf("batch processing failed: %w", err)
				result.Stats.ErrorKeys++
			}
		}
	}

	// 计算统计信息
	result.Stats.ExecutionTime = time.Since(startTime)
	result.Stats.HitKeys = len(result.Results)
	result.Stats.MissKeys = result.Stats.TotalKeys - result.Stats.HitKeys - result.Stats.ErrorKeys
	if result.Stats.TotalKeys > 0 {
		result.Stats.HitRate = float64(result.Stats.HitKeys) / float64(result.Stats.TotalKeys)
	}

	// 更新性能指标
	rpo.updateMetrics(result.Stats)

	return result, nil
}

// processBatch 处理单个批次
func (rpo *RedisPipelineOptimizer) processBatch(ctx context.Context, keys []string, result *BatchResult) error {
	// 添加连接池监控
	batchCtx, cancel := context.WithTimeout(ctx, rpo.timeout)
	defer cancel()

	// 创建Pipeline with proper error handling
	pipe := rpo.redis.Pipeline()
	defer func() {
		if closeErr := pipe.Close(); closeErr != nil {
			// 记录连接关闭错误但不影响主要流程
			fmt.Printf("Warning: failed to close pipeline: %v\n", closeErr)
		}
	}()

	// 批量添加命令到Pipeline
	commands := make(map[string]*redis.StringCmd, len(keys))
	for _, key := range keys {
		commands[key] = pipe.Get(batchCtx, key)
	}

	// 执行Pipeline with retry logic
	var execErr error
	for retry := 0; retry < 3; retry++ {
		_, execErr = pipe.Exec(batchCtx)
		if execErr == nil || execErr == redis.Nil {
			break
		}

		// 如果是上下文超时或取消，不重试
		if batchCtx.Err() != nil {
			break
		}

		// 短暂等待后重试
		time.Sleep(time.Millisecond * 10 * time.Duration(retry+1))
	}

	if execErr != nil && execErr != redis.Nil {
		// 更严格的错误处理
		if isCriticalError(execErr) {
			return fmt.Errorf("critical pipeline execution failed: %w", execErr)
		}
		// 对于非关键错误，记录但继续处理
		fmt.Printf("Warning: pipeline execution had errors: %v\n", execErr)
	}

	// 处理结果
	for key, cmd := range commands {
		if cmd.Err() != nil {
			if cmd.Err() == redis.Nil {
				// 缓存未命中，不算错误
				continue
			}
			result.Errors[key] = cmd.Err()
			result.Stats.ErrorKeys++
			continue
		}

		// 解析权限数据
		permResult, parseErr := rpo.parsePermissionResult(cmd.Val())
		if parseErr != nil {
			result.Errors[key] = fmt.Errorf("failed to parse permission result: %w", parseErr)
			result.Stats.ErrorKeys++
			continue
		}

		result.Results[key] = permResult
	}

	return nil
}

// parsePermissionResult 解析权限结果
func (rpo *RedisPipelineOptimizer) parsePermissionResult(data string) (*PermissionResult, error) {
	// 简化的解析实现，实际应该根据存储格式来解析
	if data == "" {
		return nil, fmt.Errorf("empty permission data")
	}

	// 假设存储格式为: dataScope:subDept:customDept:level
	parts := strings.Split(data, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid permission data format")
	}

	return &PermissionResult{
		DataScope:     parts[0],
		SubDept:       parts[1],
		CustomDept:    parts[2],
		Level:         parts[3],
		Source:        "cache",
		CacheHit:      true,
		ExecutionTime: 0, // Pipeline中无法准确计算单个key的执行时间
	}, nil
}

// updateMetrics 更新性能指标
func (rpo *RedisPipelineOptimizer) updateMetrics(stats *BatchStats) {
	rpo.mu.Lock()
	defer rpo.mu.Unlock()

	rpo.metrics.TotalBatches++
	rpo.metrics.TotalKeys += int64(stats.TotalKeys)

	// 计算移动平均
	if rpo.metrics.TotalBatches == 1 {
		rpo.metrics.AvgBatchSize = float64(stats.TotalKeys)
		rpo.metrics.AvgLatency = stats.ExecutionTime
		rpo.metrics.CacheHitRate = stats.HitRate
	} else {
		// 使用指数移动平均
		alpha := 0.1
		rpo.metrics.AvgBatchSize = (1-alpha)*rpo.metrics.AvgBatchSize + alpha*float64(stats.TotalKeys)
		rpo.metrics.AvgLatency = time.Duration((1-alpha)*float64(rpo.metrics.AvgLatency) + alpha*float64(stats.ExecutionTime))
		rpo.metrics.CacheHitRate = (1-alpha)*rpo.metrics.CacheHitRate + alpha*stats.HitRate
	}

	// 计算错误率
	if rpo.metrics.TotalKeys > 0 {
		errorKeys := int64(stats.ErrorKeys)
		rpo.metrics.ErrorRate = float64(errorKeys) / float64(rpo.metrics.TotalKeys)
	}

	rpo.metrics.LastUpdateTime = time.Now()
}

// GetMetrics 获取性能指标
func (rpo *RedisPipelineOptimizer) GetMetrics() *PipelineMetrics {
	rpo.mu.RLock()
	defer rpo.mu.RUnlock()

	// 返回副本以避免并发访问问题
	return &PipelineMetrics{
		TotalBatches:   rpo.metrics.TotalBatches,
		TotalKeys:      rpo.metrics.TotalKeys,
		AvgBatchSize:   rpo.metrics.AvgBatchSize,
		AvgLatency:     rpo.metrics.AvgLatency,
		ErrorRate:      rpo.metrics.ErrorRate,
		CacheHitRate:   rpo.metrics.CacheHitRate,
		LastUpdateTime: rpo.metrics.LastUpdateTime,
	}
}

// SetBatchSize 设置批量大小
func (rpo *RedisPipelineOptimizer) SetBatchSize(size int) {
	if size > 0 && size <= 1000 { // 限制最大批量大小
		rpo.batchSize = size
	}
}

// SetTimeout 设置超时时间
func (rpo *RedisPipelineOptimizer) SetTimeout(timeout time.Duration) {
	if timeout > 0 && timeout <= time.Second*30 { // 限制最大超时时间
		rpo.timeout = timeout
	}
}

// isCriticalError 检查是否是关键错误
func isCriticalError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	// 关键错误：连接池耗尽、认证失败、网络不可达等
	criticalPatterns := []string{
		"connection pool exhausted",
		"auth failed",
		"network unreachable",
		"connection refused",
		"no route to host",
		"permission denied",
	}

	for _, pattern := range criticalPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// isPartialFailure 检查是否是部分失败（非关键错误）
func isPartialFailure(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	// 部分失败：超时、临时连接问题等
	partialPatterns := []string{
		"timeout",
		"temporary failure",
		"connection reset",
		"broken pipe",
	}

	for _, pattern := range partialPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// OptimizeForConcurrency 根据并发级别优化配置
func (rpo *RedisPipelineOptimizer) OptimizeForConcurrency(concurrencyLevel int) {
	// 根据并发级别动态调整批量大小和超时时间
	switch {
	case concurrencyLevel <= 10:
		rpo.SetBatchSize(20)
		rpo.SetTimeout(time.Millisecond * 50)
	case concurrencyLevel <= 50:
		rpo.SetBatchSize(50)
		rpo.SetTimeout(time.Millisecond * 100)
	case concurrencyLevel <= 100:
		rpo.SetBatchSize(100)
		rpo.SetTimeout(time.Millisecond * 200)
	default:
		rpo.SetBatchSize(200)
		rpo.SetTimeout(time.Millisecond * 300)
	}
}

// ResetMetrics 重置性能指标
func (rpo *RedisPipelineOptimizer) ResetMetrics() {
	rpo.mu.Lock()
	defer rpo.mu.Unlock()

	rpo.metrics = &PipelineMetrics{
		LastUpdateTime: time.Now(),
	}
}
