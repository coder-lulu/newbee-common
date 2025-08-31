// Copyright 2024 Newbee Team. All Rights Reserved.
//
// Redis Batch Client for High-Performance DataPerm Middleware
// Provides Redis Pipeline batch operations to reduce network round trips

package middleware

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/logx"
)

// BatchRedisClient Redis批量客户端
type BatchRedisClient struct {
	client       redis.UniversalClient
	batchSize    int
	batchTimeout time.Duration

	// 批量操作队列
	batchMutex    sync.Mutex
	batchRequests []*BatchRequest
	batchTimer    *time.Timer

	// 性能统计
	totalRequests   int64
	batchedRequests int64
	totalBatches    int64
	avgBatchSize    float64

	// 配置项
	maxBatchSize  int
	enableMetrics bool
}

// BatchRequest 批量请求
type BatchRequest struct {
	Key        string
	ResultChan chan BatchResult
	Timestamp  time.Time
}

// BatchResult 批量结果
type BatchResult struct {
	Value string
	Error error
	Found bool
}

// NewBatchRedisClient 创建批量Redis客户端
func NewBatchRedisClient(client redis.UniversalClient, batchSize int, batchTimeout time.Duration) *BatchRedisClient {
	if batchSize <= 0 {
		batchSize = 100 // 默认批量大小
	}
	if batchTimeout <= 0 {
		batchTimeout = 10 * time.Millisecond // 默认批量超时
	}

	brc := &BatchRedisClient{
		client:        client,
		batchSize:     batchSize,
		batchTimeout:  batchTimeout,
		maxBatchSize:  batchSize * 2, // 最大批量大小
		enableMetrics: true,
	}

	logx.Infow("Batch Redis client initialized",
		logx.Field("batchSize", batchSize),
		logx.Field("batchTimeout", batchTimeout))

	return brc
}

// GetBatch 批量获取Redis值
func (brc *BatchRedisClient) GetBatch(ctx context.Context, key string) (string, error) {
	atomic.AddInt64(&brc.totalRequests, 1)

	// 创建批量请求
	request := &BatchRequest{
		Key:        key,
		ResultChan: make(chan BatchResult, 1),
		Timestamp:  time.Now(),
	}

	// 添加到批量队列
	brc.addToBatch(request)

	// 等待结果
	select {
	case result := <-request.ResultChan:
		if result.Error != nil {
			return "", result.Error
		}
		if !result.Found {
			return "", redis.Nil
		}
		return result.Value, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// addToBatch 添加请求到批量队列
func (brc *BatchRedisClient) addToBatch(request *BatchRequest) {
	brc.batchMutex.Lock()
	defer brc.batchMutex.Unlock()

	brc.batchRequests = append(brc.batchRequests, request)

	// 检查是否需要立即执行批量操作
	if len(brc.batchRequests) >= brc.batchSize {
		brc.executeBatch()
		return
	}

	// 设置超时定时器
	if brc.batchTimer == nil {
		brc.batchTimer = time.AfterFunc(brc.batchTimeout, func() {
			brc.batchMutex.Lock()
			defer brc.batchMutex.Unlock()

			if len(brc.batchRequests) > 0 {
				brc.executeBatch()
			}
		})
	}
}

// executeBatch 执行批量操作
func (brc *BatchRedisClient) executeBatch() {
	if len(brc.batchRequests) == 0 {
		return
	}

	// 停止定时器
	if brc.batchTimer != nil {
		brc.batchTimer.Stop()
		brc.batchTimer = nil
	}

	requests := brc.batchRequests
	brc.batchRequests = nil

	// 更新统计
	atomic.AddInt64(&brc.batchedRequests, int64(len(requests)))
	atomic.AddInt64(&brc.totalBatches, 1)

	// 计算平均批量大小
	totalBatches := atomic.LoadInt64(&brc.totalBatches)
	totalBatchedRequests := atomic.LoadInt64(&brc.batchedRequests)
	brc.avgBatchSize = float64(totalBatchedRequests) / float64(totalBatches)

	// 异步执行批量操作
	go brc.performBatchOperation(requests)
}

// performBatchOperation 执行批量Redis操作
func (brc *BatchRedisClient) performBatchOperation(requests []*BatchRequest) {
	if len(requests) == 0 {
		return
	}

	startTime := time.Now()

	// 创建Pipeline
	pipe := brc.client.Pipeline()

	// 收集所有键
	keys := make([]string, len(requests))
	cmds := make([]*redis.StringCmd, len(requests))

	for i, req := range requests {
		keys[i] = req.Key
		cmds[i] = pipe.Get(context.Background(), req.Key)
	}

	// 执行Pipeline
	_, err := pipe.Exec(context.Background())

	duration := time.Since(startTime)

	// 处理结果
	for i, req := range requests {
		var result BatchResult

		if err != nil {
			result.Error = err
		} else {
			value, cmdErr := cmds[i].Result()
			if cmdErr != nil {
				if cmdErr == redis.Nil {
					result.Found = false
				} else {
					result.Error = cmdErr
				}
			} else {
				result.Value = value
				result.Found = true
			}
		}

		// 发送结果
		select {
		case req.ResultChan <- result:
		default:
			// Channel可能已关闭，忽略
		}
		close(req.ResultChan)
	}

	if brc.enableMetrics {
		logx.Debugw("Batch operation completed",
			logx.Field("batchSize", len(requests)),
			logx.Field("duration", duration),
			logx.Field("avgDuration", duration/time.Duration(len(requests))))
	}
}

// GetMultiple 批量获取多个键的值
func (brc *BatchRedisClient) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return make(map[string]string), nil
	}

	// 防止请求过大，限制批量大小
	const maxBatchSize = 1000
	if len(keys) > maxBatchSize {
		return nil, fmt.Errorf("batch size %d exceeds maximum allowed %d", len(keys), maxBatchSize)
	}

	// 使用Pipeline批量获取
	pipe := brc.client.Pipeline()
	cmds := make(map[string]*redis.StringCmd, len(keys))

	for _, key := range keys {
		if len(key) > 250 { // Redis键长度限制
			return nil, fmt.Errorf("key too long: %d bytes", len(key))
		}
		cmds[key] = pipe.Get(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, err
	}

	// 收集结果
	results := make(map[string]string, len(keys))
	for key, cmd := range cmds {
		value, cmdErr := cmd.Result()
		if cmdErr == nil {
			results[key] = value
		}
		// 忽略redis.Nil错误，表示键不存在
	}

	return results, nil
}

// SetMultiple 批量设置多个键值对
func (brc *BatchRedisClient) SetMultiple(ctx context.Context, keyValues map[string]string, expiration time.Duration) error {
	if len(keyValues) == 0 {
		return nil
	}

	// 使用Pipeline批量设置
	pipe := brc.client.Pipeline()

	for key, value := range keyValues {
		if expiration > 0 {
			pipe.Set(ctx, key, value, expiration)
		} else {
			pipe.Set(ctx, key, value, 0)
		}
	}

	_, err := pipe.Exec(ctx)
	return err
}

// DeleteMultiple 批量删除多个键
func (brc *BatchRedisClient) DeleteMultiple(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	// 使用Pipeline批量删除
	pipe := brc.client.Pipeline()

	for _, key := range keys {
		pipe.Del(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// ExistsMultiple 批量检查键是否存在
func (brc *BatchRedisClient) ExistsMultiple(ctx context.Context, keys []string) (map[string]bool, error) {
	if len(keys) == 0 {
		return make(map[string]bool), nil
	}

	// 使用Pipeline批量检查
	pipe := brc.client.Pipeline()
	cmds := make(map[string]*redis.IntCmd, len(keys))

	for _, key := range keys {
		cmds[key] = pipe.Exists(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	// 收集结果
	results := make(map[string]bool, len(keys))
	for key, cmd := range cmds {
		exists, cmdErr := cmd.Result()
		if cmdErr == nil {
			results[key] = exists > 0
		} else {
			results[key] = false
		}
	}

	return results, nil
}

// GetStats 获取批量客户端统计信息
func (brc *BatchRedisClient) GetStats() map[string]interface{} {
	totalRequests := atomic.LoadInt64(&brc.totalRequests)
	batchedRequests := atomic.LoadInt64(&brc.batchedRequests)
	totalBatches := atomic.LoadInt64(&brc.totalBatches)

	batchEfficiency := float64(0)
	if totalRequests > 0 {
		batchEfficiency = float64(batchedRequests) / float64(totalRequests) * 100
	}

	return map[string]interface{}{
		"total_requests":     totalRequests,
		"batched_requests":   batchedRequests,
		"total_batches":      totalBatches,
		"avg_batch_size":     brc.avgBatchSize,
		"batch_efficiency":   batchEfficiency,
		"current_batch_size": brc.batchSize,
		"batch_timeout":      brc.batchTimeout,
	}
}

// Close 关闭批量客户端
func (brc *BatchRedisClient) Close() {
	brc.batchMutex.Lock()
	defer brc.batchMutex.Unlock()

	// 执行剩余的批量请求
	if len(brc.batchRequests) > 0 {
		brc.executeBatch()
	}

	// 停止定时器
	if brc.batchTimer != nil {
		brc.batchTimer.Stop()
		brc.batchTimer = nil
	}

	logx.Info("Batch Redis client closed")
}

// SetBatchSize 动态设置批量大小
func (brc *BatchRedisClient) SetBatchSize(size int) {
	if size > 0 && size <= brc.maxBatchSize {
		brc.batchMutex.Lock()
		brc.batchSize = size
		brc.batchMutex.Unlock()

		logx.Infow("Batch size updated", logx.Field("newBatchSize", size))
	}
}

// SetBatchTimeout 动态设置批量超时
func (brc *BatchRedisClient) SetBatchTimeout(timeout time.Duration) {
	if timeout > 0 {
		brc.batchMutex.Lock()
		brc.batchTimeout = timeout
		brc.batchMutex.Unlock()

		logx.Infow("Batch timeout updated", logx.Field("newBatchTimeout", timeout))
	}
}
