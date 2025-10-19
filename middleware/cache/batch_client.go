// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Redis Batch Client for High-Performance Cache Operations
// Provides Redis Pipeline batch operations to reduce network round trips

package cache

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

	// 关闭信号
	ctx    context.Context
	cancel context.CancelFunc
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

	ctx, cancel := context.WithCancel(context.Background())

	brc := &BatchRedisClient{
		client:        client,
		batchSize:     batchSize,
		batchTimeout:  batchTimeout,
		maxBatchSize:  batchSize * 2, // 最大批量大小
		enableMetrics: true,
		ctx:           ctx,
		cancel:        cancel,
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
	case <-time.After(brc.batchTimeout * 10): // 超时保护
		return "", fmt.Errorf("batch request timeout")
	}
}

// addToBatch 添加请求到批量队列
func (brc *BatchRedisClient) addToBatch(request *BatchRequest) {
	brc.batchMutex.Lock()
	defer brc.batchMutex.Unlock()

	// 添加请求到队列
	brc.batchRequests = append(brc.batchRequests, request)

	// 检查是否需要立即执行
	shouldExecute := len(brc.batchRequests) >= brc.batchSize

	if shouldExecute {
		// 立即执行批量操作
		brc.executeBatch()
	} else if brc.batchTimer == nil {
		// 启动定时器
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

	// 获取当前批次的请求
	currentBatch := make([]*BatchRequest, len(brc.batchRequests))
	copy(currentBatch, brc.batchRequests)
	brc.batchRequests = brc.batchRequests[:0] // 清空队列

	// 取消定时器
	if brc.batchTimer != nil {
		brc.batchTimer.Stop()
		brc.batchTimer = nil
	}

	// 异步执行批量操作
	go brc.processBatch(currentBatch)
}

// processBatch 处理批量请求
func (brc *BatchRedisClient) processBatch(requests []*BatchRequest) {
	if len(requests) == 0 {
		return
	}

	atomic.AddInt64(&brc.totalBatches, 1)
	atomic.AddInt64(&brc.batchedRequests, int64(len(requests)))

	// 更新平均批量大小
	if brc.enableMetrics {
		totalBatches := atomic.LoadInt64(&brc.totalBatches)
		totalBatchedRequests := atomic.LoadInt64(&brc.batchedRequests)
		brc.avgBatchSize = float64(totalBatchedRequests) / float64(totalBatches)
	}

	// 创建pipeline
	ctx := context.Background()
	pipe := brc.client.Pipeline()

	// 添加所有GET命令到pipeline
	cmds := make([]*redis.StringCmd, len(requests))
	for i, request := range requests {
		cmds[i] = pipe.Get(ctx, request.Key)
	}

	// 执行pipeline
	start := time.Now()
	_, err := pipe.Exec(ctx)
	duration := time.Since(start)

	// 处理结果
	for i, request := range requests {
		cmd := cmds[i]
		result := BatchResult{}

		if err != nil {
			result.Error = err
		} else if cmd.Err() == redis.Nil {
			result.Found = false
		} else if cmd.Err() != nil {
			result.Error = cmd.Err()
		} else {
			result.Value = cmd.Val()
			result.Found = true
		}

		// 发送结果
		select {
		case request.ResultChan <- result:
		default:
			// Channel已关闭或满了
		}
	}

	// 记录性能指标
	if brc.enableMetrics {
		logx.Infow("Batch processed",
			logx.Field("batchSize", len(requests)),
			logx.Field("duration", duration),
			logx.Field("avgBatchSize", brc.avgBatchSize),
			logx.Field("error", err))
	}
}

// SetBatch 批量设置Redis值
func (brc *BatchRedisClient) SetBatch(ctx context.Context, keyValues map[string]interface{}, expiration time.Duration) error {
	if len(keyValues) == 0 {
		return nil
	}

	pipe := brc.client.Pipeline()

	for key, value := range keyValues {
		pipe.Set(ctx, key, value, expiration)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// DeleteBatch 批量删除Redis键
func (brc *BatchRedisClient) DeleteBatch(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	pipe := brc.client.Pipeline()

	for _, key := range keys {
		pipe.Del(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// ExistsBatch 批量检查键是否存在
func (brc *BatchRedisClient) ExistsBatch(ctx context.Context, keys []string) (map[string]bool, error) {
	if len(keys) == 0 {
		return make(map[string]bool), nil
	}

	pipe := brc.client.Pipeline()
	cmds := make([]*redis.IntCmd, len(keys))

	for i, key := range keys {
		cmds[i] = pipe.Exists(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool, len(keys))
	for i, key := range keys {
		result[key] = cmds[i].Val() > 0
	}

	return result, nil
}

// GetStats 获取批量客户端统计信息
func (brc *BatchRedisClient) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_requests":    atomic.LoadInt64(&brc.totalRequests),
		"batched_requests":  atomic.LoadInt64(&brc.batchedRequests),
		"total_batches":     atomic.LoadInt64(&brc.totalBatches),
		"avg_batch_size":    brc.avgBatchSize,
		"batch_size":        brc.batchSize,
		"batch_timeout_ms":  brc.batchTimeout.Milliseconds(),
		"max_batch_size":    brc.maxBatchSize,
	}
}

// Close 关闭批量客户端
func (brc *BatchRedisClient) Close() error {
	brc.cancel()

	// 处理剩余的批量请求
	brc.batchMutex.Lock()
	if len(brc.batchRequests) > 0 {
		brc.executeBatch()
	}
	brc.batchMutex.Unlock()

	logx.Info("Batch Redis client closed")
	return nil
}

// UpdateBatchConfig 更新批量配置
func (brc *BatchRedisClient) UpdateBatchConfig(batchSize int, batchTimeout time.Duration) {
	brc.batchMutex.Lock()
	defer brc.batchMutex.Unlock()

	if batchSize > 0 {
		brc.batchSize = batchSize
		brc.maxBatchSize = batchSize * 2
	}

	if batchTimeout > 0 {
		brc.batchTimeout = batchTimeout
	}

	logx.Infow("Batch config updated",
		logx.Field("batchSize", brc.batchSize),
		logx.Field("batchTimeout", brc.batchTimeout))
}