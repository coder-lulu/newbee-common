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
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// CacheConsistencyManager 缓存一致性管理器
type CacheConsistencyManager struct {
	l1Cache          *L1Cache
	redisPipelineOpt *RedisPipelineOptimizer

	// 一致性控制
	invalidationChannel chan string
	refreshChannel      chan string
	stopChannel         chan struct{}

	// 配置
	config *ConsistencyConfig

	// 状态跟踪
	isRunning      int32
	refreshingKeys sync.Map

	// 性能指标
	metrics *ConsistencyMetrics

	// 同步控制
	mu sync.RWMutex
	wg sync.WaitGroup
}

// ConsistencyConfig 一致性配置
type ConsistencyConfig struct {
	RefreshBatchSize       int           `json:"refresh_batch_size"`       // 刷新批大小
	RefreshInterval        time.Duration `json:"refresh_interval"`         // 刷新间隔
	InvalidationTimeout    time.Duration `json:"invalidation_timeout"`     // 失效超时
	MaxRefreshWorkers      int           `json:"max_refresh_workers"`      // 最大刷新工作协程
	EnableProactiveRefresh bool          `json:"enable_proactive_refresh"` // 启用主动刷新
	RefreshThreshold       float64       `json:"refresh_threshold"`        // 刷新阈值(TTL剩余百分比)
	EnableVersionControl   bool          `json:"enable_version_control"`   // 启用版本控制
}

// ConsistencyMetrics 一致性指标
type ConsistencyMetrics struct {
	// 失效统计
	TotalInvalidations   int64 `json:"total_invalidations"`
	SuccessInvalidations int64 `json:"success_invalidations"`
	FailedInvalidations  int64 `json:"failed_invalidations"`

	// 刷新统计
	TotalRefreshes   int64 `json:"total_refreshes"`
	SuccessRefreshes int64 `json:"success_refreshes"`
	FailedRefreshes  int64 `json:"failed_refreshes"`

	// 性能指标
	AvgRefreshTime      time.Duration `json:"avg_refresh_time"`
	AvgInvalidationTime time.Duration `json:"avg_invalidation_time"`

	// 状态指标
	ActiveRefreshes      int64     `json:"active_refreshes"`
	LastRefreshTime      time.Time `json:"last_refresh_time"`
	LastInvalidationTime time.Time `json:"last_invalidation_time"`
}

// CacheInvalidationEvent 缓存失效事件
type CacheInvalidationEvent struct {
	Key       string    `json:"key"`
	Reason    string    `json:"reason"` // "expired", "updated", "deleted", "manual"
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "redis", "local", "external"
}

// CacheRefreshResult 缓存刷新结果
type CacheRefreshResult struct {
	Key         string            `json:"key"`
	Success     bool              `json:"success"`
	NewValue    *PermissionResult `json:"new_value,omitempty"`
	Error       error             `json:"error,omitempty"`
	RefreshTime time.Duration     `json:"refresh_time"`
	Source      string            `json:"source"`
	Timestamp   time.Time         `json:"timestamp"`
}

// NewCacheConsistencyManager 创建缓存一致性管理器
func NewCacheConsistencyManager(
	l1Cache *L1Cache,
	redisPipelineOpt *RedisPipelineOptimizer,
	config *ConsistencyConfig,
) *CacheConsistencyManager {
	if config == nil {
		config = &ConsistencyConfig{
			RefreshBatchSize:       10,
			RefreshInterval:        time.Second * 30,
			InvalidationTimeout:    time.Second * 5,
			MaxRefreshWorkers:      5,
			EnableProactiveRefresh: true,
			RefreshThreshold:       0.2, // 当TTL剩余20%时刷新
			EnableVersionControl:   false,
		}
	}

	return &CacheConsistencyManager{
		l1Cache:             l1Cache,
		redisPipelineOpt:    redisPipelineOpt,
		config:              config,
		invalidationChannel: make(chan string, 1000),
		refreshChannel:      make(chan string, 1000),
		stopChannel:         make(chan struct{}),
		metrics:             &ConsistencyMetrics{},
	}
}

// Start 启动一致性管理器
func (ccm *CacheConsistencyManager) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&ccm.isRunning, 0, 1) {
		return nil // 已经在运行
	}

	// 启动失效处理协程
	ccm.wg.Add(1)
	go ccm.invalidationWorker(ctx)

	// 启动刷新工作协程
	for i := 0; i < ccm.config.MaxRefreshWorkers; i++ {
		ccm.wg.Add(1)
		go ccm.refreshWorker(ctx, i)
	}

	// 启动主动刷新协程
	if ccm.config.EnableProactiveRefresh {
		ccm.wg.Add(1)
		go ccm.proactiveRefreshWorker(ctx)
	}

	return nil
}

// Stop 停止一致性管理器
func (ccm *CacheConsistencyManager) Stop() error {
	if !atomic.CompareAndSwapInt32(&ccm.isRunning, 1, 0) {
		return nil // 已经停止
	}

	// 先关闭停止信号通道，让工作协程退出
	close(ccm.stopChannel)

	// 等待所有工作协程退出
	ccm.wg.Wait()

	// 安全地清空工作通道（此时已无协程写入）
	ccm.drainChannels()

	return nil
}

// drainChannels 安全地清空通道
func (ccm *CacheConsistencyManager) drainChannels() {
	// 清空invalidation通道中的剩余消息
	for {
		select {
		case <-ccm.invalidationChannel:
		default:
			goto drainRefresh
		}
	}

drainRefresh:
	// 清空refresh通道中的剩余消息
	for {
		select {
		case <-ccm.refreshChannel:
		default:
			return
		}
	}
}

// InvalidateKey 失效指定键
func (ccm *CacheConsistencyManager) InvalidateKey(key string, reason string) {
	select {
	case ccm.invalidationChannel <- key:
		atomic.AddInt64(&ccm.metrics.TotalInvalidations, 1)
	default:
		// 通道满，记录失败
		atomic.AddInt64(&ccm.metrics.FailedInvalidations, 1)
	}
}

// RefreshKey 刷新指定键
func (ccm *CacheConsistencyManager) RefreshKey(key string) {
	select {
	case ccm.refreshChannel <- key:
		atomic.AddInt64(&ccm.metrics.TotalRefreshes, 1)
	default:
		// 通道满，记录失败
		atomic.AddInt64(&ccm.metrics.FailedRefreshes, 1)
	}
}

// InvalidatePattern 失效匹配模式的键
func (ccm *CacheConsistencyManager) InvalidatePattern(pattern string) error {
	// 获取L1缓存中匹配的键
	matchedKeys := ccm.getMatchedKeys(pattern)

	for _, key := range matchedKeys {
		ccm.InvalidateKey(key, "pattern_match")
	}

	return nil
}

// GetWithConsistency 一致性获取缓存值
func (ccm *CacheConsistencyManager) GetWithConsistency(
	key string,
	loader func(string) (*PermissionResult, error),
) (*PermissionResult, error) {
	// 1. 尝试从L1缓存获取
	if value, found := ccm.l1Cache.Get(key); found {
		// 检查是否需要主动刷新
		if ccm.shouldProactiveRefresh(key) {
			go ccm.RefreshKey(key)
		}
		return value, nil
	}

	// 2. L1缓存未命中，从Redis加载
	if loader != nil {
		value, err := loader(key)
		if err != nil {
			return nil, err
		}

		// 3. 加载成功，写入L1缓存
		if value != nil {
			ccm.l1Cache.Set(key, value, ccm.l1Cache.config.DefaultTTL)
		}

		return value, nil
	}

	return nil, nil
}

// SetWithConsistency 一致性设置缓存值
func (ccm *CacheConsistencyManager) SetWithConsistency(
	key string,
	value *PermissionResult,
	ttl time.Duration,
) error {
	// 1. 设置L1缓存
	if err := ccm.l1Cache.Set(key, value, ttl); err != nil {
		return err
	}

	// 2. 通知其他实例失效（如果是分布式环境）
	// 这里可以集成Redis Pub/Sub或消息队列
	// ccm.publishInvalidationEvent(key, "updated")

	return nil
}

// invalidationWorker 失效处理工作协程
func (ccm *CacheConsistencyManager) invalidationWorker(ctx context.Context) {
	defer ccm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ccm.stopChannel:
			return
		case key := <-ccm.invalidationChannel:
			ccm.processInvalidation(key)
		}
	}
}

// refreshWorker 刷新工作协程
func (ccm *CacheConsistencyManager) refreshWorker(ctx context.Context, workerID int) {
	defer ccm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ccm.stopChannel:
			return
		case key := <-ccm.refreshChannel:
			ccm.processRefresh(key)
		}
	}
}

// proactiveRefreshWorker 主动刷新工作协程
func (ccm *CacheConsistencyManager) proactiveRefreshWorker(ctx context.Context) {
	defer ccm.wg.Done()

	ticker := time.NewTicker(ccm.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ccm.stopChannel:
			return
		case <-ticker.C:
			ccm.scanAndRefresh()
		}
	}
}

// processInvalidation 处理失效
func (ccm *CacheConsistencyManager) processInvalidation(key string) {
	startTime := time.Now()

	// 从L1缓存删除
	deleted := ccm.l1Cache.Delete(key)

	// 更新指标
	if deleted {
		atomic.AddInt64(&ccm.metrics.SuccessInvalidations, 1)
	} else {
		atomic.AddInt64(&ccm.metrics.FailedInvalidations, 1)
	}

	// 更新平均处理时间
	ccm.updateInvalidationTime(time.Since(startTime))
	ccm.metrics.LastInvalidationTime = time.Now()
}

// processRefresh 处理刷新
func (ccm *CacheConsistencyManager) processRefresh(key string) {
	startTime := time.Now()

	// 检查是否已经在刷新中
	if _, exists := ccm.refreshingKeys.LoadOrStore(key, true); exists {
		return // 已经在刷新中
	}
	defer ccm.refreshingKeys.Delete(key)

	atomic.AddInt64(&ccm.metrics.ActiveRefreshes, 1)
	defer atomic.AddInt64(&ccm.metrics.ActiveRefreshes, -1)

	// 从Redis获取最新数据
	result := ccm.refreshFromRedis(key)

	// 更新L1缓存
	if result.Success && result.NewValue != nil {
		ccm.l1Cache.Set(key, result.NewValue, ccm.l1Cache.config.DefaultTTL)
		atomic.AddInt64(&ccm.metrics.SuccessRefreshes, 1)
	} else {
		atomic.AddInt64(&ccm.metrics.FailedRefreshes, 1)
	}

	// 更新指标
	ccm.updateRefreshTime(time.Since(startTime))
	ccm.metrics.LastRefreshTime = time.Now()
}

// refreshFromRedis 从Redis刷新数据
func (ccm *CacheConsistencyManager) refreshFromRedis(key string) *CacheRefreshResult {
	result := &CacheRefreshResult{
		Key:       key,
		Timestamp: time.Now(),
		Source:    "redis",
	}

	// 使用Pipeline获取数据
	batchResult, err := ccm.redisPipelineOpt.BatchGetPermissions(
		context.Background(),
		[]string{key},
	)

	if err != nil {
		result.Error = err
		return result
	}

	if value, exists := batchResult.Results[key]; exists {
		result.Success = true
		result.NewValue = value
	}

	return result
}

// scanAndRefresh 扫描并刷新即将过期的缓存
func (ccm *CacheConsistencyManager) scanAndRefresh() {
	// 这里需要遍历L1缓存中的条目
	// 检查TTL剩余时间，如果低于阈值则加入刷新队列

	// 获取需要刷新的键列表
	keysToRefresh := ccm.getKeysNeedingRefresh()

	// 批量提交刷新任务
	for _, key := range keysToRefresh {
		select {
		case ccm.refreshChannel <- key:
		default:
			// 通道满，跳过此次刷新
			break
		}
	}
}

// shouldProactiveRefresh 检查是否应该主动刷新
func (ccm *CacheConsistencyManager) shouldProactiveRefresh(key string) bool {
	if !ccm.config.EnableProactiveRefresh {
		return false
	}

	// 通过L1缓存接口检查TTL剩余时间
	return ccm.checkKeyTTLThreshold(key)
}

// checkKeyTTLThreshold 检查键的TTL是否低于阈值
func (ccm *CacheConsistencyManager) checkKeyTTLThreshold(key string) bool {
	// 这需要L1缓存提供TTL检查接口
	// 暂时使用简化的实现
	ttlInfo := ccm.l1Cache.GetKeyTTLInfo(key)
	if ttlInfo == nil {
		return false
	}

	// 如果剩余TTL小于阈值，则需要刷新
	remainingRatio := float64(ttlInfo.RemainingTTL) / float64(ttlInfo.OriginalTTL)
	return remainingRatio < ccm.config.RefreshThreshold
}

// getKeysNeedingRefresh 获取需要刷新的键列表
func (ccm *CacheConsistencyManager) getKeysNeedingRefresh() []string {
	// 获取需要刷新的键列表
	keysToRefresh := ccm.l1Cache.GetKeysForRefresh(ccm.config.RefreshThreshold)

	// 限制批次大小避免过载
	maxBatch := ccm.config.RefreshBatchSize
	if len(keysToRefresh) > maxBatch {
		keysToRefresh = keysToRefresh[:maxBatch]
	}

	return keysToRefresh
}

// getMatchedKeys 获取匹配模式的键
func (ccm *CacheConsistencyManager) getMatchedKeys(pattern string) []string {
	// 简化实现：遍历L1缓存中的所有键
	// 实际实现需要支持通配符匹配
	return []string{}
}

// updateInvalidationTime 更新失效处理时间
func (ccm *CacheConsistencyManager) updateInvalidationTime(duration time.Duration) {
	// 使用移动平均更新平均时间
	currentAvg := ccm.metrics.AvgInvalidationTime
	newAvg := time.Duration((int64(currentAvg) + int64(duration)) / 2)
	ccm.metrics.AvgInvalidationTime = newAvg
}

// updateRefreshTime 更新刷新处理时间
func (ccm *CacheConsistencyManager) updateRefreshTime(duration time.Duration) {
	// 使用移动平均更新平均时间
	currentAvg := ccm.metrics.AvgRefreshTime
	newAvg := time.Duration((int64(currentAvg) + int64(duration)) / 2)
	ccm.metrics.AvgRefreshTime = newAvg
}

// GetMetrics 获取一致性指标
func (ccm *CacheConsistencyManager) GetMetrics() *ConsistencyMetrics {
	return &ConsistencyMetrics{
		TotalInvalidations:   atomic.LoadInt64(&ccm.metrics.TotalInvalidations),
		SuccessInvalidations: atomic.LoadInt64(&ccm.metrics.SuccessInvalidations),
		FailedInvalidations:  atomic.LoadInt64(&ccm.metrics.FailedInvalidations),
		TotalRefreshes:       atomic.LoadInt64(&ccm.metrics.TotalRefreshes),
		SuccessRefreshes:     atomic.LoadInt64(&ccm.metrics.SuccessRefreshes),
		FailedRefreshes:      atomic.LoadInt64(&ccm.metrics.FailedRefreshes),
		AvgRefreshTime:       ccm.metrics.AvgRefreshTime,
		AvgInvalidationTime:  ccm.metrics.AvgInvalidationTime,
		ActiveRefreshes:      atomic.LoadInt64(&ccm.metrics.ActiveRefreshes),
		LastRefreshTime:      ccm.metrics.LastRefreshTime,
		LastInvalidationTime: ccm.metrics.LastInvalidationTime,
	}
}

// PublishInvalidationEvent 发布失效事件（用于分布式环境）
func (ccm *CacheConsistencyManager) PublishInvalidationEvent(event *CacheInvalidationEvent) error {
	// 序列化事件
	eventData, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// 发布到Redis Pub/Sub或消息队列
	// 这里需要集成具体的消息传递机制
	_ = eventData

	return nil
}

// SubscribeInvalidationEvents 订阅失效事件（用于分布式环境）
func (ccm *CacheConsistencyManager) SubscribeInvalidationEvents(ctx context.Context) error {
	// 订阅Redis Pub/Sub或消息队列
	// 接收到事件后调用InvalidateKey进行本地失效
	return nil
}

// BatchInvalidate 批量失效
func (ccm *CacheConsistencyManager) BatchInvalidate(keys []string, reason string) {
	for _, key := range keys {
		ccm.InvalidateKey(key, reason)
	}
}

// BatchRefresh 批量刷新
func (ccm *CacheConsistencyManager) BatchRefresh(keys []string) {
	for _, key := range keys {
		ccm.RefreshKey(key)
	}
}

// Stop 停止一致性管理器 - 修复P0 goroutine泄漏问题
func (ccm *CacheConsistencyManager) Stop() error {
	// 停止运行状态
	if !atomic.CompareAndSwapInt32(&ccm.isRunning, 1, 0) {
		return nil // 已经停止
	}

	// 1. 首先关闭停止通道，通知所有工作协程退出
	close(ccm.stopChannel)

	// 2. 等待所有工作协程完成
	ccm.wg.Wait()

	// 3. 安全地清空工作通道避免阻塞
	ccm.drainChannels()

	logx.Info("Cache consistency manager stopped safely")
	return nil
}

// drainChannels 安全清空通道
func (ccm *CacheConsistencyManager) drainChannels() {
	// 非阻塞地清空失效通道
	for {
		select {
		case <-ccm.invalidationChannel:
		default:
			goto drainRefresh
		}
	}

drainRefresh:
	// 非阻塞地清空刷新通道
	for {
		select {
		case <-ccm.refreshChannel:
		default:
			return
		}
	}
}
