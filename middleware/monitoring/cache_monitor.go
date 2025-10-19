// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/cache"
)

// 缓存监控器
type CacheMonitor struct {
	config    *MonitoringConfig
	collector MetricCollector
	
	// 被监控的缓存
	monitoredCaches map[string]*MonitoredCache
	cacheMutex      sync.RWMutex
	
	// 定时收集器
	ticker     *time.Ticker
	stopChan   chan struct{}
}

// 被监控的缓存
type MonitoredCache struct {
	name        string
	cacheType   string
	cache       interface{} // 可以是任何类型的缓存
	metrics     *CacheMetrics
	lastChecked time.Time
}

// 创建缓存监控器
func NewCacheMonitor(config *MonitoringConfig, collector MetricCollector) *CacheMonitor {
	return &CacheMonitor{
		config:          config,
		collector:       collector,
		monitoredCaches: make(map[string]*MonitoredCache),
		stopChan:        make(chan struct{}),
	}
}

// 启动缓存监控
func (cm *CacheMonitor) Start(ctx context.Context) error {
	cm.ticker = time.NewTicker(cm.config.CollectionInterval)
	
	go func() {
		for {
			select {
			case <-cm.ticker.C:
				cm.collectAllMetrics()
			case <-cm.stopChan:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	
	return nil
}

// 停止缓存监控
func (cm *CacheMonitor) Stop() error {
	if cm.ticker != nil {
		cm.ticker.Stop()
	}
	close(cm.stopChan)
	return nil
}

// 包装分片缓存
func (cm *CacheMonitor) WrapShardedCache(cache interface{}, name string) interface{} {
	monitoredCache := &MonitoredCache{
		name:      name,
		cacheType: "sharded",
		cache:     cache,
		metrics: &CacheMetrics{
			CacheName:   name,
			CacheType:   "sharded",
			LastUpdate:  time.Now(),
		},
		lastChecked: time.Now(),
	}
	
	cm.cacheMutex.Lock()
	cm.monitoredCaches[name] = monitoredCache
	cm.cacheMutex.Unlock()
	
	// 返回包装后的缓存 (简化实现，实际使用时需要类型断言)
	return cache // 暂时直接返回原缓存
}

// 包装JWT缓存
func (cm *CacheMonitor) WrapJWTCache(jwtCache *cache.HighPerformanceJWTCache, name string) *cache.HighPerformanceJWTCache {
	monitoredCache := &MonitoredCache{
		name:      name,
		cacheType: "jwt",
		cache:     jwtCache,
		metrics: &CacheMetrics{
			CacheName:   name,
			CacheType:   "jwt",
			LastUpdate:  time.Now(),
		},
		lastChecked: time.Now(),
	}
	
	cm.cacheMutex.Lock()
	cm.monitoredCaches[name] = monitoredCache
	cm.cacheMutex.Unlock()
	
	// 返回包装后的缓存 (简化实现)
	return jwtCache // 暂时直接返回原缓存
}

// 包装Redis缓存
func (cm *CacheMonitor) WrapRedisCache(redisCache *cache.HighPerformanceRedisClient, name string) *cache.HighPerformanceRedisClient {
	monitoredCache := &MonitoredCache{
		name:      name,
		cacheType: "redis",
		cache:     redisCache,
		metrics: &CacheMetrics{
			CacheName:   name,
			CacheType:   "redis",
			LastUpdate:  time.Now(),
		},
		lastChecked: time.Now(),
	}
	
	cm.cacheMutex.Lock()
	cm.monitoredCaches[name] = monitoredCache
	cm.cacheMutex.Unlock()
	
	return redisCache // Redis客户端暂时直接返回，后续可以添加包装
}

// 注：由于Go泛型的限制，分片缓存的包装暂时简化处理
// 在实际使用中，可以通过接口注入的方式来实现监控

// 被监控的JWT缓存
type MonitoredJWTCache struct {
	wrapped *cache.HighPerformanceJWTCache
	monitor *CacheMonitor
	name    string
}

func (mjc *MonitoredJWTCache) Get(token string) (map[string]interface{}, bool) {
	start := time.Now()
	claims, found := mjc.wrapped.Get(token)
	duration := time.Since(start)
	
	// 记录指标
	mjc.monitor.recordCacheOperation(mjc.name, "get", duration, found)
	
	return claims, found
}

func (mjc *MonitoredJWTCache) Set(token string, claims map[string]interface{}, expiresAt time.Time) bool {
	start := time.Now()
	success := mjc.wrapped.Set(token, claims, expiresAt)
	duration := time.Since(start)
	
	// 记录指标
	mjc.monitor.recordCacheOperation(mjc.name, "set", duration, success)
	
	return success
}

func (mjc *MonitoredJWTCache) Delete(token string) bool {
	start := time.Now()
	deleted := mjc.wrapped.Delete(token)
	duration := time.Since(start)
	
	// 记录指标
	mjc.monitor.recordCacheOperation(mjc.name, "delete", duration, deleted)
	
	return deleted
}

func (mjc *MonitoredJWTCache) Size() int64 {
	return mjc.wrapped.Size()
}

func (mjc *MonitoredJWTCache) HitRate() float64 {
	return mjc.wrapped.HitRate()
}

func (mjc *MonitoredJWTCache) Stats() cache.JWTCacheStats {
	return mjc.wrapped.Stats()
}

func (mjc *MonitoredJWTCache) Cleanup() int {
	start := time.Now()
	cleaned := mjc.wrapped.Cleanup()
	duration := time.Since(start)
	
	// 记录清理指标
	mjc.monitor.recordCacheCleanup(mjc.name, cleaned, duration)
	
	return cleaned
}

func (mjc *MonitoredJWTCache) StartCleanupWorker(interval time.Duration, stopCh <-chan struct{}) {
	mjc.wrapped.StartCleanupWorker(interval, stopCh)
}

func (mjc *MonitoredJWTCache) WarmUp(tokens []string, claimsFunc func(string) (map[string]interface{}, time.Time, error)) {
	mjc.wrapped.WarmUp(tokens, claimsFunc)
}

// 记录缓存操作指标
func (cm *CacheMonitor) recordCacheOperation(cacheName, operation string, duration time.Duration, success bool) {
	labels := map[string]string{
		"cache":     cacheName,
		"operation": operation,
		"success":   "true",
	}
	
	if !success {
		labels["success"] = "false"
	}
	
	// 更新指标收集器
	cm.collector.IncrementCounter("cache_operations_total", labels, 1)
	cm.collector.RecordHistogram("cache_operation_duration_seconds", labels, duration)
	
	// 更新缓存指标
	cm.cacheMutex.RLock()
	monitoredCache, exists := cm.monitoredCaches[cacheName]
	cm.cacheMutex.RUnlock()
	
	if !exists {
		return
	}
	
	switch operation {
	case "get":
		monitoredCache.metrics.GetCount++
		if success {
			monitoredCache.metrics.HitCount++
		} else {
			monitoredCache.metrics.MissCount++
		}
		monitoredCache.metrics.AvgGetLatency = cm.updateAverageLatency(monitoredCache.metrics.AvgGetLatency, duration, monitoredCache.metrics.GetCount)
		
	case "set":
		monitoredCache.metrics.SetCount++
		monitoredCache.metrics.AvgSetLatency = cm.updateAverageLatency(monitoredCache.metrics.AvgSetLatency, duration, monitoredCache.metrics.SetCount)
		
	case "delete":
		monitoredCache.metrics.DeleteCount++
		monitoredCache.metrics.AvgDeleteLatency = cm.updateAverageLatency(monitoredCache.metrics.AvgDeleteLatency, duration, monitoredCache.metrics.DeleteCount)
	}
	
	// 更新命中率
	totalOps := monitoredCache.metrics.HitCount + monitoredCache.metrics.MissCount
	if totalOps > 0 {
		monitoredCache.metrics.HitRate = float64(monitoredCache.metrics.HitCount) / float64(totalOps)
	}
	
	monitoredCache.metrics.LastUpdate = time.Now()
}

// 记录缓存清理指标
func (cm *CacheMonitor) recordCacheCleanup(cacheName string, cleanedCount int, duration time.Duration) {
	labels := map[string]string{
		"cache": cacheName,
	}
	
	cm.collector.IncrementCounter("cache_cleanups_total", labels, 1)
	cm.collector.SetGauge("cache_cleaned_items", labels, float64(cleanedCount))
	cm.collector.RecordHistogram("cache_cleanup_duration_seconds", labels, duration)
	
	// 更新缓存指标
	cm.cacheMutex.RLock()
	monitoredCache, exists := cm.monitoredCaches[cacheName]
	cm.cacheMutex.RUnlock()
	
	if exists {
		monitoredCache.metrics.CleanupCount++
		monitoredCache.metrics.LastUpdate = time.Now()
	}
}

// 收集所有缓存指标
func (cm *CacheMonitor) collectAllMetrics() {
	cm.cacheMutex.RLock()
	caches := make([]*MonitoredCache, 0, len(cm.monitoredCaches))
	for _, cache := range cm.monitoredCaches {
		caches = append(caches, cache)
	}
	cm.cacheMutex.RUnlock()
	
	for _, monitoredCache := range caches {
		cm.collectCacheMetrics(monitoredCache)
	}
}

// 收集单个缓存指标
func (cm *CacheMonitor) collectCacheMetrics(monitoredCache *MonitoredCache) {
	labels := map[string]string{
		"cache": monitoredCache.name,
		"type":  monitoredCache.cacheType,
	}
	
	switch monitoredCache.cacheType {
	case "sharded":
		// 简化的分片缓存指标收集（需要根据具体实现调整）
		cm.collector.SetGauge("cache_size", labels, float64(monitoredCache.metrics.CurrentSize))
		cm.collector.SetGauge("cache_hit_rate", labels, monitoredCache.metrics.HitRate)
		
	case "jwt":
		if jwtCache, ok := monitoredCache.cache.(*cache.HighPerformanceJWTCache); ok {
			stats := jwtCache.Stats()
			
			cm.collector.SetGauge("cache_size", labels, float64(stats.CurrentSize))
			cm.collector.SetGauge("cache_max_size", labels, float64(stats.MaxSize))
			cm.collector.SetGauge("cache_hit_rate", labels, stats.HitRate)
			cm.collector.SetGauge("cache_size_utilization", labels, stats.SizeUtilization)
			
			// 更新内部指标
			monitoredCache.metrics.CurrentSize = stats.CurrentSize
			monitoredCache.metrics.MaxSize = stats.MaxSize
			monitoredCache.metrics.HitRate = stats.HitRate
			monitoredCache.metrics.SizeUsage = stats.SizeUtilization
		}
		
	case "redis":
		// Redis缓存指标收集
		if redisClient, ok := monitoredCache.cache.(*cache.HighPerformanceRedisClient); ok {
			redisMetrics := redisClient.GetMetrics()
			
			cm.collector.SetGauge("cache_total_operations", labels, float64(redisMetrics.TotalOps))
			cm.collector.SetGauge("cache_success_operations", labels, float64(redisMetrics.SuccessOps))
			cm.collector.SetGauge("cache_failed_operations", labels, float64(redisMetrics.FailedOps))
			cm.collector.SetGauge("cache_hit_count", labels, float64(redisMetrics.CacheHits))
			cm.collector.SetGauge("cache_miss_count", labels, float64(redisMetrics.CacheMisses))
		}
	}
	
	monitoredCache.lastChecked = time.Now()
}

// 获取缓存指标
func (cm *CacheMonitor) GetCacheMetrics(cacheName string) *CacheMetrics {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()
	
	monitoredCache, exists := cm.monitoredCaches[cacheName]
	if !exists {
		return nil
	}
	
	// 返回副本
	metricsCopy := *monitoredCache.metrics
	return &metricsCopy
}

// 获取所有缓存指标
func (cm *CacheMonitor) GetAllCacheMetrics() map[string]*CacheMetrics {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()
	
	result := make(map[string]*CacheMetrics, len(cm.monitoredCaches))
	for name, monitoredCache := range cm.monitoredCaches {
		metricsCopy := *monitoredCache.metrics
		result[name] = &metricsCopy
	}
	return result
}

// 检查缓存健康状态
func (cm *CacheMonitor) CheckCacheHealth(cacheName string) *ComponentHealth {
	metrics := cm.GetCacheMetrics(cacheName)
	if metrics == nil {
		return &ComponentHealth{
			Name:         cacheName,
			Status:       HealthStatusUnknown,
			LastCheck:    time.Now(),
			ErrorMessage: "Cache not found",
		}
	}
	
	health := &ComponentHealth{
		Name:      cacheName,
		LastCheck: time.Now(),
		Metadata: map[string]string{
			"cache_type": metrics.CacheType,
			"hit_rate":   fmt.Sprintf("%.2f", metrics.HitRate),
			"size":       fmt.Sprintf("%d", metrics.CurrentSize),
		},
	}
	
	// 检查命中率
	if metrics.HitRate < cm.config.CacheThresholds.LowHitRateCritical {
		health.Status = HealthStatusUnhealthy
		health.ErrorMessage = fmt.Sprintf("Hit rate %.2f%% below critical threshold %.2f%%", 
			metrics.HitRate*100, cm.config.CacheThresholds.LowHitRateCritical*100)
	} else if metrics.HitRate < cm.config.CacheThresholds.LowHitRateWarning {
		health.Status = HealthStatusDegraded
		health.ErrorMessage = fmt.Sprintf("Hit rate %.2f%% below warning threshold %.2f%%", 
			metrics.HitRate*100, cm.config.CacheThresholds.LowHitRateWarning*100)
	} else if metrics.SizeUsage > cm.config.CacheThresholds.HighMemoryCritical {
		health.Status = HealthStatusUnhealthy
		health.ErrorMessage = fmt.Sprintf("Memory usage %.2f%% above critical threshold %.2f%%", 
			metrics.SizeUsage*100, cm.config.CacheThresholds.HighMemoryCritical*100)
	} else if metrics.SizeUsage > cm.config.CacheThresholds.HighMemoryWarning {
		health.Status = HealthStatusDegraded
		health.ErrorMessage = fmt.Sprintf("Memory usage %.2f%% above warning threshold %.2f%%", 
			metrics.SizeUsage*100, cm.config.CacheThresholds.HighMemoryWarning*100)
	} else {
		health.Status = HealthStatusHealthy
	}
	
	return health
}

// 更新平均延迟
func (cm *CacheMonitor) updateAverageLatency(currentAvg time.Duration, newDuration time.Duration, count int64) time.Duration {
	if count <= 1 {
		return newDuration
	}
	
	// 使用移动平均算法
	weight := 1.0 / float64(count)
	if count > 100 {
		weight = 0.01 // 限制权重，避免老数据影响过大
	}
	
	return time.Duration(float64(currentAvg)*(1-weight) + float64(newDuration)*weight)
}