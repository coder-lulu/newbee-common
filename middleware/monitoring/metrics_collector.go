// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// 指标收集器接口
type MetricCollector interface {
	// 计数器操作
	IncrementCounter(name string, labels map[string]string, value int64)
	SetGauge(name string, labels map[string]string, value float64)
	RecordHistogram(name string, labels map[string]string, duration time.Duration)
	
	// 批量操作
	RecordBatch(metrics []MetricRecord)
	
	// 查询操作
	GetCounter(name string, labels map[string]string) int64
	GetGauge(name string, labels map[string]string) float64
	GetHistogram(name string, labels map[string]string) *HistogramData
	
	// 管理操作
	Start(ctx context.Context) error
	Stop() error
	GetMetrics() map[string]interface{}
}

// 指标记录
type MetricRecord struct {
	Type      MetricType        `json:"type"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	Value     interface{}       `json:"value"`
	Timestamp time.Time         `json:"timestamp"`
}

// 指标类型
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
)

// 直方图数据
type HistogramData struct {
	Count    int64         `json:"count"`
	Sum      float64       `json:"sum"`
	Mean     float64       `json:"mean"`
	P50      time.Duration `json:"p50"`
	P95      time.Duration `json:"p95"`
	P99      time.Duration `json:"p99"`
	Min      time.Duration `json:"min"`
	Max      time.Duration `json:"max"`
	Buckets  []Bucket      `json:"buckets"`
	LastUpdate time.Time   `json:"last_update"`
}

// 内存指标收集器
type MemoryMetricCollector struct {
	config    *MonitoringConfig
	mu        sync.RWMutex
	counters  map[string]*AtomicCounter
	gauges    map[string]*AtomicFloat64
	histograms map[string]*HistogramCollector
	
	// 采样相关
	sampler   *Sampler
	
	// 清理相关
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// 直方图收集器
type HistogramCollector struct {
	mu        sync.RWMutex
	samples   []time.Duration
	count     int64
	sum       float64
	min       time.Duration
	max       time.Duration
	lastUpdate time.Time
	
	// 预定义的分位数桶
	buckets   []Bucket
}

// 采样器
type Sampler struct {
	rate float64
	rand *rand.Rand
	mu   sync.Mutex
}

func NewSampler(rate float64) *Sampler {
	return &Sampler{
		rate: rate,
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *Sampler) ShouldSample() bool {
	if s.rate >= 1.0 {
		return true
	}
	if s.rate <= 0.0 {
		return false
	}
	
	s.mu.Lock()
	shouldSample := s.rand.Float64() < s.rate
	s.mu.Unlock()
	return shouldSample
}

// 创建内存指标收集器
func NewMemoryMetricCollector(config *MonitoringConfig) *MemoryMetricCollector {
	collector := &MemoryMetricCollector{
		config:     config,
		counters:   make(map[string]*AtomicCounter),
		gauges:     make(map[string]*AtomicFloat64),
		histograms: make(map[string]*HistogramCollector),
		sampler:    NewSampler(config.SamplingRate),
		stopCleanup: make(chan struct{}),
	}
	
	return collector
}

func (c *MemoryMetricCollector) Start(ctx context.Context) error {
	// 启动清理定时器
	c.cleanupTicker = time.NewTicker(c.config.CollectionInterval)
	
	go func() {
		for {
			select {
			case <-c.cleanupTicker.C:
				c.cleanupOldData()
			case <-c.stopCleanup:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	
	return nil
}

func (c *MemoryMetricCollector) Stop() error {
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}
	close(c.stopCleanup)
	return nil
}

func (c *MemoryMetricCollector) IncrementCounter(name string, labels map[string]string, value int64) {
	if !c.sampler.ShouldSample() {
		return
	}
	
	key := c.generateKey(name, labels)
	c.mu.RLock()
	counter, exists := c.counters[key]
	c.mu.RUnlock()
	
	if !exists {
		c.mu.Lock()
		// 双重检查
		if counter, exists = c.counters[key]; !exists {
			counter = &AtomicCounter{}
			c.counters[key] = counter
		}
		c.mu.Unlock()
	}
	
	counter.Add(value)
}

func (c *MemoryMetricCollector) SetGauge(name string, labels map[string]string, value float64) {
	if !c.sampler.ShouldSample() {
		return
	}
	
	key := c.generateKey(name, labels)
	c.mu.RLock()
	gauge, exists := c.gauges[key]
	c.mu.RUnlock()
	
	if !exists {
		c.mu.Lock()
		if gauge, exists = c.gauges[key]; !exists {
			gauge = &AtomicFloat64{}
			c.gauges[key] = gauge
		}
		c.mu.Unlock()
	}
	
	gauge.Set(value)
}

func (c *MemoryMetricCollector) RecordHistogram(name string, labels map[string]string, duration time.Duration) {
	if !c.sampler.ShouldSample() {
		return
	}
	
	key := c.generateKey(name, labels)
	c.mu.RLock()
	histogram, exists := c.histograms[key]
	c.mu.RUnlock()
	
	if !exists {
		c.mu.Lock()
		if histogram, exists = c.histograms[key]; !exists {
			histogram = NewHistogramCollector()
			c.histograms[key] = histogram
		}
		c.mu.Unlock()
	}
	
	histogram.Record(duration)
}

func (c *MemoryMetricCollector) RecordBatch(metrics []MetricRecord) {
	for _, metric := range metrics {
		switch metric.Type {
		case MetricTypeCounter:
			if value, ok := metric.Value.(int64); ok {
				c.IncrementCounter(metric.Name, metric.Labels, value)
			}
		case MetricTypeGauge:
			if value, ok := metric.Value.(float64); ok {
				c.SetGauge(metric.Name, metric.Labels, value)
			}
		case MetricTypeHistogram:
			if value, ok := metric.Value.(time.Duration); ok {
				c.RecordHistogram(metric.Name, metric.Labels, value)
			}
		}
	}
}

func (c *MemoryMetricCollector) GetCounter(name string, labels map[string]string) int64 {
	key := c.generateKey(name, labels)
	c.mu.RLock()
	counter, exists := c.counters[key]
	c.mu.RUnlock()
	
	if !exists {
		return 0
	}
	return counter.Get()
}

func (c *MemoryMetricCollector) GetGauge(name string, labels map[string]string) float64 {
	key := c.generateKey(name, labels)
	c.mu.RLock()
	gauge, exists := c.gauges[key]
	c.mu.RUnlock()
	
	if !exists {
		return 0
	}
	return gauge.Get()
}

func (c *MemoryMetricCollector) GetHistogram(name string, labels map[string]string) *HistogramData {
	key := c.generateKey(name, labels)
	c.mu.RLock()
	histogram, exists := c.histograms[key]
	c.mu.RUnlock()
	
	if !exists {
		return &HistogramData{}
	}
	return histogram.GetData()
}

func (c *MemoryMetricCollector) GetMetrics() map[string]interface{} {
	result := make(map[string]interface{})
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// 计数器
	counters := make(map[string]int64)
	for key, counter := range c.counters {
		counters[key] = counter.Get()
	}
	result["counters"] = counters
	
	// 仪表盘
	gauges := make(map[string]float64)
	for key, gauge := range c.gauges {
		gauges[key] = gauge.Get()
	}
	result["gauges"] = gauges
	
	// 直方图
	histograms := make(map[string]*HistogramData)
	for key, histogram := range c.histograms {
		histograms[key] = histogram.GetData()
	}
	result["histograms"] = histograms
	
	return result
}

func (c *MemoryMetricCollector) generateKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	
	// 创建确定性的键
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	key := name
	for _, k := range keys {
		key += fmt.Sprintf(",%s=%s", k, labels[k])
	}
	return key
}

func (c *MemoryMetricCollector) cleanupOldData() {
	now := time.Now()
	cutoff := now.Add(-c.config.RetentionPeriod)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// 清理直方图中的旧样本
	for _, histogram := range c.histograms {
		histogram.CleanupOldSamples(cutoff)
	}
}

// 直方图收集器实现
func NewHistogramCollector() *HistogramCollector {
	return &HistogramCollector{
		samples:    make([]time.Duration, 0, 1000), // 预分配1000个样本空间
		buckets:    createDefaultBuckets(),
		min:        time.Duration(0),
		max:        time.Duration(0),
		lastUpdate: time.Now(),
	}
}

func (h *HistogramCollector) Record(duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	h.count++
	h.sum += duration.Seconds()
	h.lastUpdate = time.Now()
	
	// 更新最小最大值
	if h.count == 1 || duration < h.min {
		h.min = duration
	}
	if duration > h.max {
		h.max = duration
	}
	
	// 保留最近的1000个样本用于分位数计算
	if len(h.samples) >= 1000 {
		// 移除最老的一半样本
		copy(h.samples, h.samples[500:])
		h.samples = h.samples[:500]
	}
	h.samples = append(h.samples, duration)
	
	// 更新桶计数
	for i := range h.buckets {
		if duration <= h.buckets[i].UpperBound {
			h.buckets[i].Count++
		}
	}
}

func (h *HistogramCollector) GetData() *HistogramData {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	if h.count == 0 {
		return &HistogramData{
			LastUpdate: h.lastUpdate,
		}
	}
	
	// 计算分位数
	sortedSamples := make([]time.Duration, len(h.samples))
	copy(sortedSamples, h.samples)
	sort.Slice(sortedSamples, func(i, j int) bool {
		return sortedSamples[i] < sortedSamples[j]
	})
	
	return &HistogramData{
		Count:      h.count,
		Sum:        h.sum,
		Mean:       h.sum / float64(h.count),
		P50:        calculatePercentile(sortedSamples, 0.50),
		P95:        calculatePercentile(sortedSamples, 0.95),
		P99:        calculatePercentile(sortedSamples, 0.99),
		Min:        h.min,
		Max:        h.max,
		Buckets:    h.buckets,
		LastUpdate: h.lastUpdate,
	}
}

func (h *HistogramCollector) CleanupOldSamples(cutoff time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	if h.lastUpdate.Before(cutoff) {
		// 如果最后更新时间早于截止时间，清空所有样本
		h.samples = h.samples[:0]
		h.count = 0
		h.sum = 0
		h.min = 0
		h.max = 0
		
		// 重置桶计数
		for i := range h.buckets {
			h.buckets[i].Count = 0
		}
	}
}

// 计算分位数
func calculatePercentile(sortedSamples []time.Duration, percentile float64) time.Duration {
	if len(sortedSamples) == 0 {
		return 0
	}
	
	index := percentile * float64(len(sortedSamples)-1)
	lower := int(index)
	upper := lower + 1
	
	if upper >= len(sortedSamples) {
		return sortedSamples[len(sortedSamples)-1]
	}
	
	if lower == upper {
		return sortedSamples[lower]
	}
	
	// 线性插值
	weight := index - float64(lower)
	return time.Duration(float64(sortedSamples[lower])*(1-weight) + float64(sortedSamples[upper])*weight)
}

// 创建默认的直方图桶
func createDefaultBuckets() []Bucket {
	return []Bucket{
		{UpperBound: 1 * time.Millisecond, Count: 0},
		{UpperBound: 5 * time.Millisecond, Count: 0},
		{UpperBound: 10 * time.Millisecond, Count: 0},
		{UpperBound: 25 * time.Millisecond, Count: 0},
		{UpperBound: 50 * time.Millisecond, Count: 0},
		{UpperBound: 100 * time.Millisecond, Count: 0},
		{UpperBound: 250 * time.Millisecond, Count: 0},
		{UpperBound: 500 * time.Millisecond, Count: 0},
		{UpperBound: 1 * time.Second, Count: 0},
		{UpperBound: 2 * time.Second, Count: 0},
		{UpperBound: 5 * time.Second, Count: 0},
		{UpperBound: 10 * time.Second, Count: 0},
	}
}