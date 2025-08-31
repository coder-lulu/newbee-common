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

package types

import (
	"context"
	"time"
)

// 通用配置类型
type L1CacheConfig struct {
	Enabled   bool          `json:"enabled"`
	MaxSize   int           `json:"max_size"`
	TTL       time.Duration `json:"ttl"`
	PurgeTime time.Duration `json:"purge_time"`
}

type CircuitBreakerConfig struct {
	Enabled      bool          `json:"enabled"`
	MaxFailures  int           `json:"max_failures"`
	ResetTimeout time.Duration `json:"reset_timeout"`
	Threshold    float64       `json:"threshold"`
}

type TimeoutConfig struct {
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

type FallbackStrategyConfig struct {
	Enabled     bool   `json:"enabled"`
	DefaultMode string `json:"default_mode"`
}

// 通用接口类型
type L1Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
	Size() int
}

type CircuitBreaker interface {
	Execute(fn func() error) error
	State() string
	Reset()
	IsOpen() bool
}

type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateHalfOpen
	StateOpen
)

func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

type MetricsCollector interface {
	CollectMetrics() map[string]interface{}
	RegisterMetric(name string, metric interface{})
	GetMetric(name string) interface{}
}

type PerformanceAnalyzer interface {
	RecordLatency(operation string, duration time.Duration)
	RecordThroughput(operation string, count int)
	GetStats() map[string]interface{}
}

type GoroutineManager interface {
	Start(name string, fn func())
	Stop(name string)
	StopAll()
	GetRunning() []string
}

// 基础实现
type NoOpMetricsCollector struct{}

func (n *NoOpMetricsCollector) CollectMetrics() map[string]interface{} {
	return make(map[string]interface{})
}

func (n *NoOpMetricsCollector) RegisterMetric(name string, metric interface{}) {}

func (n *NoOpMetricsCollector) GetMetric(name string) interface{} {
	return nil
}

type NoOpPerformanceAnalyzer struct{}

func (n *NoOpPerformanceAnalyzer) RecordLatency(operation string, duration time.Duration) {}

func (n *NoOpPerformanceAnalyzer) RecordThroughput(operation string, count int) {}

func (n *NoOpPerformanceAnalyzer) GetStats() map[string]interface{} {
	return make(map[string]interface{})
}

// 默认配置函数
func DefaultL1CacheConfig() *L1CacheConfig {
	return &L1CacheConfig{
		Enabled:   true,
		MaxSize:   1000,
		TTL:       5 * time.Minute,
		PurgeTime: 1 * time.Minute,
	}
}

func GetDefaultMetricsCollector() MetricsCollector {
	return &NoOpMetricsCollector{}
}

// 通用缓存统计
type L1CacheStats struct {
	HitCount  int64 `json:"hit_count"`
	MissCount int64 `json:"miss_count"`
	Size      int   `json:"size"`
	MaxSize   int   `json:"max_size"`
}

// 简单的上下文帮助器
func GetFromContext(ctx context.Context, key string) interface{} {
	return ctx.Value(key)
}

// 基础缓存接口
type FastLRUCache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{})
	Delete(key string)
	Clear()
	Size() int
}

// 连接池相关
type ConnectionPoolOptimizer interface {
	OptimizePool() error
	GetStats() map[string]interface{}
}

type PoolMonitor interface {
	Start() error
	Stop() error
	GetMetrics() map[string]interface{}
}

// 敏感信息过滤
type SensitiveFilterConfig struct {
	Enabled               bool                   `json:"enabled"`
	MaskChar              string                 `json:"mask_char"`
	FieldNames            []string               `json:"field_names"`
	Patterns              []string               `json:"patterns"`
	PartialMask           bool                   `json:"partial_mask"`
	DesensitizationConfig *DesensitizationConfig `json:"desensitization_config"`
}

// 去敏化配置
type DesensitizationConfig struct {
	EnablePatternDetection bool                            `json:"enable_pattern_detection"`
	EnableContextAnalysis  bool                            `json:"enable_context_analysis"`
	EnableMLDetection      bool                            `json:"enable_ml_detection"`
	DefaultLevel           DesensitizationLevel            `json:"default_level"`
	LevelByContentType     map[string]DesensitizationLevel `json:"level_by_content_type"`
	LevelByField           map[string]DesensitizationLevel `json:"level_by_field"`
	CustomPatterns         []CustomPattern                 `json:"custom_patterns"`
	CustomRules            []DesensitizationRule           `json:"custom_rules"`
	// Performance related fields
	Enabled         bool          `json:"enabled"`
	PerformanceMode bool          `json:"performance_mode"`
	CacheEnabled    bool          `json:"cache_enabled"`
	CacheSize       int           `json:"cache_size"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	BatchSize       int           `json:"batch_size"`
	// Security related fields
	HashSalt        string        `json:"hash_salt"`
	// Format preservation
	PreserveFormat  bool          `json:"preserve_format"`
	PreserveLength  bool          `json:"preserve_length"`
}

// 自定义模式
type CustomPattern struct {
	Name        string               `json:"name"`
	Pattern     string               `json:"pattern"`
	Replacement string               `json:"replacement"`
	Level       DesensitizationLevel `json:"level"`
	Enabled     bool                 `json:"enabled"`
	Description string               `json:"description"`
}

// 去敏化规则
type DesensitizationRule struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Field       string               `json:"field"`
	Pattern     string               `json:"pattern"`
	Level       DesensitizationLevel `json:"level"`
	Context     []string             `json:"context"`
	Priority    int                  `json:"priority"`
	Enabled     bool                 `json:"enabled"`
	Condition   string               `json:"condition"`
	Action      string               `json:"action"`
}

// Remove LevelPartial as it conflicts with DesensitizationLevel

func DefaultSensitiveFilterConfig() *SensitiveFilterConfig {
	return &SensitiveFilterConfig{
		Enabled:     true,
		MaskChar:    "*",
		FieldNames:  []string{"password", "token", "secret"},
		PartialMask: true,
		DesensitizationConfig: &DesensitizationConfig{
			EnablePatternDetection: false,
			EnableContextAnalysis:  false,
			DefaultLevel:           DesensitizationBasic,
			LevelByContentType:     make(map[string]DesensitizationLevel),
			LevelByField:           make(map[string]DesensitizationLevel),
			CustomPatterns:         make([]CustomPattern, 0),
			CustomRules:            make([]DesensitizationRule, 0),
		},
	}
}

// 去敏化级别
type DesensitizationLevel int

const (
	DesensitizationNone DesensitizationLevel = iota
	DesensitizationBasic
	DesensitizationAdvanced
	DesensitizationFull
	DesensitizationHashed
)

// 别名以保持兼容性
const (
	LevelNone     = DesensitizationNone
	LevelBasic    = DesensitizationBasic
	LevelAdvanced = DesensitizationAdvanced
	LevelFull     = DesensitizationFull
	LevelHashed   = DesensitizationHashed
)

func (d DesensitizationLevel) String() string {
	switch d {
	case DesensitizationNone:
		return "none"
	case DesensitizationBasic:
		return "basic"
	case DesensitizationAdvanced:
		return "advanced"
	case DesensitizationFull:
		return "full"
	case DesensitizationHashed:
		return "hashed"
	default:
		return "unknown"
	}
}

// 字符串内部化器
type StringInterner interface {
	Intern(s string) string
	Stats() map[string]interface{}
}

// 简单字符串内部化器实现
type SimpleStringInterner struct {
	cache map[string]string
}

func NewStringInterner() StringInterner {
	return &SimpleStringInterner{
		cache: make(map[string]string),
	}
}

func (s *SimpleStringInterner) Intern(str string) string {
	if interned, exists := s.cache[str]; exists {
		return interned
	}
	s.cache[str] = str
	return str
}

func (s *SimpleStringInterner) Stats() map[string]interface{} {
	return map[string]interface{}{
		"cache_size": len(s.cache),
	}
}

// FastLRU 缓存实现
type SimpleFastLRUCache struct {
	data    map[string]interface{}
	maxSize int
}

func NewFastLRUCache(maxSize int) FastLRUCache {
	return &SimpleFastLRUCache{
		data:    make(map[string]interface{}),
		maxSize: maxSize,
	}
}

func (c *SimpleFastLRUCache) Get(key string) (interface{}, bool) {
	value, exists := c.data[key]
	return value, exists
}

func (c *SimpleFastLRUCache) Set(key string, value interface{}) {
	if len(c.data) >= c.maxSize {
		// Simple eviction: remove random item
		for k := range c.data {
			delete(c.data, k)
			break
		}
	}
	c.data[key] = value
}

func (c *SimpleFastLRUCache) Delete(key string) {
	delete(c.data, key)
}

func (c *SimpleFastLRUCache) Clear() {
	c.data = make(map[string]interface{})
}

func (c *SimpleFastLRUCache) Size() int {
	return len(c.data)
}

// 数据权限中间件接口
type DataPermMiddleware interface {
	ProcessRequest(ctx context.Context, request interface{}) error
	ProcessResponse(ctx context.Context, response interface{}) error
	GetConfig() interface{}
}

// 内存监控器
type MemoryMonitor interface {
	StartMonitoring()
	StopMonitoring()
	GetStats() map[string]interface{}
}

// 泄漏检测器
type LeakDetector interface {
	StartDetection()
	StopDetection()
	GetLeaks() []interface{}
}

// 简单内存监控器实现
type SimpleMemoryMonitor struct {
	running bool
}

func (m *SimpleMemoryMonitor) StartMonitoring() {
	m.running = true
}

func (m *SimpleMemoryMonitor) StopMonitoring() {
	m.running = false
}

func (m *SimpleMemoryMonitor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"running": m.running,
	}
}

// 简单泄漏检测器实现
type SimpleLeakDetector struct {
	running bool
}

func (l *SimpleLeakDetector) StartDetection() {
	l.running = true
}

func (l *SimpleLeakDetector) StopDetection() {
	l.running = false
}

func (l *SimpleLeakDetector) GetLeaks() []interface{} {
	return []interface{}{}
}

// 简单数据权限中间件实现
type SimpleDataPermMiddleware struct {
	config interface{}
}

func (d *SimpleDataPermMiddleware) ProcessRequest(ctx context.Context, request interface{}) error {
	return nil
}

func (d *SimpleDataPermMiddleware) ProcessResponse(ctx context.Context, response interface{}) error {
	return nil
}

func (d *SimpleDataPermMiddleware) GetConfig() interface{} {
	return d.config
}

// 数据脱敏器
type DataDesensitizer struct {
	config *DesensitizationConfig
}

func NewDataDesensitizer(config *DesensitizationConfig) *DataDesensitizer {
	return &DataDesensitizer{
		config: config,
	}
}

func (d *DataDesensitizer) DesensitizeJSON(data string) (string, error) {
	// 简单实现，实际应该根据配置进行脱敏
	return data, nil
}

// TenantConfig 租户配置
type TenantConfig struct {
	TenantID        string                 `json:"tenant_id"`
	Name            string                 `json:"name"`
	Status          string                 `json:"status"`
	Config          map[string]interface{} `json:"config"`
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       string                 `json:"updated_at"`
	PermissionMode  string                 `json:"permission_mode"`
	EnableDataPerm  bool                   `json:"enable_data_perm"`
}

// 数据权限优化相关类型
type OptimizedDataPermConfig struct {
	Enabled            bool                 `json:"enabled"`
	CacheSize          int                  `json:"cache_size"`
	CacheTTL           time.Duration        `json:"cache_ttl"`
	CacheExpiration    time.Duration        `json:"cache_expiration"`
	Strategies         []string             `json:"strategies"`
	OptimizationLevel  int                  `json:"optimization_level"`
	Rules              []DataPermRule       `json:"rules"`
	EnableTenantMode   bool                 `json:"enable_tenant_mode"`
	DefaultTenantId    int                  `json:"default_tenant_id"`
}

type OptimizedPermissionResult struct {
	Allowed       bool                   `json:"allowed"`
	Reason        string                 `json:"reason"`
	Conditions    []string               `json:"conditions"`
	CacheHit      bool                   `json:"cache_hit"`
	Metadata      map[string]interface{} `json:"metadata"`
	DataScope     string                 `json:"data_scope"`
	SubDept       string                 `json:"sub_dept"`
	CustomDept    string                 `json:"custom_dept"`
	Level         string                 `json:"level"`
	Source        string                 `json:"source"`
	ExecutionTime time.Duration          `json:"execution_time"`
}

type DataPermRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Pattern     string                 `json:"pattern"`
	Action      string                 `json:"action"`
	Conditions  []string               `json:"conditions"`
	Priority    int                    `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata"`
}
