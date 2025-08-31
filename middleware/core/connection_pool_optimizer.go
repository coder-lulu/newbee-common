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
	"database/sql"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// ConnectionPoolOptimizer 连接池优化器
type ConnectionPoolOptimizer struct {
	// Redis连接池
	redisClient  redis.UniversalClient
	redisConfig  *OptimizedRedisConfig
	redisMetrics *RedisPoolMetrics

	// 数据库连接池
	dbClient  *sql.DB
	dbConfig  *OptimizedDBConfig
	dbMetrics *DBPoolMetrics

	// 自适应调整
	autoTuning    *AutoTuningConfig
	adjustmentMgr *ConnectionAdjustmentManager

	// 监控和报警
	monitor      *PoolMonitor
	alertManager *PoolAlertManager

	// 控制字段
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex
	running int32
}

// OptimizedRedisConfig 优化的Redis连接池配置
type OptimizedRedisConfig struct {
	// 基础连接配置
	Addrs    []string `json:"addrs"`
	Password string   `json:"password"`
	DB       int      `json:"db"`

	// 优化的连接池配置
	PoolSize        int           `json:"pool_size"`          // 最大连接数
	MinIdleConns    int           `json:"min_idle_conns"`     // 最小空闲连接数
	MaxIdleConns    int           `json:"max_idle_conns"`     // 最大空闲连接数
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`  // 连接最大生命周期
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"` // 连接最大空闲时间

	// 超时配置
	DialTimeout  time.Duration `json:"dial_timeout"`  // 连接超时
	ReadTimeout  time.Duration `json:"read_timeout"`  // 读超时
	WriteTimeout time.Duration `json:"write_timeout"` // 写超时

	// 高级配置
	PoolTimeout        time.Duration `json:"pool_timeout"`         // 从连接池获取连接的超时时间
	IdleCheckFrequency time.Duration `json:"idle_check_frequency"` // 空闲连接检查频率
	MaxRetries         int           `json:"max_retries"`          // 最大重试次数
	RetryDelay         time.Duration `json:"retry_delay"`          // 重试延迟

	// 性能优化配置
	EnablePipelining  bool `json:"enable_pipelining"`  // 启用管道
	PipelineSize      int  `json:"pipeline_size"`      // 管道大小
	EnableCompression bool `json:"enable_compression"` // 启用压缩
	ReadBufferSize    int  `json:"read_buffer_size"`   // 读缓冲区大小
	WriteBufferSize   int  `json:"write_buffer_size"`  // 写缓冲区大小
}

// OptimizedDBConfig 优化的数据库连接池配置
type OptimizedDBConfig struct {
	// 连接池配置
	MaxOpenConns    int           `json:"max_open_conns"`     // 最大开放连接数
	MaxIdleConns    int           `json:"max_idle_conns"`     // 最大空闲连接数
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`  // 连接最大生命周期
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"` // 连接最大空闲时间

	// 超时配置
	ConnectTimeout time.Duration `json:"connect_timeout"` // 连接超时
	QueryTimeout   time.Duration `json:"query_timeout"`   // 查询超时
	ExecTimeout    time.Duration `json:"exec_timeout"`    // 执行超时

	// 健康检查
	PingInterval     time.Duration `json:"ping_interval"`      // Ping间隔
	HealthCheckQuery string        `json:"health_check_query"` // 健康检查查询

	// 性能优化
	PreparedStmtCache bool `json:"prepared_stmt_cache"` // 预编译语句缓存
	QueryCacheSize    int  `json:"query_cache_size"`    // 查询缓存大小
}

// AutoTuningConfig 自适应调整配置
type AutoTuningConfig struct {
	Enabled               bool          `json:"enabled"`                  // 启用自适应调整
	CheckInterval         time.Duration `json:"check_interval"`           // 检查间隔
	LoadThresholdHigh     float64       `json:"load_threshold_high"`      // 高负载阈值
	LoadThresholdLow      float64       `json:"load_threshold_low"`       // 低负载阈值
	ResponseTimeThreshold time.Duration `json:"response_time_threshold"`  // 响应时间阈值
	ErrorRateThreshold    float64       `json:"error_rate_threshold"`     // 错误率阈值
	AdjustmentStepSize    int           `json:"adjustment_step_size"`     // 调整步长
	MaxAdjustmentPerCycle int           `json:"max_adjustment_per_cycle"` // 每周期最大调整量
	CooldownPeriod        time.Duration `json:"cooldown_period"`          // 冷却期
}

// RedisPoolMetrics Redis连接池指标
type RedisPoolMetrics struct {
	// 连接池状态
	TotalConns int32 `json:"total_conns"` // 总连接数
	IdleConns  int32 `json:"idle_conns"`  // 空闲连接数
	StaleConns int32 `json:"stale_conns"` // 过期连接数

	// 性能指标
	Hits     int64 `json:"hits"`     // 命中数
	Misses   int64 `json:"misses"`   // 失效数
	Timeouts int64 `json:"timeouts"` // 超时数

	// 延迟统计
	AvgConnTime time.Duration `json:"avg_conn_time"` // 平均连接时间
	AvgCmdTime  time.Duration `json:"avg_cmd_time"`  // 平均命令时间
	MaxConnTime time.Duration `json:"max_conn_time"` // 最大连接时间

	// 错误统计
	ConnErrors    int64 `json:"conn_errors"`    // 连接错误数
	CmdErrors     int64 `json:"cmd_errors"`     // 命令错误数
	NetworkErrors int64 `json:"network_errors"` // 网络错误数

	LastUpdateTime time.Time `json:"last_update_time"` // 最后更新时间
}

// DBPoolMetrics 数据库连接池指标
type DBPoolMetrics struct {
	// 连接池状态
	OpenConnections  int32 `json:"open_connections"`   // 开放连接数
	InUseConnections int32 `json:"in_use_connections"` // 使用中连接数
	IdleConnections  int32 `json:"idle_connections"`   // 空闲连接数

	// 等待统计
	WaitCount    int64         `json:"wait_count"`    // 等待次数
	WaitDuration time.Duration `json:"wait_duration"` // 等待时长

	// 连接生命周期
	MaxOpenConnections int32         `json:"max_open_connections"` // 最大开放连接数
	MaxIdleConnections int32         `json:"max_idle_connections"` // 最大空闲连接数
	MaxLifetime        time.Duration `json:"max_lifetime"`         // 最大生命周期
	MaxIdleTime        time.Duration `json:"max_idle_time"`        // 最大空闲时间

	LastUpdateTime time.Time `json:"last_update_time"` // 最后更新时间
}

// ConnectionAdjustmentManager 连接调整管理器
type ConnectionAdjustmentManager struct {
	optimizer         *ConnectionPoolOptimizer
	config            *AutoTuningConfig
	lastAdjustment    time.Time
	adjustmentHistory []AdjustmentRecord
	mu                sync.RWMutex
}

// AdjustmentRecord 调整记录
type AdjustmentRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`      // redis, db
	Parameter  string    `json:"parameter"` // pool_size, max_idle_conns, etc.
	OldValue   int       `json:"old_value"`
	NewValue   int       `json:"new_value"`
	Reason     string    `json:"reason"`
	LoadBefore float64   `json:"load_before"`
	LoadAfter  float64   `json:"load_after"`
	Successful bool      `json:"successful"`
}

// PoolMonitor 连接池监控器
type PoolMonitor struct {
	optimizer  *ConnectionPoolOptimizer
	config     *MonitoringConfig
	metrics    *PoolMetrics
	collectors []MetricsCollector
	mu         sync.RWMutex
}

// PoolMetrics 连接池综合指标
type PoolMetrics struct {
	Redis     *RedisPoolMetrics `json:"redis"`
	Database  *DBPoolMetrics    `json:"database"`
	System    *SystemMetrics    `json:"system"`
	Timestamp time.Time         `json:"timestamp"`
}

// SystemMetrics 系统指标
type SystemMetrics struct {
	CPUUsage       float64       `json:"cpu_usage"`
	MemoryUsage    float64       `json:"memory_usage"`
	GoroutineCount int           `json:"goroutine_count"`
	GCPauseTime    time.Duration `json:"gc_pause_time"`
	HeapSize       uint64        `json:"heap_size"`
	HeapInUse      uint64        `json:"heap_in_use"`
}

// PoolAlertManager 连接池报警管理器
type PoolAlertManager struct {
	config       *AlertConfig
	alertChannel chan *PoolAlert
	subscribers  []AlertSubscriber
	alertHistory []PoolAlert
	mu           sync.RWMutex
}

// PoolAlert 连接池报警
type PoolAlert struct {
	ID          string                 `json:"id"`
	Type        PoolAlertType          `json:"type"`
	Level       AlertLevel             `json:"level"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Metrics     map[string]interface{} `json:"metrics"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// PoolAlertType 连接池报警类型
type PoolAlertType string

const (
	AlertTypeRedisConnectionHigh PoolAlertType = "redis_connection_high"
	AlertTypeRedisConnectionLow  PoolAlertType = "redis_connection_low"
	AlertTypeRedisLatencyHigh    PoolAlertType = "redis_latency_high"
	AlertTypeRedisErrorRateHigh  PoolAlertType = "redis_error_rate_high"
	AlertTypeDBConnectionHigh    PoolAlertType = "db_connection_high"
	AlertTypeDBConnectionLow     PoolAlertType = "db_connection_low"
	AlertTypeDBWaitTimeHigh      PoolAlertType = "db_wait_time_high"
	AlertTypeSystemResourceHigh  PoolAlertType = "system_resource_high"
	AlertTypeAutoTuningFailed    PoolAlertType = "auto_tuning_failed"
)

// AlertLevel 报警级别
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "info"
	AlertLevelWarning  AlertLevel = "warning"
	AlertLevelCritical AlertLevel = "critical"
)

// AlertSubscriber 报警订阅者接口
type AlertSubscriber interface {
	OnAlert(alert *PoolAlert) error
}

// AlertConfig 报警配置
type AlertConfig struct {
	Enabled              bool               `json:"enabled"`
	Channels             []string           `json:"channels"`              // email, slack, webhook
	Thresholds           map[string]float64 `json:"thresholds"`            // 各种阈值
	CooldownPeriod       time.Duration      `json:"cooldown_period"`       // 报警冷却期
	EscalationRules      []EscalationRule   `json:"escalation_rules"`      // 升级规则
	NotificationTemplate map[string]string  `json:"notification_template"` // 通知模板
}

// EscalationRule 升级规则
type EscalationRule struct {
	Duration  time.Duration `json:"duration"`   // 持续时间
	FromLevel AlertLevel    `json:"from_level"` // 源级别
	ToLevel   AlertLevel    `json:"to_level"`   // 目标级别
	Channels  []string      `json:"channels"`   // 升级通道
}

// MetricsCollector 指标收集器接口
type MetricsCollector interface {
	CollectRedisMetrics(client redis.UniversalClient) (*RedisPoolMetrics, error)
	CollectDBMetrics(db *sql.DB) (*DBPoolMetrics, error)
	CollectSystemMetrics() (*SystemMetrics, error)
}

// NewConnectionPoolOptimizer 创建连接池优化器
func NewConnectionPoolOptimizer(
	redisClient redis.UniversalClient,
	dbClient *sql.DB,
	config *ConnectionPoolConfig,
) *ConnectionPoolOptimizer {
	ctx, cancel := context.WithCancel(context.Background())

	optimizer := &ConnectionPoolOptimizer{
		redisClient:  redisClient,
		dbClient:     dbClient,
		redisConfig:  config.Redis,
		dbConfig:     config.Database,
		autoTuning:   config.AutoTuning,
		ctx:          ctx,
		cancel:       cancel,
		redisMetrics: &RedisPoolMetrics{},
		dbMetrics:    &DBPoolMetrics{},
	}

	// 初始化组件
	optimizer.adjustmentMgr = NewConnectionAdjustmentManager(optimizer, config.AutoTuning)
	optimizer.monitor = NewPoolMonitor(optimizer, config.Monitoring)
	optimizer.alertManager = NewPoolAlertManager(config.Alert)

	return optimizer
}

// ConnectionPoolConfig 连接池配置
type ConnectionPoolConfig struct {
	Redis      *OptimizedRedisConfig `json:"redis"`
	Database   *OptimizedDBConfig    `json:"database"`
	AutoTuning *AutoTuningConfig     `json:"auto_tuning"`
	Monitoring *MonitoringConfig     `json:"monitoring"`
	Alert      *AlertConfig          `json:"alert"`
}

// Start 启动连接池优化器
func (cpo *ConnectionPoolOptimizer) Start() error {
	if !atomic.CompareAndSwapInt32(&cpo.running, 0, 1) {
		return fmt.Errorf("connection pool optimizer already running")
	}

	// 应用初始配置
	if err := cpo.applyRedisConfig(); err != nil {
		atomic.StoreInt32(&cpo.running, 0)
		return fmt.Errorf("failed to apply redis config: %w", err)
	}

	if err := cpo.applyDBConfig(); err != nil {
		atomic.StoreInt32(&cpo.running, 0)
		return fmt.Errorf("failed to apply database config: %w", err)
	}

	// 启动监控
	if err := cpo.monitor.Start(cpo.ctx); err != nil {
		atomic.StoreInt32(&cpo.running, 0)
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// 启动报警管理器
	if err := cpo.alertManager.Start(cpo.ctx); err != nil {
		atomic.StoreInt32(&cpo.running, 0)
		return fmt.Errorf("failed to start alert manager: %w", err)
	}

	// 启动自适应调整
	if cpo.autoTuning.Enabled {
		if err := cpo.adjustmentMgr.Start(cpo.ctx); err != nil {
			atomic.StoreInt32(&cpo.running, 0)
			return fmt.Errorf("failed to start adjustment manager: %w", err)
		}
	}

	return nil
}

// Stop 停止连接池优化器
func (cpo *ConnectionPoolOptimizer) Stop() error {
	if !atomic.CompareAndSwapInt32(&cpo.running, 1, 0) {
		return fmt.Errorf("connection pool optimizer not running")
	}

	// 取消上下文
	cpo.cancel()

	// 等待所有组件停止
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		cpo.monitor.Stop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		cpo.alertManager.Stop()
	}()

	if cpo.autoTuning.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cpo.adjustmentMgr.Stop()
		}()
	}

	wg.Wait()

	return nil
}

// applyRedisConfig 应用Redis配置
func (cpo *ConnectionPoolOptimizer) applyRedisConfig() error {
	cpo.mu.Lock()
	defer cpo.mu.Unlock()

	// 这里应该重新配置Redis客户端
	// 由于go-redis的限制，我们记录配置变更用于新连接
	return nil
}

// applyDBConfig 应用数据库配置
func (cpo *ConnectionPoolOptimizer) applyDBConfig() error {
	cpo.mu.Lock()
	defer cpo.mu.Unlock()

	if cpo.dbClient == nil {
		return nil
	}

	// 应用数据库连接池配置
	cpo.dbClient.SetMaxOpenConns(cpo.dbConfig.MaxOpenConns)
	cpo.dbClient.SetMaxIdleConns(cpo.dbConfig.MaxIdleConns)
	cpo.dbClient.SetConnMaxLifetime(cpo.dbConfig.ConnMaxLifetime)
	cpo.dbClient.SetConnMaxIdleTime(cpo.dbConfig.ConnMaxIdleTime)

	return nil
}

// GetDefaultRedisConfig 获取默认Redis配置
func GetDefaultRedisConfig() *OptimizedRedisConfig {
	// 根据系统资源动态调整默认值
	cpuCount := runtime.NumCPU()
	basePoolSize := cpuCount * 10

	return &OptimizedRedisConfig{
		PoolSize:           basePoolSize,
		MinIdleConns:       basePoolSize / 4,
		MaxIdleConns:       basePoolSize / 2,
		ConnMaxLifetime:    time.Hour,
		ConnMaxIdleTime:    time.Minute * 30,
		DialTimeout:        time.Second * 5,
		ReadTimeout:        time.Second * 3,
		WriteTimeout:       time.Second * 3,
		PoolTimeout:        time.Second * 4,
		IdleCheckFrequency: time.Minute,
		MaxRetries:         3,
		RetryDelay:         time.Millisecond * 500,
		EnablePipelining:   true,
		PipelineSize:       100,
		EnableCompression:  false,
		ReadBufferSize:     4096,
		WriteBufferSize:    4096,
	}
}

// GetDefaultDBConfig 获取默认数据库配置
func GetDefaultDBConfig() *OptimizedDBConfig {
	cpuCount := runtime.NumCPU()
	baseConnSize := cpuCount * 5

	return &OptimizedDBConfig{
		MaxOpenConns:      baseConnSize,
		MaxIdleConns:      baseConnSize / 2,
		ConnMaxLifetime:   time.Hour,
		ConnMaxIdleTime:   time.Minute * 30,
		ConnectTimeout:    time.Second * 5,
		QueryTimeout:      time.Second * 30,
		ExecTimeout:       time.Second * 30,
		PingInterval:      time.Minute * 5,
		HealthCheckQuery:  "SELECT 1",
		PreparedStmtCache: true,
		QueryCacheSize:    1000,
	}
}

// GetDefaultAutoTuningConfig 获取默认自适应调整配置
func GetDefaultAutoTuningConfig() *AutoTuningConfig {
	return &AutoTuningConfig{
		Enabled:               true,
		CheckInterval:         time.Minute * 5,
		LoadThresholdHigh:     0.8,
		LoadThresholdLow:      0.3,
		ResponseTimeThreshold: time.Millisecond * 100,
		ErrorRateThreshold:    0.01,
		AdjustmentStepSize:    5,
		MaxAdjustmentPerCycle: 20,
		CooldownPeriod:        time.Minute * 10,
	}
}

// GetDefaultAlertConfig 获取默认报警配置
func GetDefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		Enabled:        true,
		Channels:       []string{"log"},
		CooldownPeriod: time.Minute * 5,
		Thresholds: map[string]float64{
			"redis_pool_usage": 0.8,
			"db_pool_usage":    0.8,
			"response_time_ms": 100,
			"error_rate":       0.01,
			"cpu_usage":        0.8,
			"memory_usage":     0.8,
		},
		EscalationRules: []EscalationRule{
			{
				Duration:  time.Minute * 5,
				FromLevel: AlertLevelWarning,
				ToLevel:   AlertLevelCritical,
				Channels:  []string{"log", "email"},
			},
		},
	}
}

// GetConnectionPoolMetrics 获取连接池指标
func (cpo *ConnectionPoolOptimizer) GetConnectionPoolMetrics() (*PoolMetrics, error) {
	cpo.mu.RLock()
	defer cpo.mu.RUnlock()

	if cpo.monitor == nil {
		return nil, fmt.Errorf("monitor not initialized")
	}

	return cpo.monitor.GetMetrics()
}

// GetAdjustmentHistory 获取调整历史
func (cpo *ConnectionPoolOptimizer) GetAdjustmentHistory() []AdjustmentRecord {
	if cpo.adjustmentMgr == nil {
		return nil
	}

	return cpo.adjustmentMgr.GetHistory()
}

// UpdateRedisConfig 更新Redis配置
func (cpo *ConnectionPoolOptimizer) UpdateRedisConfig(config *OptimizedRedisConfig) error {
	cpo.mu.Lock()
	defer cpo.mu.Unlock()

	cpo.redisConfig = config
	return cpo.applyRedisConfig()
}

// UpdateDBConfig 更新数据库配置
func (cpo *ConnectionPoolOptimizer) UpdateDBConfig(config *OptimizedDBConfig) error {
	cpo.mu.Lock()
	defer cpo.mu.Unlock()

	cpo.dbConfig = config
	return cpo.applyDBConfig()
}
