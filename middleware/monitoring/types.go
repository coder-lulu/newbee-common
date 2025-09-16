// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"sync/atomic"
	"time"
)

// 监控配置
type MonitoringConfig struct {
	// 基本配置
	Enabled           bool          `json:"enabled"`
	SamplingRate      float64       `json:"sampling_rate"`      // 0.0-1.0
	CollectionInterval time.Duration `json:"collection_interval"` // 数据收集间隔
	
	// 告警配置
	AlertEnabled      bool          `json:"alert_enabled"`
	AlertCooldown     time.Duration `json:"alert_cooldown"`     // 告警冷却期
	
	// 存储配置
	MetricStorage     string        `json:"metric_storage"`     // "memory", "prometheus"
	RetentionPeriod   time.Duration `json:"retention_period"`   // 数据保留期
	
	// 性能阈值
	LatencyThresholds LatencyThresholds `json:"latency_thresholds"`
	ErrorThresholds   ErrorThresholds   `json:"error_thresholds"`
	CacheThresholds   CacheThresholds   `json:"cache_thresholds"`
}

// 延迟阈值配置
type LatencyThresholds struct {
	P50Warning  time.Duration `json:"p50_warning"`
	P50Critical time.Duration `json:"p50_critical"`
	P95Warning  time.Duration `json:"p95_warning"`
	P95Critical time.Duration `json:"p95_critical"`
	P99Warning  time.Duration `json:"p99_warning"`
	P99Critical time.Duration `json:"p99_critical"`
}

// 错误阈值配置
type ErrorThresholds struct {
	WarningRate  float64 `json:"warning_rate"`  // 0.01 = 1%
	CriticalRate float64 `json:"critical_rate"` // 0.05 = 5%
}

// 缓存阈值配置
type CacheThresholds struct {
	LowHitRateWarning  float64 `json:"low_hit_rate_warning"`  // 0.8 = 80%
	LowHitRateCritical float64 `json:"low_hit_rate_critical"` // 0.7 = 70%
	HighMemoryWarning  float64 `json:"high_memory_warning"`   // 0.8 = 80%
	HighMemoryCritical float64 `json:"high_memory_critical"`  // 0.9 = 90%
}

// 监控指标基础结构
type MetricBase struct {
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
}

// 计数器指标
type CounterMetric struct {
	MetricBase
	Value int64 `json:"value"`
}

// 历史指标
type HistogramMetric struct {
	MetricBase
	Count   int64         `json:"count"`
	Sum     float64       `json:"sum"`
	Buckets []Bucket      `json:"buckets"`
	P50     time.Duration `json:"p50"`
	P95     time.Duration `json:"p95"`
	P99     time.Duration `json:"p99"`
}

// 直方图桶
type Bucket struct {
	UpperBound time.Duration `json:"upper_bound"`
	Count      int64         `json:"count"`
}

// 仪表盘指标
type GaugeMetric struct {
	MetricBase
	Value float64 `json:"value"`
}

// 中间件性能指标
type MiddlewareMetrics struct {
	MiddlewareName string `json:"middleware_name"`
	Priority       int    `json:"priority"`
	
	// 性能指标
	RequestCount     int64         `json:"request_count"`
	SuccessCount     int64         `json:"success_count"`
	ErrorCount       int64         `json:"error_count"`
	TotalLatency     time.Duration `json:"total_latency"`
	LastLatency      time.Duration `json:"last_latency"`
	MaxLatency       time.Duration `json:"max_latency"`
	
	// 分位数延迟
	P50Latency       time.Duration `json:"p50_latency"`
	P95Latency       time.Duration `json:"p95_latency"`
	P99Latency       time.Duration `json:"p99_latency"`
	
	// 错误统计
	AuthErrors       int64 `json:"auth_errors"`
	TenantErrors     int64 `json:"tenant_errors"`
	PermissionErrors int64 `json:"permission_errors"`
	SystemErrors     int64 `json:"system_errors"`
	
	// 时间戳
	LastUpdate       time.Time `json:"last_update"`
	StartTime        time.Time `json:"start_time"`
}

// 缓存监控指标
type CacheMetrics struct {
	CacheName    string `json:"cache_name"`
	CacheType    string `json:"cache_type"` // "jwt", "sharded", "redis"
	
	// 基础指标
	HitCount     int64   `json:"hit_count"`
	MissCount    int64   `json:"miss_count"`
	HitRate      float64 `json:"hit_rate"`
	
	// 容量指标
	CurrentSize  int64   `json:"current_size"`
	MaxSize      int64   `json:"max_size"`
	SizeUsage    float64 `json:"size_usage"`
	
	// 操作指标
	SetCount     int64         `json:"set_count"`
	GetCount     int64         `json:"get_count"`
	DeleteCount  int64         `json:"delete_count"`
	CleanupCount int64         `json:"cleanup_count"`
	
	// 性能指标
	AvgGetLatency    time.Duration `json:"avg_get_latency"`
	AvgSetLatency    time.Duration `json:"avg_set_latency"`
	AvgDeleteLatency time.Duration `json:"avg_delete_latency"`
	
	// 更新时间
	LastUpdate   time.Time `json:"last_update"`
}

// 安全监控指标
type SecurityMetrics struct {
	// 租户违规
	TenantViolations        int64 `json:"tenant_violations"`
	CrossTenantAttempts     int64 `json:"cross_tenant_attempts"`
	TenantNotFoundErrors    int64 `json:"tenant_not_found_errors"`
	
	// 认证违规
	AuthFailures            int64 `json:"auth_failures"`
	InvalidTokens           int64 `json:"invalid_tokens"`
	ExpiredTokens           int64 `json:"expired_tokens"`
	MalformedTokens         int64 `json:"malformed_tokens"`
	
	// 权限违规
	PermissionDenied        int64 `json:"permission_denied"`
	DataPermissionViolations int64 `json:"data_permission_violations"`
	UnauthorizedAccess      int64 `json:"unauthorized_access"`
	
	// 限流触发
	RateLimitExceeded       int64 `json:"rate_limit_exceeded"`
	SuspiciousIPCount       int64 `json:"suspicious_ip_count"`
	
	// 异常行为
	AbnormalRequestPatterns int64     `json:"abnormal_request_patterns"`
	LastViolationTime       time.Time `json:"last_violation_time"`
}

// 系统监控指标
type SystemMetrics struct {
	// Redis指标
	RedisConnected       bool          `json:"redis_connected"`
	RedisLatency         time.Duration `json:"redis_latency"`
	RedisConnections     int           `json:"redis_connections"`
	RedisCommandsTotal   int64         `json:"redis_commands_total"`
	RedisCommandsFailure int64         `json:"redis_commands_failure"`
	
	// 数据库指标
	DBConnected          bool          `json:"db_connected"`
	DBLatency            time.Duration `json:"db_latency"`
	DBConnections        int           `json:"db_connections"`
	DBQueriesTotal       int64         `json:"db_queries_total"`
	DBQueriesFailure     int64         `json:"db_queries_failure"`
	
	// 审计指标
	AuditWriteSuccess    int64         `json:"audit_write_success"`
	AuditWriteFailure    int64         `json:"audit_write_failure"`
	AuditAvgLatency      time.Duration `json:"audit_avg_latency"`
	AuditQueueLength     int           `json:"audit_queue_length"`
	
	// 系统资源
	MemoryUsage          float64       `json:"memory_usage"`
	CPUUsage             float64       `json:"cpu_usage"`
	GoroutineCount       int           `json:"goroutine_count"`
	GCPauseDuration      time.Duration `json:"gc_pause_duration"`
	
	// 更新时间
	LastHealthCheck      time.Time     `json:"last_health_check"`
}

// 健康状态
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// 组件健康状态
type ComponentHealth struct {
	Name           string            `json:"name"`
	Status         HealthStatus      `json:"status"`
	LastCheck      time.Time         `json:"last_check"`
	ErrorMessage   string            `json:"error_message,omitempty"`
	ResponseTime   time.Duration     `json:"response_time"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// 整体健康报告
type HealthReport struct {
	OverallStatus  HealthStatus               `json:"overall_status"`
	CheckTime      time.Time                  `json:"check_time"`
	Components     map[string]ComponentHealth `json:"components"`
	Summary        HealthSummary              `json:"summary"`
}

// 健康摘要
type HealthSummary struct {
	TotalComponents   int `json:"total_components"`
	HealthyComponents int `json:"healthy_components"`
	DegradedComponents int `json:"degraded_components"`
	UnhealthyComponents int `json:"unhealthy_components"`
	UnknownComponents  int `json:"unknown_components"`
}

// 告警级别
type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// 告警事件
type AlertEvent struct {
	ID          string        `json:"id"`
	Severity    AlertSeverity `json:"severity"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Component   string        `json:"component"`
	Metric      string        `json:"metric"`
	Value       interface{}   `json:"value"`
	Threshold   interface{}   `json:"threshold"`
	Timestamp   time.Time     `json:"timestamp"`
	Resolved    bool          `json:"resolved"`
	ResolvedAt  *time.Time    `json:"resolved_at,omitempty"`
}

// 原子计数器工具
type AtomicCounter struct {
	value int64
}

func (c *AtomicCounter) Inc() {
	atomic.AddInt64(&c.value, 1)
}

func (c *AtomicCounter) Add(delta int64) {
	atomic.AddInt64(&c.value, delta)
}

func (c *AtomicCounter) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *AtomicCounter) Reset() {
	atomic.StoreInt64(&c.value, 0)
}

// 原子浮点数工具（用于存储为int64，读取时除以固定因子）
type AtomicFloat64 struct {
	value int64
}

const float64Scale = 1000000 // 6位小数精度

func (f *AtomicFloat64) Set(val float64) {
	atomic.StoreInt64(&f.value, int64(val*float64Scale))
}

func (f *AtomicFloat64) Get() float64 {
	return float64(atomic.LoadInt64(&f.value)) / float64Scale
}

// 默认监控配置
func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		Enabled:            true,
		SamplingRate:       1.0,
		CollectionInterval: 30 * time.Second,
		AlertEnabled:       true,
		AlertCooldown:      5 * time.Minute,
		MetricStorage:      "memory",
		RetentionPeriod:    24 * time.Hour,
		LatencyThresholds: LatencyThresholds{
			P50Warning:  50 * time.Millisecond,
			P50Critical: 200 * time.Millisecond,
			P95Warning:  200 * time.Millisecond,
			P95Critical: 1 * time.Second,
			P99Warning:  1 * time.Second,
			P99Critical: 5 * time.Second,
		},
		ErrorThresholds: ErrorThresholds{
			WarningRate:  0.01, // 1%
			CriticalRate: 0.05, // 5%
		},
		CacheThresholds: CacheThresholds{
			LowHitRateWarning:  0.80, // 80%
			LowHitRateCritical: 0.70, // 70%
			HighMemoryWarning:  0.80, // 80%
			HighMemoryCritical: 0.90, // 90%
		},
	}
}