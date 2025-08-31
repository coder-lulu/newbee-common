package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// 认证性能指标
	AuthRequestTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_request_total",
			Help: "Total number of authentication requests",
		},
		[]string{"status", "tenant"},
	)

	AuthRequestLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_request_latency_seconds",
			Help:    "Authentication request latency distribution",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"status", "tenant"},
	)

	// JWT性能指标
	JWTParseLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "jwt_parse_latency_seconds",
			Help:    "JWT token parsing latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant"},
	)

	// 缓存性能指标
	CacheHitRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "auth_cache_hit_rate",
			Help: "Token cache hit rate",
		},
		[]string{"tenant"},
	)

	CacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "auth_cache_size",
			Help: "Current size of token cache",
		},
		[]string{"tenant"},
	)

	// 安全指标
	SecurityViolations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_security_violations_total",
			Help: "Total number of security violations",
		},
		[]string{"type", "tenant"},
	)
)

// RecordAuthRequest 记录认证请求指标
func RecordAuthRequest(status string, tenant string, latency float64) {
	AuthRequestTotal.WithLabelValues(status, tenant).Inc()
	AuthRequestLatency.WithLabelValues(status, tenant).Observe(latency)
}

// RecordJWTParseLatency 记录JWT解析延迟
func RecordJWTParseLatency(tenant string, latency float64) {
	JWTParseLatency.WithLabelValues(tenant).Observe(latency)
}

// UpdateCacheMetrics 更新缓存指标
func UpdateCacheMetrics(tenant string, hitRate float64, size int) {
	CacheHitRate.WithLabelValues(tenant).Set(hitRate)
	CacheSize.WithLabelValues(tenant).Set(float64(size))
}

// RecordSecurityViolation 记录安全违规
func RecordSecurityViolation(violationType string, tenant string) {
	SecurityViolations.WithLabelValues(violationType, tenant).Inc()
}