// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest"
)

// PerformanceMetrics 中间件性能指标
type PerformanceMetrics struct {
	// 执行计数
	TotalRequests    int64 `json:"total_requests"`
	AuthRequests     int64 `json:"auth_requests"`
	TenantRequests   int64 `json:"tenant_requests"`
	DataPermRequests int64 `json:"dataperm_requests"`
	AuditRequests    int64 `json:"audit_requests"`
	
	// 执行耗时 (纳秒)
	AuthDuration     int64 `json:"auth_duration_ns"`
	TenantDuration   int64 `json:"tenant_duration_ns"`
	DataPermDuration int64 `json:"dataperm_duration_ns"`
	AuditDuration    int64 `json:"audit_duration_ns"`
	
	// 错误计数
	AuthErrors     int64 `json:"auth_errors"`
	TenantErrors   int64 `json:"tenant_errors"`
	DataPermErrors int64 `json:"dataperm_errors"`
	AuditErrors    int64 `json:"audit_errors"`
	
	// 缓存性能
	AuthCacheHits   int64 `json:"auth_cache_hits"`
	AuthCacheMisses int64 `json:"auth_cache_misses"`
	
	lastReset time.Time
	mu        sync.RWMutex
}

// GetCacheHitRate 获取认证缓存命中率
func (m *PerformanceMetrics) GetCacheHitRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	total := m.AuthCacheHits + m.AuthCacheMisses
	if total == 0 {
		return 0.0
	}
	return float64(m.AuthCacheHits) / float64(total) * 100.0
}

// GetErrorRate 获取错误率
func (m *PerformanceMetrics) GetErrorRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	totalErrors := m.AuthErrors + m.TenantErrors + m.DataPermErrors + m.AuditErrors
	if m.TotalRequests == 0 {
		return 0.0
	}
	return float64(totalErrors) / float64(m.TotalRequests) * 100.0
}

// GetAverageDuration 获取平均执行时间 (毫秒)
func (m *PerformanceMetrics) GetAverageDuration(plugin string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	switch plugin {
	case "auth":
		if m.AuthRequests == 0 {
			return 0.0
		}
		return float64(m.AuthDuration) / float64(m.AuthRequests) / 1e6 // 转换为毫秒
	case "tenant":
		if m.TenantRequests == 0 {
			return 0.0
		}
		return float64(m.TenantDuration) / float64(m.TenantRequests) / 1e6
	case "dataperm":
		if m.DataPermRequests == 0 {
			return 0.0
		}
		return float64(m.DataPermDuration) / float64(m.DataPermRequests) / 1e6
	case "audit":
		if m.AuditRequests == 0 {
			return 0.0
		}
		return float64(m.AuditDuration) / float64(m.AuditRequests) / 1e6
	default:
		return 0.0
	}
}

// RecordPluginExecution 记录插件执行指标
func (m *PerformanceMetrics) RecordPluginExecution(plugin string, duration time.Duration, success bool) {
	atomic.AddInt64(&m.TotalRequests, 1)
	
	durationNs := duration.Nanoseconds()
	
	switch plugin {
	case "auth":
		atomic.AddInt64(&m.AuthRequests, 1)
		atomic.AddInt64(&m.AuthDuration, durationNs)
		if !success {
			atomic.AddInt64(&m.AuthErrors, 1)
		}
	case "tenant":
		atomic.AddInt64(&m.TenantRequests, 1)
		atomic.AddInt64(&m.TenantDuration, durationNs)
		if !success {
			atomic.AddInt64(&m.TenantErrors, 1)
		}
	case "dataperm":
		atomic.AddInt64(&m.DataPermRequests, 1)
		atomic.AddInt64(&m.DataPermDuration, durationNs)
		if !success {
			atomic.AddInt64(&m.DataPermErrors, 1)
		}
	case "audit":
		atomic.AddInt64(&m.AuditRequests, 1)
		atomic.AddInt64(&m.AuditDuration, durationNs)
		if !success {
			atomic.AddInt64(&m.AuditErrors, 1)
		}
	}
}

// RecordAuthCache 记录认证缓存性能
func (m *PerformanceMetrics) RecordAuthCache(hit bool) {
	if hit {
		atomic.AddInt64(&m.AuthCacheHits, 1)
	} else {
		atomic.AddInt64(&m.AuthCacheMisses, 1)
	}
}

// GetUptime 获取运行时间
func (m *PerformanceMetrics) GetUptime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Since(m.lastReset)
}

// Reset 重置指标
func (m *PerformanceMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.TotalRequests = 0
	m.AuthRequests = 0
	m.TenantRequests = 0
	m.DataPermRequests = 0
	m.AuditRequests = 0
	
	m.AuthDuration = 0
	m.TenantDuration = 0
	m.DataPermDuration = 0
	m.AuditDuration = 0
	
	m.AuthErrors = 0
	m.TenantErrors = 0
	m.DataPermErrors = 0
	m.AuditErrors = 0
	
	m.AuthCacheHits = 0
	m.AuthCacheMisses = 0
	
	m.lastReset = time.Now()
}

// MiddlewareManager orchestrates the entire middleware stack. It handles the
// initialization of core services, registration of plugins, and the construction
// of the final, ordered middleware chain.
type MiddlewareManager struct {
	core    *CoreServices
	plugins []MiddlewarePlugin
	metrics *PerformanceMetrics
}

// NewManager creates a new middleware manager with the given configuration.
// It initializes all core services that will be shared across plugins.
func NewManager(config *UnifiedConfig, ctx context.Context, redisClient redis.Cmdable, auditWriter AuditWriter, apiResourceProvider ApiResourceProvider) (*MiddlewareManager, error) {
	// If no config is provided, use a sensible default.
	if config == nil {
		config = DefaultUnifiedConfig()
	}

	// If no context is provided, use a background context
	if ctx == nil {
		ctx = context.Background()
	}

	// Initialize performance metrics
	metrics := &PerformanceMetrics{
		lastReset: time.Now(),
	}

	// Initialize all core services.
	coreServices := &CoreServices{
		Config:            config,
		ContextManager:    keys.NewContextManager(),
		Context:           ctx,
		Redis:             redisClient,
		AuditWriter:       auditWriter,
		ApiResourceProvider: apiResourceProvider,
		Metrics:           metrics,
	}

	logx.Info("Middleware manager and core services initialized.")

	return &MiddlewareManager{
		core:    coreServices,
		plugins: make([]MiddlewarePlugin, 0),
		metrics: metrics,
	}, nil
}

// Register registers one or more middleware plugins with the manager.
// It calls the Init() method on each plugin, injecting the core services.
func (m *MiddlewareManager) Register(plugins ...MiddlewarePlugin) error {
	for _, p := range plugins {
		if err := p.Init(m.core); err != nil {
			return fmt.Errorf("failed to initialize plugin '%s': %w", p.Name(), err)
		}
		m.plugins = append(m.plugins, p)
		logx.Infof("Registered middleware plugin: %s (Priority: %d)", p.Name(), p.Priority())
	}
	return nil
}

// BuildChain constructs the final go-zero compatible middleware chain.
// It sorts the registered plugins by priority before chaining them.
func (m *MiddlewareManager) BuildChain() []rest.Middleware {
	// Sort plugins based on priority (lower value means higher priority).
	// This is crucial for ensuring middlewares like auth run before permission checks.
	sort.SliceStable(m.plugins, func(i, j int) bool {
		return m.plugins[i].Priority() < m.plugins[j].Priority()
	})

	// Build the chain of go-zero middlewares.
	chain := make([]rest.Middleware, len(m.plugins))
	for i, p := range m.plugins {
		// This closure captures the current plugin for each link in the chain.
		plugin := p
		chain[i] = func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()
				success := true
				
				// 使用panic recovery来捕获插件错误
				defer func() {
					if err := recover(); err != nil {
						success = false
						// 记录性能指标
						m.metrics.RecordPluginExecution(plugin.Name(), time.Since(start), success)
						panic(err) // 重新抛出panic
					} else {
						// 记录性能指标
						m.metrics.RecordPluginExecution(plugin.Name(), time.Since(start), success)
					}
				}()
				
				plugin.Handle(next)(w, r)
			}
		}
	}

	logx.Info("Middleware chain built successfully.")
	return chain
}

// GetCoreServices returns the shared core services container.
// This can be useful for other parts of the application that might need access
// to services like the object pool or metrics collector.
func (m *MiddlewareManager) GetCoreServices() *CoreServices {
	return m.core
}

// GetMetrics 获取性能指标
func (m *MiddlewareManager) GetMetrics() *PerformanceMetrics {
	return m.metrics
}

// ResetMetrics 重置性能指标
func (m *MiddlewareManager) ResetMetrics() {
	m.metrics.Reset()
}

// LogMetrics 记录性能指标到日志
func (m *MiddlewareManager) LogMetrics() {
	logx.Infow("Middleware Performance Metrics",
		logx.Field("total_requests", m.metrics.TotalRequests),
		logx.Field("auth_cache_hit_rate", m.metrics.GetCacheHitRate()),
		logx.Field("error_rate", m.metrics.GetErrorRate()),
		logx.Field("auth_avg_duration_ms", m.metrics.GetAverageDuration("auth")),
		logx.Field("tenant_avg_duration_ms", m.metrics.GetAverageDuration("tenant")),
		logx.Field("dataperm_avg_duration_ms", m.metrics.GetAverageDuration("dataperm")),
		logx.Field("audit_avg_duration_ms", m.metrics.GetAverageDuration("audit")),
		logx.Field("since_last_reset", time.Since(m.metrics.lastReset).String()))
}

// Shutdown gracefully shuts down all plugins that implement ShutdownablePlugin
func (m *MiddlewareManager) Shutdown() error {
	// 记录最终的性能指标
	m.LogMetrics()
	
	for _, p := range m.plugins {
		if shutdownable, ok := p.(ShutdownablePlugin); ok {
			if err := shutdownable.Shutdown(); err != nil {
				logx.Errorw("Failed to shutdown plugin", 
					logx.Field("plugin", p.Name()),
					logx.Field("error", err))
				// Continue shutting down other plugins even if one fails
			} else {
				logx.Infof("Plugin shutdown successfully: %s", p.Name())
			}
		}
	}
	return nil
}
