// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/framework"
)

// 性能监控器
type PerformanceMonitor struct {
	config    *MonitoringConfig
	collector MetricCollector
	
	// 中间件指标存储
	middlewareMetrics map[string]*MiddlewareMetrics
	metricsMutex      sync.RWMutex
	
	// 请求追踪
	activeRequests map[string]*RequestTracker
	trackerMutex   sync.RWMutex
}

// 请求追踪器
type RequestTracker struct {
	RequestID     string
	StartTime     time.Time
	MiddlewarePath []MiddlewareStep
	Context       context.Context
}

// 中间件执行步骤
type MiddlewareStep struct {
	Name      string
	Priority  int
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Error     error
	Success   bool
}

// 创建性能监控器
func NewPerformanceMonitor(config *MonitoringConfig, collector MetricCollector) *PerformanceMonitor {
	return &PerformanceMonitor{
		config:            config,
		collector:         collector,
		middlewareMetrics: make(map[string]*MiddlewareMetrics),
		activeRequests:    make(map[string]*RequestTracker),
	}
}

// 包装中间件以进行性能监控
func (pm *PerformanceMonitor) WrapMiddleware(name string, priority int, middleware framework.MiddlewarePlugin) framework.MiddlewarePlugin {
	return &MonitoredMiddleware{
		name:     name,
		priority: priority,
		wrapped:  middleware,
		monitor:  pm,
	}
}

// 包装HTTP处理函数
func (pm *PerformanceMonitor) WrapHandler(name string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := pm.generateRequestID(r)
		
		// 开始请求追踪
		pm.startRequestTracking(requestID, r.Context())
		
		// 包装ResponseWriter以捕获状态码
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}
		
		// 执行处理函数
		handler(wrappedWriter, r)
		
		// 记录性能指标
		duration := time.Since(startTime)
		pm.recordHandlerMetrics(name, duration, wrappedWriter.statusCode)
		
		// 结束请求追踪
		pm.endRequestTracking(requestID)
	}
}

// 监控的中间件
type MonitoredMiddleware struct {
	name     string
	priority int
	wrapped  framework.MiddlewarePlugin
	monitor  *PerformanceMonitor
}

func (mm *MonitoredMiddleware) Name() string {
	return mm.wrapped.Name()
}

func (mm *MonitoredMiddleware) Priority() int {
	return mm.wrapped.Priority()
}

func (mm *MonitoredMiddleware) Init(core *framework.CoreServices) error {
	return mm.wrapped.Init(core)
}

func (mm *MonitoredMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	wrappedNext := mm.wrapped.Handle(next)
	
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := mm.monitor.generateRequestID(r)
		
		// 开始中间件执行追踪
		mm.monitor.startMiddlewareExecution(requestID, mm.name, mm.priority)
		
		// 包装ResponseWriter以捕获错误
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}
		
		// 执行中间件
		var middlewareError error
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					middlewareError = fmt.Errorf("middleware panic: %v", recovered)
					http.Error(w, "Internal Server Error", 500)
				}
			}()
			
			wrappedNext(wrappedWriter, r)
		}()
		
		// 记录执行结果
		duration := time.Since(startTime)
		success := middlewareError == nil && wrappedWriter.statusCode < 400
		
		mm.monitor.endMiddlewareExecution(requestID, mm.name, duration, success, middlewareError)
		mm.monitor.recordMiddlewareMetrics(mm.name, duration, success, wrappedWriter.statusCode)
	}
}

// 响应写入器包装
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// 生成请求ID
func (pm *PerformanceMonitor) generateRequestID(r *http.Request) string {
	// 尝试从头部获取请求ID
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		return requestID
	}
	
	// 生成新的请求ID
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
}

// 开始请求追踪
func (pm *PerformanceMonitor) startRequestTracking(requestID string, ctx context.Context) {
	tracker := &RequestTracker{
		RequestID:      requestID,
		StartTime:      time.Now(),
		MiddlewarePath: make([]MiddlewareStep, 0),
		Context:        ctx,
	}
	
	pm.trackerMutex.Lock()
	pm.activeRequests[requestID] = tracker
	pm.trackerMutex.Unlock()
}

// 结束请求追踪
func (pm *PerformanceMonitor) endRequestTracking(requestID string) {
	pm.trackerMutex.Lock()
	delete(pm.activeRequests, requestID)
	pm.trackerMutex.Unlock()
}

// 开始中间件执行
func (pm *PerformanceMonitor) startMiddlewareExecution(requestID, middlewareName string, priority int) {
	pm.trackerMutex.RLock()
	tracker, exists := pm.activeRequests[requestID]
	pm.trackerMutex.RUnlock()
	
	if !exists {
		return
	}
	
	step := MiddlewareStep{
		Name:      middlewareName,
		Priority:  priority,
		StartTime: time.Now(),
	}
	
	// 这里需要锁保护，因为可能并发访问
	pm.trackerMutex.Lock()
	tracker.MiddlewarePath = append(tracker.MiddlewarePath, step)
	pm.trackerMutex.Unlock()
}

// 结束中间件执行
func (pm *PerformanceMonitor) endMiddlewareExecution(requestID, middlewareName string, duration time.Duration, success bool, err error) {
	pm.trackerMutex.Lock()
	defer pm.trackerMutex.Unlock()
	
	tracker, exists := pm.activeRequests[requestID]
	if !exists {
		return
	}
	
	// 查找对应的中间件步骤并更新
	for i := len(tracker.MiddlewarePath) - 1; i >= 0; i-- {
		step := &tracker.MiddlewarePath[i]
		if step.Name == middlewareName && step.EndTime.IsZero() {
			step.EndTime = time.Now()
			step.Duration = duration
			step.Success = success
			step.Error = err
			break
		}
	}
}

// 记录中间件指标
func (pm *PerformanceMonitor) recordMiddlewareMetrics(middlewareName string, duration time.Duration, success bool, statusCode int) {
	// 获取或创建中间件指标
	pm.metricsMutex.RLock()
	metrics, exists := pm.middlewareMetrics[middlewareName]
	pm.metricsMutex.RUnlock()
	
	if !exists {
		pm.metricsMutex.Lock()
		if metrics, exists = pm.middlewareMetrics[middlewareName]; !exists {
			metrics = &MiddlewareMetrics{
				MiddlewareName: middlewareName,
				StartTime:      time.Now(),
			}
			pm.middlewareMetrics[middlewareName] = metrics
		}
		pm.metricsMutex.Unlock()
	}
	
	// 更新指标
	pm.metricsMutex.Lock()
	metrics.RequestCount++
	metrics.TotalLatency += duration
	metrics.LastLatency = duration
	metrics.LastUpdate = time.Now()
	
	if duration > metrics.MaxLatency {
		metrics.MaxLatency = duration
	}
	
	if success {
		metrics.SuccessCount++
	} else {
		metrics.ErrorCount++
		
		// 分类错误类型
		switch {
		case statusCode == 401 || statusCode == 403:
			metrics.AuthErrors++
		case statusCode == 404:
			metrics.TenantErrors++
		case statusCode >= 400 && statusCode < 500:
			metrics.PermissionErrors++
		default:
			metrics.SystemErrors++
		}
	}
	pm.metricsMutex.Unlock()
	
	// 记录到指标收集器
	labels := map[string]string{
		"middleware": middlewareName,
		"success":    fmt.Sprintf("%t", success),
		"status":     fmt.Sprintf("%d", statusCode),
	}
	
	pm.collector.IncrementCounter("middleware_requests_total", labels, 1)
	pm.collector.RecordHistogram("middleware_duration_seconds", labels, duration)
	
	if !success {
		pm.collector.IncrementCounter("middleware_errors_total", labels, 1)
	}
}

// 记录处理器指标
func (pm *PerformanceMonitor) recordHandlerMetrics(handlerName string, duration time.Duration, statusCode int) {
	labels := map[string]string{
		"handler": handlerName,
		"status":  fmt.Sprintf("%d", statusCode),
	}
	
	pm.collector.IncrementCounter("handler_requests_total", labels, 1)
	pm.collector.RecordHistogram("handler_duration_seconds", labels, duration)
	
	if statusCode >= 400 {
		pm.collector.IncrementCounter("handler_errors_total", labels, 1)
	}
}

// 获取中间件指标
func (pm *PerformanceMonitor) GetMiddlewareMetrics(middlewareName string) *MiddlewareMetrics {
	pm.metricsMutex.RLock()
	defer pm.metricsMutex.RUnlock()
	
	metrics, exists := pm.middlewareMetrics[middlewareName]
	if !exists {
		return nil
	}
	
	// 返回副本以避免并发访问问题
	return &MiddlewareMetrics{
		MiddlewareName:   metrics.MiddlewareName,
		Priority:         metrics.Priority,
		RequestCount:     metrics.RequestCount,
		SuccessCount:     metrics.SuccessCount,
		ErrorCount:       metrics.ErrorCount,
		TotalLatency:     metrics.TotalLatency,
		LastLatency:      metrics.LastLatency,
		MaxLatency:       metrics.MaxLatency,
		AuthErrors:       metrics.AuthErrors,
		TenantErrors:     metrics.TenantErrors,
		PermissionErrors: metrics.PermissionErrors,
		SystemErrors:     metrics.SystemErrors,
		LastUpdate:       metrics.LastUpdate,
		StartTime:        metrics.StartTime,
	}
}

// 获取所有中间件指标
func (pm *PerformanceMonitor) GetAllMiddlewareMetrics() map[string]*MiddlewareMetrics {
	pm.metricsMutex.RLock()
	defer pm.metricsMutex.RUnlock()
	
	result := make(map[string]*MiddlewareMetrics, len(pm.middlewareMetrics))
	for name, metrics := range pm.middlewareMetrics {
		result[name] = &MiddlewareMetrics{
			MiddlewareName:   metrics.MiddlewareName,
			Priority:         metrics.Priority,
			RequestCount:     metrics.RequestCount,
			SuccessCount:     metrics.SuccessCount,
			ErrorCount:       metrics.ErrorCount,
			TotalLatency:     metrics.TotalLatency,
			LastLatency:      metrics.LastLatency,
			MaxLatency:       metrics.MaxLatency,
			AuthErrors:       metrics.AuthErrors,
			TenantErrors:     metrics.TenantErrors,
			PermissionErrors: metrics.PermissionErrors,
			SystemErrors:     metrics.SystemErrors,
			LastUpdate:       metrics.LastUpdate,
			StartTime:        metrics.StartTime,
		}
	}
	return result
}

// 计算中间件性能统计
func (pm *PerformanceMonitor) CalculateMiddlewareStats(middlewareName string) (*MiddlewareStats, error) {
	metrics := pm.GetMiddlewareMetrics(middlewareName)
	if metrics == nil {
		return nil, fmt.Errorf("middleware %s not found", middlewareName)
	}
	
	// 从指标收集器获取分位数数据
	histogramLabels := map[string]string{"middleware": middlewareName}
	histogramData := pm.collector.GetHistogram("middleware_duration_seconds", histogramLabels)
	
	stats := &MiddlewareStats{
		MiddlewareName: middlewareName,
		TotalRequests:  metrics.RequestCount,
		SuccessCount:   metrics.SuccessCount,
		ErrorCount:     metrics.ErrorCount,
		ErrorRate:      float64(metrics.ErrorCount) / float64(metrics.RequestCount),
		AverageLatency: time.Duration(float64(metrics.TotalLatency) / float64(metrics.RequestCount)),
		MaxLatency:     metrics.MaxLatency,
		LastLatency:    metrics.LastLatency,
		P50Latency:     histogramData.P50,
		P95Latency:     histogramData.P95,
		P99Latency:     histogramData.P99,
		StartTime:      metrics.StartTime,
		LastUpdate:     metrics.LastUpdate,
	}
	
	return stats, nil
}

// 中间件统计信息
type MiddlewareStats struct {
	MiddlewareName string        `json:"middleware_name"`
	TotalRequests  int64         `json:"total_requests"`
	SuccessCount   int64         `json:"success_count"`
	ErrorCount     int64         `json:"error_count"`
	ErrorRate      float64       `json:"error_rate"`
	AverageLatency time.Duration `json:"average_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	LastLatency    time.Duration `json:"last_latency"`
	P50Latency     time.Duration `json:"p50_latency"`
	P95Latency     time.Duration `json:"p95_latency"`
	P99Latency     time.Duration `json:"p99_latency"`
	StartTime      time.Time     `json:"start_time"`
	LastUpdate     time.Time     `json:"last_update"`
}

// 获取活跃请求数量
func (pm *PerformanceMonitor) GetActiveRequestCount() int {
	pm.trackerMutex.RLock()
	defer pm.trackerMutex.RUnlock()
	return len(pm.activeRequests)
}

// 获取请求追踪信息
func (pm *PerformanceMonitor) GetRequestTracker(requestID string) *RequestTracker {
	pm.trackerMutex.RLock()
	defer pm.trackerMutex.RUnlock()
	
	tracker, exists := pm.activeRequests[requestID]
	if !exists {
		return nil
	}
	
	// 返回副本
	trackerCopy := &RequestTracker{
		RequestID:      tracker.RequestID,
		StartTime:      tracker.StartTime,
		Context:        tracker.Context,
		MiddlewarePath: make([]MiddlewareStep, len(tracker.MiddlewarePath)),
	}
	copy(trackerCopy.MiddlewarePath, tracker.MiddlewarePath)
	
	return trackerCopy
}