// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/cache"
	"github.com/coder-lulu/newbee-common/middleware/framework"
)

// 监控管理器 - 统一管理所有监控组件
type MonitoringManager struct {
	config *MonitoringConfig
	
	// 核心监控组件
	metricCollector     MetricCollector
	performanceMonitor  *PerformanceMonitor
	cacheMonitor       *CacheMonitor
	securityMonitor    *SecurityMonitor
	systemMonitor      *SystemMonitor
	healthMonitor      *HealthMonitor
	alertManager       *AlertManager
	
	// 管理状态
	isRunning   bool
	startTime   time.Time
	mutex       sync.RWMutex
	
	// 停止信号
	stopChan    chan struct{}
	
	// HTTP服务器（可选的监控API）
	httpServer  *http.Server
}

// 系统监控器
type SystemMonitor struct {
	config    *MonitoringConfig
	collector MetricCollector
	
	// 系统指标
	systemMetrics *SystemMetrics
	metricsMutex  sync.RWMutex
	
	// 组件健康检查
	healthCheckers map[string]HealthChecker
	checkersMutex  sync.RWMutex
}

// 健康检查器接口
type HealthChecker interface {
	CheckHealth(ctx context.Context) *ComponentHealth
}

// 健康监控器
type HealthMonitor struct {
	config        *MonitoringConfig
	systemMonitor *SystemMonitor
	
	// 健康状态缓存
	healthCache   map[string]*ComponentHealth
	cacheMutex    sync.RWMutex
	cacheExpiry   time.Duration
}

// 告警管理器
type AlertManager struct {
	config         *MonitoringConfig
	
	// 告警规则
	rules          []AlertRule
	rulesMutex     sync.RWMutex
	
	// 活跃告警
	activeAlerts   map[string]*AlertEvent
	alertsMutex    sync.RWMutex
	
	// 告警通道
	alertChannels  []AlertChannel
	channelsMutex  sync.RWMutex
	
	// 告警抑制
	suppressions   map[string]time.Time
	suppressMutex  sync.RWMutex
}

// 告警规则
type AlertRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Condition   AlertCondition `json:"condition"`
	Severity    AlertSeverity `json:"severity"`
	Enabled     bool          `json:"enabled"`
	Cooldown    time.Duration `json:"cooldown"`
}

// 告警条件
type AlertCondition struct {
	MetricName string      `json:"metric_name"`
	Operator   string      `json:"operator"` // "gt", "lt", "eq", "ne"
	Threshold  interface{} `json:"threshold"`
	Duration   time.Duration `json:"duration"`
}

// 告警通道接口
type AlertChannel interface {
	SendAlert(ctx context.Context, alert *AlertEvent) error
}

// 创建监控管理器
func NewMonitoringManager(config *MonitoringConfig) (*MonitoringManager, error) {
	if config == nil {
		config = DefaultMonitoringConfig()
	}
	
	// 创建指标收集器
	var collector MetricCollector
	switch config.MetricStorage {
	case "memory":
		collector = NewMemoryMetricCollector(config)
	case "prometheus":
		// TODO: 实现Prometheus收集器
		collector = NewMemoryMetricCollector(config)
	default:
		collector = NewMemoryMetricCollector(config)
	}
	
	// 创建各个监控组件
	performanceMonitor := NewPerformanceMonitor(config, collector)
	cacheMonitor := NewCacheMonitor(config, collector)
	securityMonitor := NewSecurityMonitor(config, collector)
	
	systemMonitor := &SystemMonitor{
		config:         config,
		collector:      collector,
		systemMetrics:  &SystemMetrics{},
		healthCheckers: make(map[string]HealthChecker),
	}
	
	healthMonitor := &HealthMonitor{
		config:        config,
		systemMonitor: systemMonitor,
		healthCache:   make(map[string]*ComponentHealth),
		cacheExpiry:   30 * time.Second,
	}
	
	alertManager := &AlertManager{
		config:        config,
		rules:         make([]AlertRule, 0),
		activeAlerts:  make(map[string]*AlertEvent),
		alertChannels: make([]AlertChannel, 0),
		suppressions:  make(map[string]time.Time),
	}
	
	manager := &MonitoringManager{
		config:             config,
		metricCollector:    collector,
		performanceMonitor: performanceMonitor,
		cacheMonitor:       cacheMonitor,
		securityMonitor:    securityMonitor,
		systemMonitor:      systemMonitor,
		healthMonitor:      healthMonitor,
		alertManager:       alertManager,
		stopChan:           make(chan struct{}),
	}
	
	// 初始化默认告警规则
	manager.initializeDefaultAlertRules()
	
	return manager, nil
}

// 启动监控
func (mm *MonitoringManager) Start(ctx context.Context) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	
	if mm.isRunning {
		return fmt.Errorf("monitoring manager is already running")
	}
	
	mm.startTime = time.Now()
	mm.isRunning = true
	
	// 启动各个监控组件
	if err := mm.metricCollector.Start(ctx); err != nil {
		return fmt.Errorf("failed to start metric collector: %w", err)
	}
	
	if err := mm.cacheMonitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start cache monitor: %w", err)
	}
	
	// 启动系统监控
	go mm.runSystemMonitoring(ctx)
	
	// 启动告警检查
	go mm.runAlertChecking(ctx)
	
	// 启动HTTP监控API（如果配置了）
	if mm.config.MetricStorage == "http" || true { // 总是启动HTTP服务器
		mm.startHTTPServer()
	}
	
	return nil
}

// 停止监控
func (mm *MonitoringManager) Stop() error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	
	if !mm.isRunning {
		return nil
	}
	
	mm.isRunning = false
	close(mm.stopChan)
	
	// 停止HTTP服务器
	if mm.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		mm.httpServer.Shutdown(ctx)
	}
	
	// 停止各个监控组件
	mm.metricCollector.Stop()
	mm.cacheMonitor.Stop()
	
	return nil
}

// 包装中间件进行监控
func (mm *MonitoringManager) WrapMiddleware(name string, priority int, middleware framework.MiddlewarePlugin) framework.MiddlewarePlugin {
	return mm.performanceMonitor.WrapMiddleware(name, priority, middleware)
}

// 包装缓存进行监控
func (mm *MonitoringManager) WrapShardedCache(cache interface{}, name string) interface{} {
	return mm.cacheMonitor.WrapShardedCache(cache, name)
}

func (mm *MonitoringManager) WrapJWTCache(jwtCache *cache.HighPerformanceJWTCache, name string) *cache.HighPerformanceJWTCache {
	return mm.cacheMonitor.WrapJWTCache(jwtCache, name)
}

func (mm *MonitoringManager) WrapRedisCache(redisCache *cache.HighPerformanceRedisClient, name string) *cache.HighPerformanceRedisClient {
	return mm.cacheMonitor.WrapRedisCache(redisCache, name)
}

// 安全事件记录方法
func (mm *MonitoringManager) RecordTenantViolation(ctx context.Context, tenantID, userID, resource string, details map[string]interface{}) {
	mm.securityMonitor.RecordTenantViolation(ctx, tenantID, userID, resource, details)
}

func (mm *MonitoringManager) RecordAuthFailure(ctx context.Context, reason string, details map[string]interface{}) {
	mm.securityMonitor.RecordAuthFailure(ctx, reason, details)
}

func (mm *MonitoringManager) RecordPermissionViolation(ctx context.Context, tenantID, userID, resource, permission string, details map[string]interface{}) {
	mm.securityMonitor.RecordPermissionViolation(ctx, tenantID, userID, resource, permission, details)
}

func (mm *MonitoringManager) RecordRateLimitViolation(ctx context.Context, tenantID string, limit int, details map[string]interface{}) {
	mm.securityMonitor.RecordRateLimitViolation(ctx, tenantID, limit, details)
}

// 获取监控概览
func (mm *MonitoringManager) GetMonitoringOverview() *MonitoringOverview {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()
	
	overview := &MonitoringOverview{
		Status:           mm.getOverallStatus(),
		StartTime:        mm.startTime,
		Uptime:           time.Since(mm.startTime),
		LastUpdate:       time.Now(),
		ComponentsStatus: make(map[string]string),
	}
	
	// 获取各组件状态
	if mm.isRunning {
		overview.ComponentsStatus["metric_collector"] = "running"
		overview.ComponentsStatus["performance_monitor"] = "running"
		overview.ComponentsStatus["cache_monitor"] = "running"
		overview.ComponentsStatus["security_monitor"] = "running"
		overview.ComponentsStatus["system_monitor"] = "running"
		overview.ComponentsStatus["health_monitor"] = "running"
		overview.ComponentsStatus["alert_manager"] = "running"
	} else {
		for component := range overview.ComponentsStatus {
			overview.ComponentsStatus[component] = "stopped"
		}
	}
	
	// 获取活跃告警数量
	overview.ActiveAlertsCount = len(mm.alertManager.activeAlerts)
	
	return overview
}

// 监控概览
type MonitoringOverview struct {
	Status             string            `json:"status"`
	StartTime          time.Time         `json:"start_time"`
	Uptime             time.Duration     `json:"uptime"`
	LastUpdate         time.Time         `json:"last_update"`
	ComponentsStatus   map[string]string `json:"components_status"`
	ActiveAlertsCount  int               `json:"active_alerts_count"`
}

// 获取健康报告
func (mm *MonitoringManager) GetHealthReport() *HealthReport {
	return mm.healthMonitor.GetHealthReport()
}

// 运行系统监控
func (mm *MonitoringManager) runSystemMonitoring(ctx context.Context) {
	ticker := time.NewTicker(mm.config.CollectionInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mm.systemMonitor.collectSystemMetrics()
			mm.healthMonitor.updateHealthStatus()
		case <-mm.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// 运行告警检查
func (mm *MonitoringManager) runAlertChecking(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // 每30秒检查一次告警
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mm.checkAlerts()
		case <-mm.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// 检查告警
func (mm *MonitoringManager) checkAlerts() {
	mm.alertManager.rulesMutex.RLock()
	rules := make([]AlertRule, len(mm.alertManager.rules))
	copy(rules, mm.alertManager.rules)
	mm.alertManager.rulesMutex.RUnlock()
	
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		
		if mm.shouldTriggerAlert(rule) {
			mm.triggerAlert(rule)
		}
	}
	
	// 检查告警恢复
	mm.checkAlertRecovery()
}

// 判断是否应该触发告警
func (mm *MonitoringManager) shouldTriggerAlert(rule AlertRule) bool {
	// 检查抑制状态
	mm.alertManager.suppressMutex.RLock()
	if suppressUntil, exists := mm.alertManager.suppressions[rule.ID]; exists {
		if time.Now().Before(suppressUntil) {
			mm.alertManager.suppressMutex.RUnlock()
			return false
		}
		// 清理过期的抑制
		delete(mm.alertManager.suppressions, rule.ID)
	}
	mm.alertManager.suppressMutex.RUnlock()
	
	// 获取指标值
	metricValue := mm.getMetricValue(rule.Condition.MetricName)
	if metricValue == nil {
		return false
	}
	
	// 检查阈值条件
	return mm.evaluateCondition(metricValue, rule.Condition)
}

// 触发告警
func (mm *MonitoringManager) triggerAlert(rule AlertRule) {
	alert := &AlertEvent{
		ID:          fmt.Sprintf("%s-%d", rule.ID, time.Now().UnixNano()),
		Severity:    rule.Severity,
		Title:       rule.Name,
		Description: rule.Description,
		Component:   "monitoring",
		Metric:      rule.Condition.MetricName,
		Timestamp:   time.Now(),
		Resolved:    false,
	}
	
	// 记录活跃告警
	mm.alertManager.alertsMutex.Lock()
	mm.alertManager.activeAlerts[alert.ID] = alert
	mm.alertManager.alertsMutex.Unlock()
	
	// 发送告警
	mm.sendAlert(alert)
	
	// 设置抑制
	if rule.Cooldown > 0 {
		mm.alertManager.suppressMutex.Lock()
		mm.alertManager.suppressions[rule.ID] = time.Now().Add(rule.Cooldown)
		mm.alertManager.suppressMutex.Unlock()
	}
}

// 发送告警
func (mm *MonitoringManager) sendAlert(alert *AlertEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	mm.alertManager.channelsMutex.RLock()
	channels := make([]AlertChannel, len(mm.alertManager.alertChannels))
	copy(channels, mm.alertManager.alertChannels)
	mm.alertManager.channelsMutex.RUnlock()
	
	for _, channel := range channels {
		go func(ch AlertChannel, alertCopy *AlertEvent) {
			if err := ch.SendAlert(ctx, alertCopy); err != nil {
				// 记录发送失败，但不阻塞
				fmt.Printf("Failed to send alert via channel: %v\n", err)
			}
		}(channel, alert)
	}
}

// 检查告警恢复
func (mm *MonitoringManager) checkAlertRecovery() {
	mm.alertManager.alertsMutex.Lock()
	defer mm.alertManager.alertsMutex.Unlock()
	
	now := time.Now()
	for alertID, alert := range mm.alertManager.activeAlerts {
		if alert.Resolved {
			continue
		}
		
		// 检查指标是否恢复正常
		if mm.isMetricHealthy(alert.Metric) {
			alert.Resolved = true
			resolvedAt := now
			alert.ResolvedAt = &resolvedAt
			
			// 发送恢复通知
			mm.sendAlert(alert)
			
			// 从活跃告警中移除
			delete(mm.alertManager.activeAlerts, alertID)
		}
	}
}

// 启动HTTP监控服务器
func (mm *MonitoringManager) startHTTPServer() {
	mux := http.NewServeMux()
	
	// 监控概览
	mux.HandleFunc("/monitoring/overview", mm.handleOverview)
	
	// 指标端点
	mux.HandleFunc("/monitoring/metrics", mm.handleMetrics)
	
	// 健康检查
	mux.HandleFunc("/monitoring/health", mm.handleHealth)
	
	// 中间件性能指标
	mux.HandleFunc("/monitoring/middleware", mm.handleMiddlewareMetrics)
	
	// 缓存指标
	mux.HandleFunc("/monitoring/cache", mm.handleCacheMetrics)
	
	// 安全指标
	mux.HandleFunc("/monitoring/security", mm.handleSecurityMetrics)
	
	// 告警管理
	mux.HandleFunc("/monitoring/alerts", mm.handleAlerts)
	
	mm.httpServer = &http.Server{
		Addr:         ":9090", // 可配置
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	
	go func() {
		if err := mm.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Monitoring HTTP server error: %v\n", err)
		}
	}()
}

// HTTP处理器实现
func (mm *MonitoringManager) handleOverview(w http.ResponseWriter, r *http.Request) {
	overview := mm.GetMonitoringOverview()
	mm.writeJSONResponse(w, overview)
}

func (mm *MonitoringManager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := mm.metricCollector.GetMetrics()
	mm.writeJSONResponse(w, metrics)
}

func (mm *MonitoringManager) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := mm.GetHealthReport()
	mm.writeJSONResponse(w, health)
}

func (mm *MonitoringManager) handleMiddlewareMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := mm.performanceMonitor.GetAllMiddlewareMetrics()
	mm.writeJSONResponse(w, metrics)
}

func (mm *MonitoringManager) handleCacheMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := mm.cacheMonitor.GetAllCacheMetrics()
	mm.writeJSONResponse(w, metrics)
}

func (mm *MonitoringManager) handleSecurityMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := mm.securityMonitor.GetSecurityMetrics()
	mm.writeJSONResponse(w, metrics)
}

func (mm *MonitoringManager) handleAlerts(w http.ResponseWriter, r *http.Request) {
	mm.alertManager.alertsMutex.RLock()
	alerts := make([]*AlertEvent, 0, len(mm.alertManager.activeAlerts))
	for _, alert := range mm.alertManager.activeAlerts {
		alerts = append(alerts, alert)
	}
	mm.alertManager.alertsMutex.RUnlock()
	
	mm.writeJSONResponse(w, alerts)
}

func (mm *MonitoringManager) writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// 辅助方法
func (mm *MonitoringManager) getOverallStatus() string {
	if !mm.isRunning {
		return "stopped"
	}
	
	health := mm.healthMonitor.GetHealthReport()
	switch health.OverallStatus {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

func (mm *MonitoringManager) getMetricValue(metricName string) interface{} {
	// 从指标收集器获取指标值
	// 这里需要根据具体的指标名称来获取对应的值
	metrics := mm.metricCollector.GetMetrics()
	
	// 简化实现，实际应该支持更复杂的指标查询
	if counters, ok := metrics["counters"].(map[string]int64); ok {
		if value, exists := counters[metricName]; exists {
			return value
		}
	}
	
	if gauges, ok := metrics["gauges"].(map[string]float64); ok {
		if value, exists := gauges[metricName]; exists {
			return value
		}
	}
	
	return nil
}

func (mm *MonitoringManager) evaluateCondition(value interface{}, condition AlertCondition) bool {
	// 简化的条件评估实现
	switch condition.Operator {
	case "gt":
		if threshold, ok := condition.Threshold.(float64); ok {
			if val, ok := value.(float64); ok {
				return val > threshold
			}
		}
	case "lt":
		if threshold, ok := condition.Threshold.(float64); ok {
			if val, ok := value.(float64); ok {
				return val < threshold
			}
		}
	}
	return false
}

func (mm *MonitoringManager) isMetricHealthy(metricName string) bool {
	// 简化实现：检查指标是否恢复正常
	return true // 实际应该根据指标值判断
}

// 初始化默认告警规则
func (mm *MonitoringManager) initializeDefaultAlertRules() {
	defaultRules := []AlertRule{
		{
			ID:          "high_error_rate",
			Name:        "High Error Rate",
			Description: "Error rate exceeds threshold",
			Condition: AlertCondition{
				MetricName: "middleware_errors_total",
				Operator:   "gt",
				Threshold:  100.0,
				Duration:   5 * time.Minute,
			},
			Severity: AlertSeverityHigh,
			Enabled:  true,
			Cooldown: 5 * time.Minute,
		},
		{
			ID:          "low_cache_hit_rate",
			Name:        "Low Cache Hit Rate",
			Description: "Cache hit rate is below threshold",
			Condition: AlertCondition{
				MetricName: "cache_hit_rate",
				Operator:   "lt",
				Threshold:  0.8,
				Duration:   2 * time.Minute,
			},
			Severity: AlertSeverityMedium,
			Enabled:  true,
			Cooldown: 10 * time.Minute,
		},
	}
	
	mm.alertManager.rulesMutex.Lock()
	mm.alertManager.rules = defaultRules
	mm.alertManager.rulesMutex.Unlock()
}

// 系统监控器实现
func (sm *SystemMonitor) collectSystemMetrics() {
	sm.metricsMutex.Lock()
	defer sm.metricsMutex.Unlock()
	
	// 收集系统指标（简化实现）
	sm.systemMetrics.LastHealthCheck = time.Now()
	sm.systemMetrics.MemoryUsage = 0.5  // 模拟值
	sm.systemMetrics.CPUUsage = 0.3     // 模拟值
	sm.systemMetrics.GoroutineCount = 100 // 模拟值
	
	// 记录到指标收集器
	labels := map[string]string{"component": "system"}
	sm.collector.SetGauge("system_memory_usage", labels, sm.systemMetrics.MemoryUsage)
	sm.collector.SetGauge("system_cpu_usage", labels, sm.systemMetrics.CPUUsage)
	sm.collector.SetGauge("system_goroutines", labels, float64(sm.systemMetrics.GoroutineCount))
}

// 健康监控器实现
func (hm *HealthMonitor) GetHealthReport() *HealthReport {
	hm.cacheMutex.Lock()
	defer hm.cacheMutex.Unlock()
	
	components := make(map[string]ComponentHealth)
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	unknownCount := 0
	
	// 收集所有组件的健康状态
	for name, health := range hm.healthCache {
		components[name] = *health
		switch health.Status {
		case HealthStatusHealthy:
			healthyCount++
		case HealthStatusDegraded:
			degradedCount++
		case HealthStatusUnhealthy:
			unhealthyCount++
		default:
			unknownCount++
		}
	}
	
	// 确定整体状态
	overallStatus := HealthStatusHealthy
	if unhealthyCount > 0 {
		overallStatus = HealthStatusUnhealthy
	} else if degradedCount > 0 {
		overallStatus = HealthStatusDegraded
	} else if unknownCount > 0 && healthyCount == 0 {
		overallStatus = HealthStatusUnknown
	}
	
	return &HealthReport{
		OverallStatus: overallStatus,
		CheckTime:     time.Now(),
		Components:    components,
		Summary: HealthSummary{
			TotalComponents:     len(components),
			HealthyComponents:   healthyCount,
			DegradedComponents:  degradedCount,
			UnhealthyComponents: unhealthyCount,
			UnknownComponents:   unknownCount,
		},
	}
}

func (hm *HealthMonitor) updateHealthStatus() {
	hm.systemMonitor.checkersMutex.RLock()
	checkers := make(map[string]HealthChecker)
	for name, checker := range hm.systemMonitor.healthCheckers {
		checkers[name] = checker
	}
	hm.systemMonitor.checkersMutex.RUnlock()
	
	hm.cacheMutex.Lock()
	defer hm.cacheMutex.Unlock()
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	for name, checker := range checkers {
		health := checker.CheckHealth(ctx)
		hm.healthCache[name] = health
	}
}