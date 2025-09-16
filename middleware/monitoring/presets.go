// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/framework"
)

// 预设监控配置和快速集成助手

// 创建生产环境监控设置
func CreateProductionMonitoringSetup() (*MonitoringManager, error) {
	config := &MonitoringConfig{
		Enabled:            true,
		SamplingRate:       1.0, // 生产环境全采样
		CollectionInterval: 30 * time.Second,
		AlertEnabled:       true,
		AlertCooldown:      5 * time.Minute,
		MetricStorage:      "memory",
		RetentionPeriod:    7 * 24 * time.Hour, // 保留7天数据
		LatencyThresholds: LatencyThresholds{
			P50Warning:  100 * time.Millisecond,
			P50Critical: 500 * time.Millisecond,
			P95Warning:  500 * time.Millisecond,
			P95Critical: 2 * time.Second,
			P99Warning:  2 * time.Second,
			P99Critical: 10 * time.Second,
		},
		ErrorThresholds: ErrorThresholds{
			WarningRate:  0.005, // 0.5%
			CriticalRate: 0.02,  // 2%
		},
		CacheThresholds: CacheThresholds{
			LowHitRateWarning:  0.85, // 85%
			LowHitRateCritical: 0.70, // 70%
			HighMemoryWarning:  0.75, // 75%
			HighMemoryCritical: 0.90, // 90%
		},
	}

	return NewMonitoringManager(config)
}

// 创建开发环境监控设置
func CreateDevelopmentMonitoringSetup() (*MonitoringManager, error) {
	config := &MonitoringConfig{
		Enabled:            true,
		SamplingRate:       0.1, // 开发环境降低采样率
		CollectionInterval: 10 * time.Second,
		AlertEnabled:       false, // 开发环境关闭告警
		AlertCooldown:      1 * time.Minute,
		MetricStorage:      "memory",
		RetentionPeriod:    1 * time.Hour, // 只保留1小时数据
		LatencyThresholds: LatencyThresholds{
			P50Warning:  200 * time.Millisecond,
			P50Critical: 1 * time.Second,
			P95Warning:  1 * time.Second,
			P95Critical: 5 * time.Second,
			P99Warning:  5 * time.Second,
			P99Critical: 30 * time.Second,
		},
		ErrorThresholds: ErrorThresholds{
			WarningRate:  0.05, // 5%
			CriticalRate: 0.20, // 20%
		},
		CacheThresholds: CacheThresholds{
			LowHitRateWarning:  0.60, // 60%
			LowHitRateCritical: 0.40, // 40%
			HighMemoryWarning:  0.90, // 90%
			HighMemoryCritical: 0.95, // 95%
		},
	}

	return NewMonitoringManager(config)
}

// 创建轻量级监控设置
func CreateLightweightMonitoringSetup() (*MonitoringManager, error) {
	config := &MonitoringConfig{
		Enabled:            true,
		SamplingRate:       0.01, // 1%采样率
		CollectionInterval: 60 * time.Second,
		AlertEnabled:       false,
		AlertCooldown:      5 * time.Minute,
		MetricStorage:      "memory",
		RetentionPeriod:    30 * time.Minute,
		LatencyThresholds: LatencyThresholds{
			P50Warning:  1 * time.Second,
			P50Critical: 5 * time.Second,
			P95Warning:  5 * time.Second,
			P95Critical: 30 * time.Second,
			P99Warning:  30 * time.Second,
			P99Critical: 60 * time.Second,
		},
		ErrorThresholds: ErrorThresholds{
			WarningRate:  0.10, // 10%
			CriticalRate: 0.50, // 50%
		},
		CacheThresholds: CacheThresholds{
			LowHitRateWarning:  0.30, // 30%
			LowHitRateCritical: 0.10, // 10%
			HighMemoryWarning:  0.95, // 95%
			HighMemoryCritical: 0.99, // 99%
		},
	}

	return NewMonitoringManager(config)
}

// 创建默认监控设置
func CreateDefaultMonitoringSetup() (*MonitoringManager, error) {
	return NewMonitoringManager(nil) // 使用默认配置
}

// 监控集成助手
type MonitoringIntegrator struct {
	manager *MonitoringManager
}

// 创建监控集成助手
func NewMonitoringIntegrator(manager *MonitoringManager) *MonitoringIntegrator {
	return &MonitoringIntegrator{
		manager: manager,
	}
}

// 自动集成中间件框架 (简化实现)
func (mi *MonitoringIntegrator) IntegrateMiddlewareFramework(plugins map[string]framework.MiddlewarePlugin) error {
	if plugins == nil {
		return fmt.Errorf("plugins map is nil")
	}

	for name, plugin := range plugins {
		// 包装每个插件进行监控
		priority := plugin.Priority()
		_ = mi.manager.WrapMiddleware(name, priority, plugin)
	}

	return nil
}

// 集成安全事件记录
func (mi *MonitoringIntegrator) IntegrateSecurityEventRecording(ctx context.Context) {
	// 这里可以注册全局的安全事件处理器
	// 实际实现需要根据具体的框架结构
}

// 监控报告生成器
type MonitoringReporter struct {
	manager *MonitoringManager
}

// 创建监控报告生成器
func NewMonitoringReporter(manager *MonitoringManager) *MonitoringReporter {
	return &MonitoringReporter{
		manager: manager,
	}
}

// 生成性能报告
func (mr *MonitoringReporter) GeneratePerformanceReport() *PerformanceReport {
	middlewareMetrics := mr.manager.performanceMonitor.GetAllMiddlewareMetrics()
	
	report := &PerformanceReport{
		GeneratedAt:     time.Now(),
		ReportPeriod:    "Current Session",
		MiddlewareStats: make(map[string]*MiddlewareStats),
		Summary:        &PerformanceSummary{},
	}
	
	totalRequests := int64(0)
	totalErrors := int64(0)
	var totalLatency time.Duration
	
	for name := range middlewareMetrics {
		stats, _ := mr.manager.performanceMonitor.CalculateMiddlewareStats(name)
		if stats != nil {
			report.MiddlewareStats[name] = stats
			
			totalRequests += stats.TotalRequests
			totalErrors += stats.ErrorCount
			totalLatency += stats.AverageLatency
		}
	}
	
	// 计算摘要
	if len(middlewareMetrics) > 0 {
		report.Summary.TotalRequests = totalRequests
		report.Summary.TotalErrors = totalErrors
		if totalRequests > 0 {
			report.Summary.OverallErrorRate = float64(totalErrors) / float64(totalRequests)
		}
		report.Summary.AverageLatency = time.Duration(int64(totalLatency) / int64(len(middlewareMetrics)))
	}
	
	return report
}

// 生成缓存报告
func (mr *MonitoringReporter) GenerateCacheReport() *CacheReport {
	cacheMetrics := mr.manager.cacheMonitor.GetAllCacheMetrics()
	
	report := &CacheReport{
		GeneratedAt:  time.Now(),
		ReportPeriod: "Current Session",
		CacheStats:   cacheMetrics,
		Summary:      &CacheSummary{},
	}
	
	totalHits := int64(0)
	totalMisses := int64(0)
	totalSize := int64(0)
	
	for _, metrics := range cacheMetrics {
		totalHits += metrics.HitCount
		totalMisses += metrics.MissCount
		totalSize += metrics.CurrentSize
	}
	
	// 计算摘要
	report.Summary.TotalCaches = len(cacheMetrics)
	report.Summary.TotalHits = totalHits
	report.Summary.TotalMisses = totalMisses
	report.Summary.TotalSize = totalSize
	
	if totalHits+totalMisses > 0 {
		report.Summary.OverallHitRate = float64(totalHits) / float64(totalHits+totalMisses)
	}
	
	return report
}

// 生成安全报告
func (mr *MonitoringReporter) GenerateSecurityReport() *SecurityReport {
	securityMetrics := mr.manager.securityMonitor.GetSecurityMetrics()
	violationEvents := mr.manager.securityMonitor.GetViolationEvents(100)
	suspiciousIPs := mr.manager.securityMonitor.GetSuspiciousIPs()
	
	report := &SecurityReport{
		GeneratedAt:      time.Now(),
		ReportPeriod:     "Current Session",
		SecurityMetrics:  securityMetrics,
		ViolationEvents:  violationEvents,
		SuspiciousIPs:    suspiciousIPs,
		Summary:         &SecuritySummary{},
	}
	
	// 计算摘要
	report.Summary.TotalViolations = securityMetrics.TenantViolations + 
									securityMetrics.AuthFailures + 
									securityMetrics.PermissionDenied
	report.Summary.SuspiciousIPCount = int64(len(suspiciousIPs))
	report.Summary.LastViolationTime = securityMetrics.LastViolationTime
	
	return report
}

// 生成综合健康报告
func (mr *MonitoringReporter) GenerateHealthReport() *ComprehensiveHealthReport {
	healthReport := mr.manager.GetHealthReport()
	overview := mr.manager.GetMonitoringOverview()
	
	return &ComprehensiveHealthReport{
		GeneratedAt:         time.Now(),
		OverallStatus:       healthReport.OverallStatus,
		MonitoringOverview:  overview,
		ComponentsHealth:    healthReport.Components,
		HealthSummary:      healthReport.Summary,
		Recommendations:    mr.generateHealthRecommendations(healthReport),
	}
}

// 生成健康建议
func (mr *MonitoringReporter) generateHealthRecommendations(health *HealthReport) []HealthRecommendation {
	var recommendations []HealthRecommendation
	
	// 检查不健康的组件
	for name, component := range health.Components {
		if component.Status == HealthStatusUnhealthy {
			recommendations = append(recommendations, HealthRecommendation{
				Priority:    "High",
				Component:   name,
				Issue:       fmt.Sprintf("Component %s is unhealthy", name),
				Suggestion:  fmt.Sprintf("Check logs and restart %s if necessary", name),
				Action:      "investigate_unhealthy_component",
			})
		} else if component.Status == HealthStatusDegraded {
			recommendations = append(recommendations, HealthRecommendation{
				Priority:    "Medium",
				Component:   name,
				Issue:       fmt.Sprintf("Component %s is degraded", name),
				Suggestion:  fmt.Sprintf("Monitor %s closely and consider optimization", name),
				Action:      "monitor_degraded_component",
			})
		}
	}
	
	// 检查缓存性能
	cacheMetrics := mr.manager.cacheMonitor.GetAllCacheMetrics()
	for name, cache := range cacheMetrics {
		if cache.HitRate < 0.7 {
			recommendations = append(recommendations, HealthRecommendation{
				Priority:   "Medium",
				Component:  name,
				Issue:      fmt.Sprintf("Cache %s has low hit rate: %.2f%%", name, cache.HitRate*100),
				Suggestion: "Review cache configuration and warm-up strategy",
				Action:     "optimize_cache_performance",
			})
		}
	}
	
	return recommendations
}

// 报告结构定义
type PerformanceReport struct {
	GeneratedAt     time.Time                   `json:"generated_at"`
	ReportPeriod    string                      `json:"report_period"`
	MiddlewareStats map[string]*MiddlewareStats `json:"middleware_stats"`
	Summary         *PerformanceSummary         `json:"summary"`
}

type PerformanceSummary struct {
	TotalRequests    int64         `json:"total_requests"`
	TotalErrors      int64         `json:"total_errors"`
	OverallErrorRate float64       `json:"overall_error_rate"`
	AverageLatency   time.Duration `json:"average_latency"`
}

type CacheReport struct {
	GeneratedAt  time.Time                   `json:"generated_at"`
	ReportPeriod string                      `json:"report_period"`
	CacheStats   map[string]*CacheMetrics    `json:"cache_stats"`
	Summary      *CacheSummary               `json:"summary"`
}

type CacheSummary struct {
	TotalCaches     int     `json:"total_caches"`
	TotalHits       int64   `json:"total_hits"`
	TotalMisses     int64   `json:"total_misses"`
	TotalSize       int64   `json:"total_size"`
	OverallHitRate  float64 `json:"overall_hit_rate"`
}

type SecurityReport struct {
	GeneratedAt     time.Time                  `json:"generated_at"`
	ReportPeriod    string                     `json:"report_period"`
	SecurityMetrics *SecurityMetrics           `json:"security_metrics"`
	ViolationEvents []SecurityViolationEvent   `json:"violation_events"`
	SuspiciousIPs   []string                   `json:"suspicious_ips"`
	Summary         *SecuritySummary           `json:"summary"`
}

type SecuritySummary struct {
	TotalViolations     int64     `json:"total_violations"`
	SuspiciousIPCount   int64     `json:"suspicious_ip_count"`
	LastViolationTime   time.Time `json:"last_violation_time"`
}

type ComprehensiveHealthReport struct {
	GeneratedAt        time.Time                      `json:"generated_at"`
	OverallStatus      HealthStatus                   `json:"overall_status"`
	MonitoringOverview *MonitoringOverview            `json:"monitoring_overview"`
	ComponentsHealth   map[string]ComponentHealth     `json:"components_health"`
	HealthSummary      HealthSummary                  `json:"health_summary"`
	Recommendations    []HealthRecommendation         `json:"recommendations"`
}

type HealthRecommendation struct {
	Priority   string `json:"priority"`
	Component  string `json:"component"`
	Issue      string `json:"issue"`
	Suggestion string `json:"suggestion"`
	Action     string `json:"action"`
}

// 监控最佳实践助手
type MonitoringBestPractices struct {
	manager *MonitoringManager
}

// 创建最佳实践助手
func NewMonitoringBestPractices(manager *MonitoringManager) *MonitoringBestPractices {
	return &MonitoringBestPractices{
		manager: manager,
	}
}

// 验证监控配置
func (mbp *MonitoringBestPractices) ValidateConfiguration() []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	config := mbp.manager.config
	
	// 检查采样率
	if config.SamplingRate <= 0 || config.SamplingRate > 1 {
		issues = append(issues, ConfigurationIssue{
			Severity:    "Error",
			Component:   "SamplingRate",
			Issue:       fmt.Sprintf("Invalid sampling rate: %.2f", config.SamplingRate),
			Suggestion:  "Sampling rate must be between 0.0 and 1.0",
		})
	}
	
	// 检查收集间隔
	if config.CollectionInterval < 10*time.Second {
		issues = append(issues, ConfigurationIssue{
			Severity:    "Warning",
			Component:   "CollectionInterval",
			Issue:       fmt.Sprintf("Very short collection interval: %v", config.CollectionInterval),
			Suggestion:  "Consider using a longer interval (>=30s) to reduce overhead",
		})
	}
	
	// 检查数据保留期
	if config.RetentionPeriod > 30*24*time.Hour {
		issues = append(issues, ConfigurationIssue{
			Severity:    "Warning",
			Component:   "RetentionPeriod",
			Issue:       fmt.Sprintf("Very long retention period: %v", config.RetentionPeriod),
			Suggestion:  "Long retention periods may consume significant memory",
		})
	}
	
	return issues
}

// 性能优化建议
func (mbp *MonitoringBestPractices) GetOptimizationSuggestions() []OptimizationSuggestion {
	var suggestions []OptimizationSuggestion
	
	// 分析中间件性能
	middlewareMetrics := mbp.manager.performanceMonitor.GetAllMiddlewareMetrics()
	for name, metrics := range middlewareMetrics {
		if metrics.RequestCount > 0 {
			avgLatency := time.Duration(int64(metrics.TotalLatency) / metrics.RequestCount)
			errorRate := float64(metrics.ErrorCount) / float64(metrics.RequestCount)
			
			if avgLatency > 100*time.Millisecond {
				suggestions = append(suggestions, OptimizationSuggestion{
					Priority:   "High",
					Component:  name,
					MetricType: "Latency",
					Issue:      fmt.Sprintf("High average latency: %v", avgLatency),
					Suggestion: "Consider optimizing middleware logic or adding caching",
				})
			}
			
			if errorRate > 0.05 {
				suggestions = append(suggestions, OptimizationSuggestion{
					Priority:   "High",
					Component:  name,
					MetricType: "ErrorRate",
					Issue:      fmt.Sprintf("High error rate: %.2f%%", errorRate*100),
					Suggestion: "Review error handling and add monitoring for specific error types",
				})
			}
		}
	}
	
	// 分析缓存性能
	cacheMetrics := mbp.manager.cacheMonitor.GetAllCacheMetrics()
	for name, cache := range cacheMetrics {
		if cache.HitRate < 0.8 {
			suggestions = append(suggestions, OptimizationSuggestion{
				Priority:   "Medium",
				Component:  name,
				MetricType: "CacheHitRate",
				Issue:      fmt.Sprintf("Low cache hit rate: %.2f%%", cache.HitRate*100),
				Suggestion: "Review cache TTL settings and consider cache warming strategies",
			})
		}
		
		if cache.SizeUsage > 0.9 {
			suggestions = append(suggestions, OptimizationSuggestion{
				Priority:   "Medium",
				Component:  name,
				MetricType: "CacheSize",
				Issue:      fmt.Sprintf("High cache memory usage: %.2f%%", cache.SizeUsage*100),
				Suggestion: "Consider increasing cache size or implementing better eviction policies",
			})
		}
	}
	
	return suggestions
}

type ConfigurationIssue struct {
	Severity   string `json:"severity"`
	Component  string `json:"component"`
	Issue      string `json:"issue"`
	Suggestion string `json:"suggestion"`
}

type OptimizationSuggestion struct {
	Priority   string `json:"priority"`
	Component  string `json:"component"`
	MetricType string `json:"metric_type"`
	Issue      string `json:"issue"`
	Suggestion string `json:"suggestion"`
}