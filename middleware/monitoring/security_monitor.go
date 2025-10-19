// Copyright 2024 The NewBee Authors. All Rights Reserved.

package monitoring

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// 安全监控器
type SecurityMonitor struct {
	config    *MonitoringConfig
	collector MetricCollector
	
	// 安全指标
	securityMetrics *SecurityMetrics
	metricsMutex    sync.RWMutex
	
	// IP行为分析
	ipAnalyzer      *IPBehaviorAnalyzer
	
	// 违规事件缓存（用于分析模式）
	violationEvents []SecurityViolationEvent
	eventsMutex     sync.RWMutex
	maxEvents       int
	
	// 异常检测
	anomalyDetector *AnomalyDetector
}

// 安全违规事件
type SecurityViolationEvent struct {
	EventID       string                 `json:"event_id"`
	Timestamp     time.Time              `json:"timestamp"`
	ViolationType SecurityViolationType  `json:"violation_type"`
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id"`
	ClientIP      string                 `json:"client_ip"`
	Resource      string                 `json:"resource"`
	Details       map[string]interface{} `json:"details"`
	Severity      AlertSeverity          `json:"severity"`
}

// 安全违规类型
type SecurityViolationType string

const (
	ViolationTypeTenantCross    SecurityViolationType = "tenant_cross_access"
	ViolationTypePermissionDenied SecurityViolationType = "permission_denied"
	ViolationTypeAuthFailure     SecurityViolationType = "auth_failure"
	ViolationTypeRateLimit       SecurityViolationType = "rate_limit_exceeded"
	ViolationTypeInvalidToken    SecurityViolationType = "invalid_token"
	ViolationTypeExpiredToken    SecurityViolationType = "expired_token"
	ViolationTypeMalformedToken  SecurityViolationType = "malformed_token"
	ViolationTypeSuspiciousIP    SecurityViolationType = "suspicious_ip"
	ViolationTypeAbnormalPattern SecurityViolationType = "abnormal_pattern"
)

// IP行为分析器
type IPBehaviorAnalyzer struct {
	// IP访问统计
	ipStats         map[string]*IPStats
	statsMutex      sync.RWMutex
	
	// 分析配置
	maxFailuresPerIP    int
	maxRequestsPerMinute int
	suspiciousThreshold  float64
}

// IP统计信息
type IPStats struct {
	IP                string        `json:"ip"`
	FirstSeen         time.Time     `json:"first_seen"`
	LastSeen          time.Time     `json:"last_seen"`
	TotalRequests     int64         `json:"total_requests"`
	FailedRequests    int64         `json:"failed_requests"`
	SuccessRate       float64       `json:"success_rate"`
	RequestsPerMinute float64       `json:"requests_per_minute"`
	Countries         map[string]int `json:"countries"`
	UserAgents        map[string]int `json:"user_agents"`
	AccessedTenants   map[string]int `json:"accessed_tenants"`
	ViolationCount    int           `json:"violation_count"`
	IsSuspicious      bool          `json:"is_suspicious"`
	RiskScore         float64       `json:"risk_score"`
}

// 异常检测器
type AnomalyDetector struct {
	// 基线统计
	baselineRequests    int64
	baselineFailures    int64
	baselineLatency     time.Duration
	baselineUpdateTime  time.Time
	
	// 检测阈值
	requestSpikeFactor  float64 // 请求数激增因子
	failureSpikeFactor  float64 // 失败率激增因子
	latencySpikeFactor  float64 // 延迟激增因子
}

// 创建安全监控器
func NewSecurityMonitor(config *MonitoringConfig, collector MetricCollector) *SecurityMonitor {
	return &SecurityMonitor{
		config:    config,
		collector: collector,
		securityMetrics: &SecurityMetrics{
			LastViolationTime: time.Time{},
		},
		ipAnalyzer: &IPBehaviorAnalyzer{
			ipStats:              make(map[string]*IPStats),
			maxFailuresPerIP:     50,  // 每小时最大失败次数
			maxRequestsPerMinute: 100, // 每分钟最大请求数
			suspiciousThreshold:  0.7, // 风险分数阈值
		},
		violationEvents: make([]SecurityViolationEvent, 0, 1000),
		maxEvents:       1000,
		anomalyDetector: &AnomalyDetector{
			requestSpikeFactor: 3.0, // 请求数超过基线3倍算异常
			failureSpikeFactor: 5.0, // 失败率超过基线5倍算异常
			latencySpikeFactor: 2.0, // 延迟超过基线2倍算异常
		},
	}
}

// 记录租户违规
func (sm *SecurityMonitor) RecordTenantViolation(ctx context.Context, tenantID, userID, resource string, details map[string]interface{}) {
	clientIP := sm.extractClientIP(ctx)
	
	event := SecurityViolationEvent{
		EventID:       sm.generateEventID(),
		Timestamp:     time.Now(),
		ViolationType: ViolationTypeTenantCross,
		TenantID:      tenantID,
		UserID:        userID,
		ClientIP:      clientIP,
		Resource:      resource,
		Details:       details,
		Severity:      AlertSeverityHigh,
	}
	
	sm.recordViolationEvent(event)
	
	// 更新指标
	sm.metricsMutex.Lock()
	sm.securityMetrics.TenantViolations++
	sm.securityMetrics.CrossTenantAttempts++
	sm.securityMetrics.LastViolationTime = time.Now()
	sm.metricsMutex.Unlock()
	
	// 记录到指标收集器
	labels := map[string]string{
		"violation_type": string(ViolationTypeTenantCross),
		"tenant_id":      tenantID,
		"client_ip":      clientIP,
	}
	sm.collector.IncrementCounter("security_violations_total", labels, 1)
}

// 记录认证失败
func (sm *SecurityMonitor) RecordAuthFailure(ctx context.Context, reason string, details map[string]interface{}) {
	clientIP := sm.extractClientIP(ctx)
	violationType := sm.mapAuthFailureReason(reason)
	
	event := SecurityViolationEvent{
		EventID:       sm.generateEventID(),
		Timestamp:     time.Now(),
		ViolationType: violationType,
		ClientIP:      clientIP,
		Details:       details,
		Severity:      sm.determineSeverity(violationType),
	}
	
	sm.recordViolationEvent(event)
	
	// 更新指标
	sm.metricsMutex.Lock()
	sm.securityMetrics.AuthFailures++
	switch violationType {
	case ViolationTypeInvalidToken:
		sm.securityMetrics.InvalidTokens++
	case ViolationTypeExpiredToken:
		sm.securityMetrics.ExpiredTokens++
	case ViolationTypeMalformedToken:
		sm.securityMetrics.MalformedTokens++
	}
	sm.securityMetrics.LastViolationTime = time.Now()
	sm.metricsMutex.Unlock()
	
	// 更新IP统计
	sm.ipAnalyzer.recordFailedRequest(clientIP)
	
	// 记录到指标收集器
	labels := map[string]string{
		"violation_type": string(violationType),
		"reason":         reason,
		"client_ip":      clientIP,
	}
	sm.collector.IncrementCounter("security_violations_total", labels, 1)
}

// 记录权限违规
func (sm *SecurityMonitor) RecordPermissionViolation(ctx context.Context, tenantID, userID, resource, permission string, details map[string]interface{}) {
	clientIP := sm.extractClientIP(ctx)
	
	event := SecurityViolationEvent{
		EventID:       sm.generateEventID(),
		Timestamp:     time.Now(),
		ViolationType: ViolationTypePermissionDenied,
		TenantID:      tenantID,
		UserID:        userID,
		ClientIP:      clientIP,
		Resource:      resource,
		Details:       details,
		Severity:      AlertSeverityMedium,
	}
	
	sm.recordViolationEvent(event)
	
	// 更新指标
	sm.metricsMutex.Lock()
	sm.securityMetrics.PermissionDenied++
	sm.securityMetrics.DataPermissionViolations++
	sm.securityMetrics.LastViolationTime = time.Now()
	sm.metricsMutex.Unlock()
	
	// 记录到指标收集器
	labels := map[string]string{
		"violation_type": string(ViolationTypePermissionDenied),
		"tenant_id":      tenantID,
		"resource":       resource,
		"permission":     permission,
		"client_ip":      clientIP,
	}
	sm.collector.IncrementCounter("security_violations_total", labels, 1)
}

// 记录限流违规
func (sm *SecurityMonitor) RecordRateLimitViolation(ctx context.Context, tenantID string, limit int, details map[string]interface{}) {
	clientIP := sm.extractClientIP(ctx)
	
	event := SecurityViolationEvent{
		EventID:       sm.generateEventID(),
		Timestamp:     time.Now(),
		ViolationType: ViolationTypeRateLimit,
		TenantID:      tenantID,
		ClientIP:      clientIP,
		Details:       details,
		Severity:      AlertSeverityLow,
	}
	
	sm.recordViolationEvent(event)
	
	// 更新指标
	sm.metricsMutex.Lock()
	sm.securityMetrics.RateLimitExceeded++
	sm.securityMetrics.LastViolationTime = time.Now()
	sm.metricsMutex.Unlock()
	
	// 记录到指标收集器
	labels := map[string]string{
		"violation_type": string(ViolationTypeRateLimit),
		"tenant_id":      tenantID,
		"client_ip":      clientIP,
		"limit":          fmt.Sprintf("%d", limit),
	}
	sm.collector.IncrementCounter("security_violations_total", labels, 1)
}

// 分析IP行为模式
func (sm *SecurityMonitor) AnalyzeIPBehavior() map[string]*IPStats {
	sm.ipAnalyzer.statsMutex.RLock()
	defer sm.ipAnalyzer.statsMutex.RUnlock()
	
	result := make(map[string]*IPStats)
	now := time.Now()
	
	for ip, stats := range sm.ipAnalyzer.ipStats {
		// 计算请求频率
		timeSinceFirst := now.Sub(stats.FirstSeen).Minutes()
		if timeSinceFirst > 0 {
			stats.RequestsPerMinute = float64(stats.TotalRequests) / timeSinceFirst
		}
		
		// 计算成功率
		if stats.TotalRequests > 0 {
			stats.SuccessRate = float64(stats.TotalRequests-stats.FailedRequests) / float64(stats.TotalRequests)
		}
		
		// 计算风险分数
		stats.RiskScore = sm.calculateRiskScore(stats)
		
		// 标记可疑IP
		stats.IsSuspicious = stats.RiskScore > sm.ipAnalyzer.suspiciousThreshold
		
		if stats.IsSuspicious {
			sm.metricsMutex.Lock()
			sm.securityMetrics.SuspiciousIPCount++
			sm.metricsMutex.Unlock()
		}
		
		// 复制统计信息
		statsCopy := *stats
		result[ip] = &statsCopy
	}
	
	return result
}

// 检测异常行为
func (sm *SecurityMonitor) DetectAnomalies() []AnomalyReport {
	var anomalies []AnomalyReport
	now := time.Now()
	
	// 获取当前指标
	sm.metricsMutex.RLock()
	currentMetrics := *sm.securityMetrics
	sm.metricsMutex.RUnlock()
	
	// 检测请求数异常
	if sm.anomalyDetector.baselineRequests > 0 {
		currentRequests := currentMetrics.TenantViolations + currentMetrics.AuthFailures + currentMetrics.PermissionDenied
		if float64(currentRequests) > float64(sm.anomalyDetector.baselineRequests)*sm.anomalyDetector.requestSpikeFactor {
			anomalies = append(anomalies, AnomalyReport{
				Type:        "request_spike",
				Description: fmt.Sprintf("Request count %d exceeds baseline %d by %.1fx", currentRequests, sm.anomalyDetector.baselineRequests, sm.anomalyDetector.requestSpikeFactor),
				Severity:    AlertSeverityHigh,
				DetectedAt:  now,
				Value:       float64(currentRequests),
				Threshold:   float64(sm.anomalyDetector.baselineRequests) * sm.anomalyDetector.requestSpikeFactor,
			})
		}
	}
	
	// 检测失败率异常
	if sm.anomalyDetector.baselineFailures > 0 {
		currentFailures := currentMetrics.AuthFailures + currentMetrics.PermissionDenied
		if float64(currentFailures) > float64(sm.anomalyDetector.baselineFailures)*sm.anomalyDetector.failureSpikeFactor {
			anomalies = append(anomalies, AnomalyReport{
				Type:        "failure_spike",
				Description: fmt.Sprintf("Failure count %d exceeds baseline %d by %.1fx", currentFailures, sm.anomalyDetector.baselineFailures, sm.anomalyDetector.failureSpikeFactor),
				Severity:    AlertSeverityCritical,
				DetectedAt:  now,
				Value:       float64(currentFailures),
				Threshold:   float64(sm.anomalyDetector.baselineFailures) * sm.anomalyDetector.failureSpikeFactor,
			})
		}
	}
	
	// 更新基线
	sm.updateBaseline()
	
	return anomalies
}

// 异常报告
type AnomalyReport struct {
	Type        string        `json:"type"`
	Description string        `json:"description"`
	Severity    AlertSeverity `json:"severity"`
	DetectedAt  time.Time     `json:"detected_at"`
	Value       float64       `json:"value"`
	Threshold   float64       `json:"threshold"`
}

// 获取安全指标
func (sm *SecurityMonitor) GetSecurityMetrics() *SecurityMetrics {
	sm.metricsMutex.RLock()
	defer sm.metricsMutex.RUnlock()
	
	// 返回副本
	metricsCopy := *sm.securityMetrics
	return &metricsCopy
}

// 获取违规事件
func (sm *SecurityMonitor) GetViolationEvents(limit int) []SecurityViolationEvent {
	sm.eventsMutex.RLock()
	defer sm.eventsMutex.RUnlock()
	
	if limit <= 0 || limit > len(sm.violationEvents) {
		limit = len(sm.violationEvents)
	}
	
	// 返回最近的事件
	result := make([]SecurityViolationEvent, limit)
	startIdx := len(sm.violationEvents) - limit
	copy(result, sm.violationEvents[startIdx:])
	
	return result
}

// 获取可疑IP列表
func (sm *SecurityMonitor) GetSuspiciousIPs() []string {
	ipStats := sm.AnalyzeIPBehavior()
	var suspiciousIPs []string
	
	for ip, stats := range ipStats {
		if stats.IsSuspicious {
			suspiciousIPs = append(suspiciousIPs, ip)
		}
	}
	
	return suspiciousIPs
}

// 内部辅助方法

func (sm *SecurityMonitor) recordViolationEvent(event SecurityViolationEvent) {
	sm.eventsMutex.Lock()
	defer sm.eventsMutex.Unlock()
	
	// 如果事件数量达到最大值，删除最老的事件
	if len(sm.violationEvents) >= sm.maxEvents {
		// 删除前半部分事件，保留后半部分
		copy(sm.violationEvents, sm.violationEvents[sm.maxEvents/2:])
		sm.violationEvents = sm.violationEvents[:sm.maxEvents/2]
	}
	
	sm.violationEvents = append(sm.violationEvents, event)
}

func (sm *SecurityMonitor) extractClientIP(ctx context.Context) string {
	// 从上下文中提取客户端IP
	if ip, ok := ctx.Value("client_ip").(string); ok {
		return ip
	}
	
	// 从HTTP头中提取
	if xRealIP, ok := ctx.Value("X-Real-IP").(string); ok {
		return xRealIP
	}
	
	if xForwardedFor, ok := ctx.Value("X-Forwarded-For").(string); ok {
		// 取第一个IP
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	return "unknown"
}

func (sm *SecurityMonitor) generateEventID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
}

func (sm *SecurityMonitor) mapAuthFailureReason(reason string) SecurityViolationType {
	switch strings.ToLower(reason) {
	case "invalid_token", "token_invalid":
		return ViolationTypeInvalidToken
	case "expired_token", "token_expired":
		return ViolationTypeExpiredToken
	case "malformed_token", "token_malformed":
		return ViolationTypeMalformedToken
	default:
		return ViolationTypeAuthFailure
	}
}

func (sm *SecurityMonitor) determineSeverity(violationType SecurityViolationType) AlertSeverity {
	switch violationType {
	case ViolationTypeTenantCross:
		return AlertSeverityCritical
	case ViolationTypePermissionDenied:
		return AlertSeverityHigh
	case ViolationTypeAuthFailure, ViolationTypeInvalidToken:
		return AlertSeverityMedium
	case ViolationTypeExpiredToken, ViolationTypeMalformedToken:
		return AlertSeverityLow
	default:
		return AlertSeverityMedium
	}
}

// IP分析器方法

func (analyzer *IPBehaviorAnalyzer) recordRequest(ip string, success bool, userAgent, country, tenantID string) {
	analyzer.statsMutex.Lock()
	defer analyzer.statsMutex.Unlock()
	
	stats, exists := analyzer.ipStats[ip]
	if !exists {
		stats = &IPStats{
			IP:              ip,
			FirstSeen:       time.Now(),
			Countries:       make(map[string]int),
			UserAgents:      make(map[string]int),
			AccessedTenants: make(map[string]int),
		}
		analyzer.ipStats[ip] = stats
	}
	
	stats.LastSeen = time.Now()
	stats.TotalRequests++
	
	if !success {
		stats.FailedRequests++
	}
	
	// 记录用户代理
	if userAgent != "" {
		stats.UserAgents[userAgent]++
	}
	
	// 记录国家
	if country != "" {
		stats.Countries[country]++
	}
	
	// 记录访问的租户
	if tenantID != "" {
		stats.AccessedTenants[tenantID]++
	}
}

func (analyzer *IPBehaviorAnalyzer) recordFailedRequest(ip string) {
	analyzer.recordRequest(ip, false, "", "", "")
}

func (sm *SecurityMonitor) calculateRiskScore(stats *IPStats) float64 {
	score := 0.0
	
	// 失败率权重 (40%)
	if stats.TotalRequests > 0 {
		failureRate := float64(stats.FailedRequests) / float64(stats.TotalRequests)
		score += failureRate * 0.4
	}
	
	// 请求频率权重 (30%)
	if stats.RequestsPerMinute > float64(sm.ipAnalyzer.maxRequestsPerMinute) {
		frequencyScore := stats.RequestsPerMinute / float64(sm.ipAnalyzer.maxRequestsPerMinute)
		if frequencyScore > 1.0 {
			frequencyScore = 1.0
		}
		score += frequencyScore * 0.3
	}
	
	// 访问多租户权重 (20%)
	tenantCount := len(stats.AccessedTenants)
	if tenantCount > 5 { // 访问超过5个租户认为可疑
		tenantScore := float64(tenantCount) / 10.0
		if tenantScore > 1.0 {
			tenantScore = 1.0
		}
		score += tenantScore * 0.2
	}
	
	// 违规次数权重 (10%)
	if stats.ViolationCount > 0 {
		violationScore := float64(stats.ViolationCount) / 10.0
		if violationScore > 1.0 {
			violationScore = 1.0
		}
		score += violationScore * 0.1
	}
	
	return score
}

func (sm *SecurityMonitor) updateBaseline() {
	now := time.Now()
	
	// 每小时更新一次基线
	if now.Sub(sm.anomalyDetector.baselineUpdateTime) < time.Hour {
		return
	}
	
	sm.metricsMutex.RLock()
	currentMetrics := *sm.securityMetrics
	sm.metricsMutex.RUnlock()
	
	// 使用指数移动平均更新基线
	alpha := 0.1 // 平滑系数
	
	currentRequests := currentMetrics.TenantViolations + currentMetrics.AuthFailures + currentMetrics.PermissionDenied
	sm.anomalyDetector.baselineRequests = int64(float64(sm.anomalyDetector.baselineRequests)*(1-alpha) + float64(currentRequests)*alpha)
	
	currentFailures := currentMetrics.AuthFailures + currentMetrics.PermissionDenied
	sm.anomalyDetector.baselineFailures = int64(float64(sm.anomalyDetector.baselineFailures)*(1-alpha) + float64(currentFailures)*alpha)
	
	sm.anomalyDetector.baselineUpdateTime = now
}

// IP地址解析辅助函数
func (sm *SecurityMonitor) parseIP(ipStr string) net.IP {
	return net.ParseIP(ipStr)
}

func (sm *SecurityMonitor) isPrivateIP(ip net.IP) bool {
	private := false
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	private = private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) || private16BitBlock.Contains(ip)
	return private
}