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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// NewPoolAlertManager 创建连接池报警管理器
func NewPoolAlertManager(config *AlertConfig) *PoolAlertManager {
	return &PoolAlertManager{
		config:       config,
		alertChannel: make(chan *PoolAlert, 100),
		subscribers:  make([]AlertSubscriber, 0),
		alertHistory: make([]PoolAlert, 0, 1000),
	}
}

// Start 启动报警管理器
func (pam *PoolAlertManager) Start(ctx context.Context) error {
	if !pam.config.Enabled {
		return nil
	}

	go pam.alertProcessingLoop(ctx)
	go pam.escalationLoop(ctx)

	return nil
}

// Stop 停止报警管理器
func (pam *PoolAlertManager) Stop() {
	// 处理循环会通过context取消自动停止
	close(pam.alertChannel)
}

// alertProcessingLoop 报警处理循环
func (pam *PoolAlertManager) alertProcessingLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert, ok := <-pam.alertChannel:
			if !ok {
				return
			}
			pam.processAlert(alert)
		}
	}
}

// escalationLoop 升级循环
func (pam *PoolAlertManager) escalationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pam.checkEscalations()
		}
	}
}

// processAlert 处理报警
func (pam *PoolAlertManager) processAlert(alert *PoolAlert) {
	pam.mu.Lock()
	defer pam.mu.Unlock()

	// 检查冷却期
	if pam.isInCooldown(alert) {
		return
	}

	// 生成报警ID
	alert.ID = pam.generateAlertID()
	alert.Timestamp = time.Now()

	// 添加到历史记录
	pam.alertHistory = append(pam.alertHistory, *alert)

	// 限制历史记录数量
	if len(pam.alertHistory) > 1000 {
		pam.alertHistory = pam.alertHistory[1:]
	}

	// 通知订阅者
	pam.notifySubscribers(alert)
}

// isInCooldown 检查是否在冷却期
func (pam *PoolAlertManager) isInCooldown(alert *PoolAlert) bool {
	cutoff := time.Now().Add(-pam.config.CooldownPeriod)

	for i := len(pam.alertHistory) - 1; i >= 0; i-- {
		existing := &pam.alertHistory[i]
		if existing.Timestamp.Before(cutoff) {
			break
		}

		if existing.Type == alert.Type && !existing.Resolved {
			return true
		}
	}

	return false
}

// generateAlertID 生成报警ID
func (pam *PoolAlertManager) generateAlertID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// notifySubscribers 通知订阅者
func (pam *PoolAlertManager) notifySubscribers(alert *PoolAlert) {
	for _, subscriber := range pam.subscribers {
		go func(sub AlertSubscriber) {
			if err := sub.OnAlert(alert); err != nil {
				fmt.Printf("Alert notification failed: %v\n", err)
			}
		}(subscriber)
	}
}

// checkEscalations 检查升级
func (pam *PoolAlertManager) checkEscalations() {
	pam.mu.Lock()
	defer pam.mu.Unlock()

	now := time.Now()

	for i := range pam.alertHistory {
		alert := &pam.alertHistory[i]

		if alert.Resolved {
			continue
		}

		// 检查是否需要升级
		for _, rule := range pam.config.EscalationRules {
			if alert.Level == rule.FromLevel {
				if now.Sub(alert.Timestamp) >= rule.Duration {
					// 执行升级
					pam.escalateAlert(alert, rule)
				}
			}
		}
	}
}

// escalateAlert 升级报警
func (pam *PoolAlertManager) escalateAlert(alert *PoolAlert, rule EscalationRule) {
	// 创建升级后的报警
	escalatedAlert := &PoolAlert{
		ID:    pam.generateAlertID(),
		Type:  alert.Type,
		Level: rule.ToLevel,
		Title: fmt.Sprintf("[ESCALATED] %s", alert.Title),
		Description: fmt.Sprintf("Alert escalated from %s to %s after %v. Original: %s",
			rule.FromLevel, rule.ToLevel, rule.Duration, alert.Description),
		Metrics:   alert.Metrics,
		Timestamp: time.Now(),
		Resolved:  false,
	}

	// 添加到历史记录
	pam.alertHistory = append(pam.alertHistory, *escalatedAlert)

	// 标记原报警为已解决（被升级替代）
	alert.Resolved = true
	now := time.Now()
	alert.ResolvedAt = &now

	// 通知订阅者
	pam.notifySubscribers(escalatedAlert)
}

// SendAlert 发送报警
func (pam *PoolAlertManager) SendAlert(alertType PoolAlertType, level AlertLevel, title, description string, metrics map[string]interface{}) {
	if !pam.config.Enabled {
		return
	}

	alert := &PoolAlert{
		Type:        alertType,
		Level:       level,
		Title:       title,
		Description: description,
		Metrics:     metrics,
		Resolved:    false,
	}

	select {
	case pam.alertChannel <- alert:
	default:
		// 通道满了，丢弃报警或记录错误
		fmt.Printf("Alert channel full, dropping alert: %s\n", title)
	}
}

// ResolveAlert 解决报警
func (pam *PoolAlertManager) ResolveAlert(alertID string) error {
	pam.mu.Lock()
	defer pam.mu.Unlock()

	for i := range pam.alertHistory {
		alert := &pam.alertHistory[i]
		if alert.ID == alertID && !alert.Resolved {
			alert.Resolved = true
			now := time.Now()
			alert.ResolvedAt = &now
			return nil
		}
	}

	return fmt.Errorf("alert not found or already resolved: %s", alertID)
}

// GetActiveAlerts 获取活跃报警
func (pam *PoolAlertManager) GetActiveAlerts() []PoolAlert {
	pam.mu.RLock()
	defer pam.mu.RUnlock()

	var activeAlerts []PoolAlert

	for _, alert := range pam.alertHistory {
		if !alert.Resolved {
			activeAlerts = append(activeAlerts, alert)
		}
	}

	return activeAlerts
}

// GetAlertHistory 获取报警历史
func (pam *PoolAlertManager) GetAlertHistory(duration time.Duration) []PoolAlert {
	pam.mu.RLock()
	defer pam.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	var history []PoolAlert

	for _, alert := range pam.alertHistory {
		if alert.Timestamp.After(cutoff) {
			history = append(history, alert)
		}
	}

	return history
}

// GetAlertStatistics 获取报警统计
func (pam *PoolAlertManager) GetAlertStatistics(duration time.Duration) *AlertStatistics {
	pam.mu.RLock()
	defer pam.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	stats := &AlertStatistics{
		Period:        duration,
		AlertsByType:  make(map[PoolAlertType]int),
		AlertsByLevel: make(map[AlertLevel]int),
	}

	for _, alert := range pam.alertHistory {
		if alert.Timestamp.After(cutoff) {
			stats.TotalAlerts++
			stats.AlertsByType[alert.Type]++
			stats.AlertsByLevel[alert.Level]++

			if alert.Resolved {
				stats.ResolvedAlerts++
				if alert.ResolvedAt != nil {
					resolutionTime := alert.ResolvedAt.Sub(alert.Timestamp)
					stats.AvgResolutionTime = (stats.AvgResolutionTime*time.Duration(stats.ResolvedAlerts-1) + resolutionTime) / time.Duration(stats.ResolvedAlerts)
				}
			}
		}
	}

	if stats.TotalAlerts > 0 {
		stats.ResolutionRate = float64(stats.ResolvedAlerts) / float64(stats.TotalAlerts)
	}

	return stats
}

// AddSubscriber 添加报警订阅者
func (pam *PoolAlertManager) AddSubscriber(subscriber AlertSubscriber) {
	pam.mu.Lock()
	defer pam.mu.Unlock()
	pam.subscribers = append(pam.subscribers, subscriber)
}

// RemoveSubscriber 移除报警订阅者
func (pam *PoolAlertManager) RemoveSubscriber(subscriber AlertSubscriber) {
	pam.mu.Lock()
	defer pam.mu.Unlock()

	for i, sub := range pam.subscribers {
		if sub == subscriber {
			pam.subscribers = append(pam.subscribers[:i], pam.subscribers[i+1:]...)
			break
		}
	}
}

// CheckPoolMetrics 检查连接池指标并生成报警
func (pam *PoolAlertManager) CheckPoolMetrics(metrics *PoolMetrics) {
	if !pam.config.Enabled {
		return
	}

	// 检查Redis指标
	if metrics.Redis != nil {
		pam.checkRedisMetrics(metrics.Redis)
	}

	// 检查数据库指标
	if metrics.Database != nil {
		pam.checkDBMetrics(metrics.Database)
	}

	// 检查系统指标
	if metrics.System != nil {
		pam.checkSystemMetrics(metrics.System)
	}
}

// checkRedisMetrics 检查Redis指标
func (pam *PoolAlertManager) checkRedisMetrics(metrics *RedisPoolMetrics) {
	// 检查连接池使用率
	if metrics.TotalConns > 0 {
		poolUsage := float64(metrics.TotalConns-metrics.IdleConns) / float64(metrics.TotalConns)

		if threshold, exists := pam.config.Thresholds["redis_pool_usage"]; exists && poolUsage > threshold {
			pam.SendAlert(
				AlertTypeRedisConnectionHigh,
				AlertLevelWarning,
				"Redis Connection Pool Usage High",
				fmt.Sprintf("Redis pool usage is %.2f%%, exceeding threshold of %.2f%%", poolUsage*100, threshold*100),
				map[string]interface{}{
					"pool_usage":  poolUsage,
					"total_conns": metrics.TotalConns,
					"idle_conns":  metrics.IdleConns,
					"threshold":   threshold,
				},
			)
		}
	}

	// 检查错误率
	totalOps := metrics.Hits + metrics.Misses + metrics.ConnErrors + metrics.CmdErrors
	if totalOps > 0 {
		errorRate := float64(metrics.ConnErrors+metrics.CmdErrors) / float64(totalOps)

		if threshold, exists := pam.config.Thresholds["error_rate"]; exists && errorRate > threshold {
			pam.SendAlert(
				AlertTypeRedisErrorRateHigh,
				AlertLevelCritical,
				"Redis Error Rate High",
				fmt.Sprintf("Redis error rate is %.4f, exceeding threshold of %.4f", errorRate, threshold),
				map[string]interface{}{
					"error_rate":  errorRate,
					"conn_errors": metrics.ConnErrors,
					"cmd_errors":  metrics.CmdErrors,
					"total_ops":   totalOps,
					"threshold":   threshold,
				},
			)
		}
	}

	// 检查响应时间
	if threshold, exists := pam.config.Thresholds["response_time_ms"]; exists {
		responseTimeMs := float64(metrics.AvgCmdTime.Nanoseconds()) / 1e6
		if responseTimeMs > threshold {
			pam.SendAlert(
				AlertTypeRedisLatencyHigh,
				AlertLevelWarning,
				"Redis Response Time High",
				fmt.Sprintf("Redis average response time is %.2fms, exceeding threshold of %.2fms", responseTimeMs, threshold),
				map[string]interface{}{
					"response_time_ms": responseTimeMs,
					"threshold":        threshold,
				},
			)
		}
	}
}

// checkDBMetrics 检查数据库指标
func (pam *PoolAlertManager) checkDBMetrics(metrics *DBPoolMetrics) {
	// 检查连接池使用率
	if metrics.MaxOpenConnections > 0 {
		poolUsage := float64(metrics.InUseConnections) / float64(metrics.MaxOpenConnections)

		if threshold, exists := pam.config.Thresholds["db_pool_usage"]; exists && poolUsage > threshold {
			pam.SendAlert(
				AlertTypeDBConnectionHigh,
				AlertLevelWarning,
				"Database Connection Pool Usage High",
				fmt.Sprintf("Database pool usage is %.2f%%, exceeding threshold of %.2f%%", poolUsage*100, threshold*100),
				map[string]interface{}{
					"pool_usage":     poolUsage,
					"in_use_conns":   metrics.InUseConnections,
					"max_open_conns": metrics.MaxOpenConnections,
					"threshold":      threshold,
				},
			)
		}
	}

	// 检查等待时间
	if threshold, exists := pam.config.Thresholds["response_time_ms"]; exists {
		waitTimeMs := float64(metrics.WaitDuration.Nanoseconds()) / 1e6
		if waitTimeMs > threshold && metrics.WaitCount > 0 {
			pam.SendAlert(
				AlertTypeDBWaitTimeHigh,
				AlertLevelCritical,
				"Database Wait Time High",
				fmt.Sprintf("Database average wait time is %.2fms, exceeding threshold of %.2fms", waitTimeMs, threshold),
				map[string]interface{}{
					"wait_time_ms": waitTimeMs,
					"wait_count":   metrics.WaitCount,
					"threshold":    threshold,
				},
			)
		}
	}
}

// checkSystemMetrics 检查系统指标
func (pam *PoolAlertManager) checkSystemMetrics(metrics *SystemMetrics) {
	// 检查CPU使用率
	if threshold, exists := pam.config.Thresholds["cpu_usage"]; exists && metrics.CPUUsage > threshold {
		pam.SendAlert(
			AlertTypeSystemResourceHigh,
			AlertLevelWarning,
			"High CPU Usage",
			fmt.Sprintf("CPU usage is %.2f%%, exceeding threshold of %.2f%%", metrics.CPUUsage*100, threshold*100),
			map[string]interface{}{
				"cpu_usage": metrics.CPUUsage,
				"threshold": threshold,
			},
		)
	}

	// 检查内存使用率
	if threshold, exists := pam.config.Thresholds["memory_usage"]; exists && metrics.MemoryUsage > threshold {
		pam.SendAlert(
			AlertTypeSystemResourceHigh,
			AlertLevelWarning,
			"High Memory Usage",
			fmt.Sprintf("Memory usage is %.2f%%, exceeding threshold of %.2f%%", metrics.MemoryUsage*100, threshold*100),
			map[string]interface{}{
				"memory_usage": metrics.MemoryUsage,
				"threshold":    threshold,
			},
		)
	}

	// 检查Goroutine数量
	if metrics.GoroutineCount > 10000 {
		pam.SendAlert(
			AlertTypeSystemResourceHigh,
			AlertLevelCritical,
			"High Goroutine Count",
			fmt.Sprintf("Goroutine count is %d, which may indicate a goroutine leak", metrics.GoroutineCount),
			map[string]interface{}{
				"goroutine_count": metrics.GoroutineCount,
			},
		)
	}
}

// AlertStatistics 报警统计
type AlertStatistics struct {
	Period            time.Duration         `json:"period"`
	TotalAlerts       int                   `json:"total_alerts"`
	ResolvedAlerts    int                   `json:"resolved_alerts"`
	ResolutionRate    float64               `json:"resolution_rate"`
	AvgResolutionTime time.Duration         `json:"avg_resolution_time"`
	AlertsByType      map[PoolAlertType]int `json:"alerts_by_type"`
	AlertsByLevel     map[AlertLevel]int    `json:"alerts_by_level"`
}

// LogAlertSubscriber 日志报警订阅者
type LogAlertSubscriber struct{}

// OnAlert 处理报警
func (las *LogAlertSubscriber) OnAlert(alert *PoolAlert) error {
	timestamp := alert.Timestamp.Format(time.RFC3339)
	fmt.Printf("[%s] %s ALERT [%s]: %s - %s\n",
		timestamp, alert.Level, alert.Type, alert.Title, alert.Description)
	return nil
}

// TestAlert 测试报警
func (pam *PoolAlertManager) TestAlert() error {
	pam.SendAlert(
		AlertTypeSystemResourceHigh,
		AlertLevelInfo,
		"Test Alert",
		"This is a test alert to verify the alerting system is working",
		map[string]interface{}{
			"test": true,
		},
	)
	return nil
}

// UpdateConfig 更新配置
func (pam *PoolAlertManager) UpdateConfig(config *AlertConfig) {
	pam.mu.Lock()
	defer pam.mu.Unlock()
	pam.config = config
}

// GetConfig 获取当前配置
func (pam *PoolAlertManager) GetConfig() *AlertConfig {
	pam.mu.RLock()
	defer pam.mu.RUnlock()

	// 返回配置副本
	configCopy := *pam.config
	return &configCopy
}
