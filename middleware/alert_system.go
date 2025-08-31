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
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// AlertManager manages alerts and notifications for middleware performance
type AlertManager struct {
	config       *AlertConfig
	rules        []AlertRule
	activeAlerts map[string]*ActiveAlert
	alertHistory []AlertEvent
	notifiers    []AlertNotifier
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// Trend analysis
	trendAnalyzer   *TrendAnalyzer
	anomalyDetector *AnomalyDetector

	// Alert state
	lastEvaluation  time.Time
	suppressedUntil map[string]time.Time

	// Metrics function - can be overridden for testing
	getCurrentMetrics func() map[string]interface{}
}

// AlertConfig defines configuration for alert system
type AlertConfig struct {
	// Evaluation settings
	EvaluationInterval time.Duration `json:"evaluation_interval"`
	AlertRetention     time.Duration `json:"alert_retention"`
	MaxActiveAlerts    int           `json:"max_active_alerts"`

	// Notification settings
	EnableNotifications     bool          `json:"enable_notifications"`
	NotificationCooldown    time.Duration `json:"notification_cooldown"`
	MaxNotificationsPerHour int           `json:"max_notifications_per_hour"`

	// Suppression settings
	EnableSuppression bool          `json:"enable_suppression"`
	SuppressionWindow time.Duration `json:"suppression_window"`

	// Escalation settings
	EnableEscalation bool          `json:"enable_escalation"`
	EscalationDelay  time.Duration `json:"escalation_delay"`
	EscalationLevels []string      `json:"escalation_levels"`

	// Trend analysis
	EnableTrendAnalysis bool          `json:"enable_trend_analysis"`
	TrendWindow         time.Duration `json:"trend_window"`
	AnomalyThreshold    float64       `json:"anomaly_threshold"`
}

// DefaultAlertConfig returns default alert configuration
func DefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		EvaluationInterval:      30 * time.Second,
		AlertRetention:          24 * time.Hour,
		MaxActiveAlerts:         100,
		EnableNotifications:     true,
		NotificationCooldown:    5 * time.Minute,
		MaxNotificationsPerHour: 10,
		EnableSuppression:       true,
		SuppressionWindow:       10 * time.Minute,
		EnableEscalation:        true,
		EscalationDelay:         15 * time.Minute,
		EscalationLevels:        []string{"warning", "critical", "emergency"},
		EnableTrendAnalysis:     true,
		TrendWindow:             1 * time.Hour,
		AnomalyThreshold:        2.0, // 2 standard deviations
	}
}

// AlertRule defines a condition that triggers an alert
type AlertRule struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Condition   AlertConditionFunc `json:"-"`
	Severity    AlertSeverity      `json:"severity"`
	Labels      map[string]string  `json:"labels"`
	Annotations map[string]string  `json:"annotations"`

	// Evaluation settings
	EvaluationPeriod time.Duration `json:"evaluation_period"`
	MinDuration      time.Duration `json:"min_duration"`

	// Actions
	NotificationChannels []string      `json:"notification_channels"`
	Actions              []AlertAction `json:"actions"`

	// State
	Enabled         bool      `json:"enabled"`
	LastEvaluated   time.Time `json:"last_evaluated"`
	EvaluationCount int64     `json:"evaluation_count"`
}

// AlertConditionFunc is a function that evaluates an alert condition
type AlertConditionFunc func(metrics map[string]interface{}) bool

// AlertSeverity defines alert severity levels
type AlertSeverity int

const (
	SeverityInfo AlertSeverity = iota
	SeverityWarning
	SeverityCritical
	SeverityEmergency
)

func (s AlertSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	case SeverityEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

// ActiveAlert represents an active alert
type ActiveAlert struct {
	Rule        *AlertRule        `json:"rule"`
	StartTime   time.Time         `json:"start_time"`
	LastSeen    time.Time         `json:"last_seen"`
	State       AlertState        `json:"state"`
	Value       float64           `json:"value"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`

	// Escalation tracking
	EscalationLevel   int       `json:"escalation_level"`
	NextEscalation    time.Time `json:"next_escalation"`
	NotificationCount int       `json:"notification_count"`
	LastNotification  time.Time `json:"last_notification"`
}

// AlertState defines the state of an alert
type AlertState int

const (
	StatePending AlertState = iota
	StateFiring
	StateResolved
	StateSuppressed
)

func (s AlertState) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateFiring:
		return "firing"
	case StateResolved:
		return "resolved"
	case StateSuppressed:
		return "suppressed"
	default:
		return "unknown"
	}
}

// AlertEvent represents a historical alert event
type AlertEvent struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Event       AlertEventType    `json:"event"`
	Timestamp   time.Time         `json:"timestamp"`
	Value       float64           `json:"value"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Duration    time.Duration     `json:"duration,omitempty"`
}

// AlertEventType defines types of alert events
type AlertEventType int

const (
	EventTriggered AlertEventType = iota
	EventResolved
	EventEscalated
	EventSuppressed
	EventNotificationSent
)

func (e AlertEventType) String() string {
	switch e {
	case EventTriggered:
		return "triggered"
	case EventResolved:
		return "resolved"
	case EventEscalated:
		return "escalated"
	case EventSuppressed:
		return "suppressed"
	case EventNotificationSent:
		return "notification_sent"
	default:
		return "unknown"
	}
}

// AlertNotifier defines the interface for alert notifications
type AlertNotifier interface {
	Notify(ctx context.Context, alert *ActiveAlert, event AlertEventType) error
	Name() string
	Channels() []string
}

// AlertAction defines an action to take when an alert triggers
type AlertAction struct {
	Type       string            `json:"type"`
	Parameters map[string]string `json:"parameters"`
	Conditions []string          `json:"conditions"`
	Enabled    bool              `json:"enabled"`
}

// TrendAnalyzer analyzes metric trends for predictive alerting
type TrendAnalyzer struct {
	config     *AlertConfig
	dataPoints map[string][]DataPoint
	mu         sync.RWMutex
}

// DataPoint represents a metric data point
type DataPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels"`
}

// AnomalyDetector detects anomalies in metrics using statistical methods
type AnomalyDetector struct {
	config    *AlertConfig
	baselines map[string]*Baseline
	mu        sync.RWMutex
}

// Baseline represents statistical baseline for anomaly detection
type Baseline struct {
	Mean       float64   `json:"mean"`
	StdDev     float64   `json:"std_dev"`
	Min        float64   `json:"min"`
	Max        float64   `json:"max"`
	SampleSize int       `json:"sample_size"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig) *AlertManager {
	if config == nil {
		config = DefaultAlertConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &AlertManager{
		config:          config,
		rules:           make([]AlertRule, 0),
		activeAlerts:    make(map[string]*ActiveAlert),
		alertHistory:    make([]AlertEvent, 0),
		notifiers:       make([]AlertNotifier, 0),
		ctx:             ctx,
		cancel:          cancel,
		suppressedUntil: make(map[string]time.Time),
		trendAnalyzer: &TrendAnalyzer{
			config:     config,
			dataPoints: make(map[string][]DataPoint),
		},
		anomalyDetector: &AnomalyDetector{
			config:    config,
			baselines: make(map[string]*Baseline),
		},
	}

	// Initialize default metrics function
	manager.getCurrentMetrics = func() map[string]interface{} {
		// Placeholder - in real implementation this would get metrics from collector
		return map[string]interface{}{
			"error_rate":        0.05,
			"response_time_p95": 500.0,
			"memory_usage":      80.0,
			"cpu_usage":         75.0,
			"goroutine_count":   150,
			"cache_hit_rate":    0.95,
		}
	}

	logx.Infow("Alert manager initialized",
		logx.Field("evaluationInterval", config.EvaluationInterval),
		logx.Field("maxActiveAlerts", config.MaxActiveAlerts),
		logx.Field("enableTrendAnalysis", config.EnableTrendAnalysis))

	return manager
}

// Start begins alert evaluation
func (am *AlertManager) Start() {
	am.wg.Add(1)
	go am.evaluationLoop()

	if am.config.EnableEscalation {
		am.wg.Add(1)
		go am.escalationLoop()
	}

	logx.Info("Alert manager started")
}

// Stop gracefully shuts down the alert manager
func (am *AlertManager) Stop() error {
	am.cancel()
	am.wg.Wait()
	logx.Info("Alert manager stopped")
	return nil
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check for existing rule
	for i, existingRule := range am.rules {
		if existingRule.ID == rule.ID {
			am.rules[i] = rule
			logx.Infow("Alert rule updated", logx.Field("ruleID", rule.ID))
			return
		}
	}

	am.rules = append(am.rules, rule)
	logx.Infow("Alert rule added", logx.Field("ruleID", rule.ID))
}

// RemoveRule removes an alert rule
func (am *AlertManager) RemoveRule(ruleID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	for i, rule := range am.rules {
		if rule.ID == ruleID {
			am.rules = append(am.rules[:i], am.rules[i+1:]...)
			logx.Infow("Alert rule removed", logx.Field("ruleID", ruleID))
			return
		}
	}
}

// AddNotifier adds an alert notifier
func (am *AlertManager) AddNotifier(notifier AlertNotifier) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.notifiers = append(am.notifiers, notifier)
	logx.Infow("Alert notifier added", logx.Field("name", notifier.Name()))
}

// evaluationLoop runs the main alert evaluation loop
func (am *AlertManager) evaluationLoop() {
	defer am.wg.Done()

	ticker := time.NewTicker(am.config.EvaluationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.evaluateRules()
		case <-am.ctx.Done():
			return
		}
	}
}

// escalationLoop handles alert escalation
func (am *AlertManager) escalationLoop() {
	defer am.wg.Done()

	ticker := time.NewTicker(1 * time.Minute) // Check escalations every minute
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.processEscalations()
		case <-am.ctx.Done():
			return
		}
	}
}

// evaluateRules evaluates all enabled alert rules
func (am *AlertManager) evaluateRules() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	am.lastEvaluation = now

	// Get current metrics (would be provided by metrics collector)
	metrics := am.getCurrentMetrics()

	for i := range am.rules {
		rule := &am.rules[i]
		if !rule.Enabled {
			continue
		}

		// Evaluate rule condition
		triggered := am.evaluateRule(rule, metrics)
		alertID := am.getAlertID(rule, metrics)

		if triggered {
			am.handleTriggeredAlert(rule, alertID, metrics, now)
		} else {
			am.handleResolvedAlert(rule, alertID, now)
		}

		rule.LastEvaluated = now
		rule.EvaluationCount++
	}

	// Clean up old alerts
	am.cleanupAlerts(now)
}

// evaluateRule evaluates a single alert rule
func (am *AlertManager) evaluateRule(rule *AlertRule, metrics map[string]interface{}) bool {
	if rule.Condition == nil {
		return false
	}

	return rule.Condition(metrics)
}

// handleTriggeredAlert handles a triggered alert
func (am *AlertManager) handleTriggeredAlert(rule *AlertRule, alertID string, metrics map[string]interface{}, now time.Time) {
	activeAlert, exists := am.activeAlerts[alertID]

	if !exists {
		// New alert
		activeAlert = &ActiveAlert{
			Rule:        rule,
			StartTime:   now,
			LastSeen:    now,
			State:       StatePending,
			Labels:      copyMap(rule.Labels),
			Annotations: copyMap(rule.Annotations),
		}

		// Check if alert should be suppressed
		if am.isAlertSuppressed(alertID, now) {
			activeAlert.State = StateSuppressed
		}

		am.activeAlerts[alertID] = activeAlert

		am.recordAlertEvent(AlertEvent{
			ID:          generateEventID(),
			RuleID:      rule.ID,
			Event:       EventTriggered,
			Timestamp:   now,
			Labels:      activeAlert.Labels,
			Annotations: activeAlert.Annotations,
		})

		logx.Infow("Alert triggered",
			logx.Field("ruleID", rule.ID),
			logx.Field("alertID", alertID),
			logx.Field("severity", rule.Severity.String()))
	} else {
		// Update existing alert
		activeAlert.LastSeen = now

		// Check if alert should transition to firing
		if activeAlert.State == StatePending {
			duration := now.Sub(activeAlert.StartTime)
			if duration >= rule.MinDuration {
				activeAlert.State = StateFiring
				am.sendNotifications(activeAlert, EventTriggered)
			}
		}
	}
}

// handleResolvedAlert handles a resolved alert
func (am *AlertManager) handleResolvedAlert(rule *AlertRule, alertID string, now time.Time) {
	if activeAlert, exists := am.activeAlerts[alertID]; exists {
		if activeAlert.State == StateFiring {
			am.sendNotifications(activeAlert, EventResolved)
		}

		duration := now.Sub(activeAlert.StartTime)
		am.recordAlertEvent(AlertEvent{
			ID:          generateEventID(),
			RuleID:      rule.ID,
			Event:       EventResolved,
			Timestamp:   now,
			Duration:    duration,
			Labels:      activeAlert.Labels,
			Annotations: activeAlert.Annotations,
		})

		delete(am.activeAlerts, alertID)

		logx.Infow("Alert resolved",
			logx.Field("ruleID", rule.ID),
			logx.Field("alertID", alertID),
			logx.Field("duration", duration))
	}
}

// processEscalations processes alert escalations
func (am *AlertManager) processEscalations() {
	if !am.config.EnableEscalation {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()

	for alertID, alert := range am.activeAlerts {
		if alert.State != StateFiring {
			continue
		}

		// Check if escalation is needed
		if now.After(alert.NextEscalation) {
			am.escalateAlert(alert, now)

			// Schedule next escalation
			alert.NextEscalation = now.Add(am.config.EscalationDelay)

			logx.Infow("Alert escalated",
				logx.Field("alertID", alertID),
				logx.Field("escalationLevel", alert.EscalationLevel))
		}
	}
}

// escalateAlert escalates an alert to the next level
func (am *AlertManager) escalateAlert(alert *ActiveAlert, now time.Time) {
	if alert.EscalationLevel < len(am.config.EscalationLevels)-1 {
		alert.EscalationLevel++

		am.sendNotifications(alert, EventEscalated)

		am.recordAlertEvent(AlertEvent{
			ID:          generateEventID(),
			RuleID:      alert.Rule.ID,
			Event:       EventEscalated,
			Timestamp:   now,
			Labels:      alert.Labels,
			Annotations: alert.Annotations,
		})
	}
}

// sendNotifications sends notifications for an alert event
func (am *AlertManager) sendNotifications(alert *ActiveAlert, event AlertEventType) {
	if !am.config.EnableNotifications {
		return
	}

	now := time.Now()

	// Check cooldown
	if now.Sub(alert.LastNotification) < am.config.NotificationCooldown {
		return
	}

	// Check rate limiting
	if alert.NotificationCount >= am.config.MaxNotificationsPerHour {
		logx.Errorw("Notification rate limit exceeded",
			logx.Field("ruleID", alert.Rule.ID))
		return
	}

	for _, notifier := range am.notifiers {
		// Check if notifier handles this alert's channels
		if am.shouldNotify(notifier, alert) {
			go func(n AlertNotifier) {
				if err := n.Notify(am.ctx, alert, event); err != nil {
					logx.Errorw("Notification failed",
						logx.Field("notifier", n.Name()),
						logx.Field("error", err))
				}
			}(notifier)
		}
	}

	alert.LastNotification = now
	alert.NotificationCount++

	am.recordAlertEvent(AlertEvent{
		ID:          generateEventID(),
		RuleID:      alert.Rule.ID,
		Event:       EventNotificationSent,
		Timestamp:   now,
		Labels:      alert.Labels,
		Annotations: alert.Annotations,
	})
}

// shouldNotify determines if a notifier should handle an alert
func (am *AlertManager) shouldNotify(notifier AlertNotifier, alert *ActiveAlert) bool {
	notifierChannels := notifier.Channels()
	alertChannels := alert.Rule.NotificationChannels

	// If no specific channels configured, notify all
	if len(alertChannels) == 0 {
		return true
	}

	// Check if notifier handles any of the alert channels
	for _, alertChannel := range alertChannels {
		for _, notifierChannel := range notifierChannels {
			if alertChannel == notifierChannel {
				return true
			}
		}
	}

	return false
}

// isAlertSuppressed checks if an alert should be suppressed
func (am *AlertManager) isAlertSuppressed(alertID string, now time.Time) bool {
	if !am.config.EnableSuppression {
		return false
	}

	if suppressedUntil, exists := am.suppressedUntil[alertID]; exists {
		return now.Before(suppressedUntil)
	}

	return false
}

// SuppressAlert suppresses an alert for a specified duration
func (am *AlertManager) SuppressAlert(alertID string, duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	am.suppressedUntil[alertID] = now.Add(duration)

	if alert, exists := am.activeAlerts[alertID]; exists {
		alert.State = StateSuppressed

		am.recordAlertEvent(AlertEvent{
			ID:          generateEventID(),
			RuleID:      alert.Rule.ID,
			Event:       EventSuppressed,
			Timestamp:   now,
			Duration:    duration,
			Labels:      alert.Labels,
			Annotations: alert.Annotations,
		})
	}

	logx.Infow("Alert suppressed",
		logx.Field("alertID", alertID),
		logx.Field("duration", duration))
}

// recordAlertEvent records an alert event to history
func (am *AlertManager) recordAlertEvent(event AlertEvent) {
	am.alertHistory = append(am.alertHistory, event)

	// Limit history size
	maxHistory := 1000
	if len(am.alertHistory) > maxHistory {
		am.alertHistory = am.alertHistory[len(am.alertHistory)-maxHistory:]
	}
}

// cleanupAlerts removes old resolved alerts and history
func (am *AlertManager) cleanupAlerts(now time.Time) {
	// Clean up suppression entries
	for alertID, suppressedUntil := range am.suppressedUntil {
		if now.After(suppressedUntil) {
			delete(am.suppressedUntil, alertID)
		}
	}

	// Clean up old alert history
	cutoff := now.Add(-am.config.AlertRetention)
	newHistory := make([]AlertEvent, 0)
	for _, event := range am.alertHistory {
		if event.Timestamp.After(cutoff) {
			newHistory = append(newHistory, event)
		}
	}
	am.alertHistory = newHistory
}

// getAlertID generates a unique ID for an alert
func (am *AlertManager) getAlertID(rule *AlertRule, metrics map[string]interface{}) string {
	return fmt.Sprintf("%s", rule.ID) // Simplified - could include label values
}

// Helper functions

func copyMap(m map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = v
	}
	return result
}

func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

// GetActiveAlerts returns currently active alerts
func (am *AlertManager) GetActiveAlerts() map[string]*ActiveAlert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make(map[string]*ActiveAlert)
	for k, v := range am.activeAlerts {
		alertCopy := *v
		alertCopy.Labels = copyMap(v.Labels)
		alertCopy.Annotations = copyMap(v.Annotations)
		result[k] = &alertCopy
	}
	return result
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []AlertEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	// Return most recent events
	start := len(am.alertHistory) - limit
	result := make([]AlertEvent, limit)
	copy(result, am.alertHistory[start:])

	return result
}

// AnalyzeTrend analyzes metric trends for predictive alerting
func (ta *TrendAnalyzer) AnalyzeTrend(metricName string, value float64, timestamp time.Time) TrendAnalysis {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// Add data point
	dataPoint := DataPoint{
		Timestamp: timestamp,
		Value:     value,
	}

	if _, exists := ta.dataPoints[metricName]; !exists {
		ta.dataPoints[metricName] = make([]DataPoint, 0)
	}

	ta.dataPoints[metricName] = append(ta.dataPoints[metricName], dataPoint)

	// Keep only data within trend window
	cutoff := timestamp.Add(-ta.config.TrendWindow)
	points := ta.dataPoints[metricName]
	validPoints := make([]DataPoint, 0)
	for _, p := range points {
		if p.Timestamp.After(cutoff) {
			validPoints = append(validPoints, p)
		}
	}
	ta.dataPoints[metricName] = validPoints

	// Calculate trend
	return ta.calculateTrend(metricName, validPoints)
}

// TrendAnalysis represents trend analysis results
type TrendAnalysis struct {
	MetricName  string         `json:"metric_name"`
	Trend       TrendDirection `json:"trend"`
	Slope       float64        `json:"slope"`
	Correlation float64        `json:"correlation"`
	Prediction  float64        `json:"prediction_5min"`
	Confidence  float64        `json:"confidence"`
	SampleSize  int            `json:"sample_size"`
	AnalyzedAt  time.Time      `json:"analyzed_at"`
}

// TrendDirection represents the direction of a trend
type TrendDirection int

const (
	TrendFlat TrendDirection = iota
	TrendIncreasing
	TrendDecreasing
	TrendVolatile
)

func (t TrendDirection) String() string {
	switch t {
	case TrendFlat:
		return "flat"
	case TrendIncreasing:
		return "increasing"
	case TrendDecreasing:
		return "decreasing"
	case TrendVolatile:
		return "volatile"
	default:
		return "unknown"
	}
}

// calculateTrend calculates trend analysis from data points
func (ta *TrendAnalyzer) calculateTrend(metricName string, points []DataPoint) TrendAnalysis {
	analysis := TrendAnalysis{
		MetricName: metricName,
		SampleSize: len(points),
		AnalyzedAt: time.Now(),
	}

	if len(points) < 2 {
		analysis.Trend = TrendFlat
		return analysis
	}

	// Simple linear regression for trend calculation
	n := len(points)
	var sumX, sumY, sumXY, sumXX float64

	for i, point := range points {
		x := float64(i)
		y := point.Value
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}

	// Calculate slope (trend)
	denominator := float64(n)*sumXX - sumX*sumX
	if denominator != 0 {
		analysis.Slope = (float64(n)*sumXY - sumX*sumY) / denominator

		// Calculate correlation coefficient
		meanX := sumX / float64(n)
		meanY := sumY / float64(n)

		var sumXDiffSq, sumYDiffSq, sumXYDiff float64
		for i, point := range points {
			xDiff := float64(i) - meanX
			yDiff := point.Value - meanY
			sumXDiffSq += xDiff * xDiff
			sumYDiffSq += yDiff * yDiff
			sumXYDiff += xDiff * yDiff
		}

		corrDenom := math.Sqrt(sumXDiffSq * sumYDiffSq)
		if corrDenom != 0 {
			analysis.Correlation = sumXYDiff / corrDenom
		}
	}

	// Determine trend direction
	slopeThreshold := 0.1 // Configurable threshold
	if math.Abs(analysis.Slope) < slopeThreshold {
		analysis.Trend = TrendFlat
	} else if analysis.Slope > 0 {
		analysis.Trend = TrendIncreasing
	} else {
		analysis.Trend = TrendDecreasing
	}

	// Check for volatility
	if len(points) > 5 {
		var variance float64
		mean := sumY / float64(n)
		for _, point := range points {
			diff := point.Value - mean
			variance += diff * diff
		}
		variance /= float64(n)

		// If variance is high relative to mean, consider volatile
		if variance > mean*0.5 {
			analysis.Trend = TrendVolatile
		}
	}

	// Simple prediction (5 minutes ahead)
	if len(points) > 0 {
		lastValue := points[len(points)-1].Value
		analysis.Prediction = lastValue + (analysis.Slope * 5) // 5 time units ahead
	}

	// Confidence based on correlation strength
	analysis.Confidence = math.Abs(analysis.Correlation)

	return analysis
}

// DetectAnomaly detects anomalies in metric values
func (ad *AnomalyDetector) DetectAnomaly(metricName string, value float64, timestamp time.Time) AnomalyResult {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	result := AnomalyResult{
		MetricName: metricName,
		Value:      value,
		Timestamp:  timestamp,
		IsAnomaly:  false,
		Severity:   AnomalySeverityNormal,
		Confidence: 0.0,
		DetectedAt: time.Now(),
	}

	baseline, exists := ad.baselines[metricName]
	if !exists {
		// Initialize baseline
		baseline = &Baseline{
			Mean:       value,
			StdDev:     0,
			Min:        value,
			Max:        value,
			SampleSize: 1,
			UpdatedAt:  timestamp,
		}
		ad.baselines[metricName] = baseline
		return result
	}

	// Calculate z-score
	if baseline.StdDev > 0 {
		zScore := math.Abs(value-baseline.Mean) / baseline.StdDev
		result.ZScore = zScore

		// Determine if anomaly
		if zScore > ad.config.AnomalyThreshold {
			result.IsAnomaly = true
			result.Confidence = math.Min(zScore/ad.config.AnomalyThreshold, 1.0)

			// Determine severity
			if zScore > ad.config.AnomalyThreshold*2 {
				result.Severity = AnomalySeverityCritical
			} else {
				result.Severity = AnomalySeverityMild
			}
		}
	}

	// Update baseline
	ad.updateBaseline(baseline, value)

	return result
}

// AnomalyResult represents anomaly detection results
type AnomalyResult struct {
	MetricName string          `json:"metric_name"`
	Value      float64         `json:"value"`
	Timestamp  time.Time       `json:"timestamp"`
	IsAnomaly  bool            `json:"is_anomaly"`
	Severity   AnomalySeverity `json:"severity"`
	ZScore     float64         `json:"z_score"`
	Confidence float64         `json:"confidence"`
	DetectedAt time.Time       `json:"detected_at"`
}

// AnomalySeverity defines anomaly severity levels
type AnomalySeverity int

const (
	AnomalySeverityNormal AnomalySeverity = iota
	AnomalySeverityMild
	AnomalySeverityCritical
)

func (s AnomalySeverity) String() string {
	switch s {
	case AnomalySeverityNormal:
		return "normal"
	case AnomalySeverityMild:
		return "mild"
	case AnomalySeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// updateBaseline updates the baseline with new value using exponential moving average
func (ad *AnomalyDetector) updateBaseline(baseline *Baseline, value float64) {
	if baseline.SampleSize < 10 {
		// Not enough samples for stable baseline, use simple average
		baseline.Mean = (baseline.Mean*float64(baseline.SampleSize) + value) / float64(baseline.SampleSize+1)
		baseline.SampleSize++
	} else {
		// Use exponential moving average
		alpha := 0.1 // Smoothing factor
		baseline.Mean = alpha*value + (1-alpha)*baseline.Mean

		// Update standard deviation using exponential moving average
		variance := alpha*math.Pow(value-baseline.Mean, 2) + (1-alpha)*math.Pow(baseline.StdDev, 2)
		baseline.StdDev = math.Sqrt(variance)
	}

	// Update min/max
	if value < baseline.Min {
		baseline.Min = value
	}
	if value > baseline.Max {
		baseline.Max = value
	}

	baseline.UpdatedAt = time.Now()
}
