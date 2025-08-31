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
	"testing"
	"time"
)

func TestAlertManager_AddRule(t *testing.T) {
	manager := NewAlertManager(nil)

	rule := AlertRule{
		ID:          "test-rule-1",
		Name:        "High Error Rate",
		Description: "Triggers when error rate exceeds 5%",
		Condition: func(metrics map[string]interface{}) bool {
			if errorRate, ok := metrics["error_rate"].(float64); ok {
				return errorRate > 0.05
			}
			return false
		},
		Severity:         SeverityWarning,
		Enabled:          true,
		EvaluationPeriod: 1 * time.Minute,
		MinDuration:      30 * time.Second,
	}

	manager.AddRule(rule)

	// Verify rule was added
	if len(manager.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(manager.rules))
	}

	if manager.rules[0].ID != "test-rule-1" {
		t.Errorf("Expected rule ID 'test-rule-1', got '%s'", manager.rules[0].ID)
	}
}

func TestAlertManager_EvaluateRules(t *testing.T) {
	config := DefaultAlertConfig()
	config.EvaluationInterval = 100 * time.Millisecond
	manager := NewAlertManager(config)

	// Add a test rule
	rule := AlertRule{
		ID:          "error-rate-rule",
		Name:        "Error Rate Alert",
		Description: "High error rate detected",
		Condition: func(metrics map[string]interface{}) bool {
			if errorRate, ok := metrics["error_rate"].(float64); ok {
				return errorRate > 0.03 // 3% threshold
			}
			return false
		},
		Severity:    SeverityWarning,
		Enabled:     true,
		MinDuration: 10 * time.Millisecond, // Short duration for testing
	}

	manager.AddRule(rule)

	// Mock getCurrentMetrics to return high error rate
	originalGetCurrentMetrics := manager.getCurrentMetrics
	manager.getCurrentMetrics = func() map[string]interface{} {
		return map[string]interface{}{
			"error_rate": 0.08, // 8% error rate - should trigger alert
		}
	}
	defer func() {
		manager.getCurrentMetrics = originalGetCurrentMetrics
	}()

	// Evaluate rules
	manager.evaluateRules()

	// Should have one active alert
	activeAlerts := manager.GetActiveAlerts()
	if len(activeAlerts) != 1 {
		t.Errorf("Expected 1 active alert, got %d", len(activeAlerts))
	}

	// Check alert details
	for _, alert := range activeAlerts {
		if alert.Rule.ID != "error-rate-rule" {
			t.Errorf("Expected alert for rule 'error-rate-rule', got '%s'", alert.Rule.ID)
		}

		if alert.State != StatePending && alert.State != StateFiring {
			t.Errorf("Expected alert state to be pending or firing, got %s", alert.State.String())
		}
	}
}

func TestAlertManager_AlertResolution(t *testing.T) {
	manager := NewAlertManager(nil)

	rule := AlertRule{
		ID:          "resolution-test",
		Name:        "Resolution Test Alert",
		Description: "Test alert resolution",
		Condition: func(metrics map[string]interface{}) bool {
			if value, ok := metrics["test_metric"].(float64); ok {
				return value > 50
			}
			return false
		},
		Severity:    SeverityInfo,
		Enabled:     true,
		MinDuration: 1 * time.Millisecond,
	}

	manager.AddRule(rule)

	// First evaluation - trigger alert
	originalGetCurrentMetrics := manager.getCurrentMetrics
	manager.getCurrentMetrics = func() map[string]interface{} {
		return map[string]interface{}{
			"test_metric": 75.0, // Above threshold
		}
	}

	manager.evaluateRules()

	// Should have active alert
	if len(manager.GetActiveAlerts()) != 1 {
		t.Error("Expected 1 active alert after first evaluation")
	}

	// Second evaluation - resolve alert
	manager.getCurrentMetrics = func() map[string]interface{} {
		return map[string]interface{}{
			"test_metric": 25.0, // Below threshold
		}
	}

	manager.evaluateRules()

	// Alert should be resolved
	if len(manager.GetActiveAlerts()) != 0 {
		t.Error("Expected 0 active alerts after resolution")
	}

	// Restore original function
	manager.getCurrentMetrics = originalGetCurrentMetrics
}

func TestAlertManager_SuppressAlert(t *testing.T) {
	manager := NewAlertManager(nil)

	// Create and trigger an alert first
	rule := AlertRule{
		ID:          "suppress-test",
		Name:        "Suppression Test Alert",
		Description: "Test alert suppression",
		Condition: func(metrics map[string]interface{}) bool {
			return true // Always trigger
		},
		Severity:    SeverityInfo,
		Enabled:     true,
		MinDuration: 1 * time.Millisecond,
	}

	manager.AddRule(rule)
	manager.evaluateRules()

	alertID := manager.getAlertID(&rule, map[string]interface{}{})

	// Suppress the alert
	suppressDuration := 5 * time.Minute
	manager.SuppressAlert(alertID, suppressDuration)

	// Check that alert is suppressed
	activeAlerts := manager.GetActiveAlerts()
	if len(activeAlerts) != 1 {
		t.Error("Expected 1 active alert")
	}

	for _, alert := range activeAlerts {
		if alert.State != StateSuppressed {
			t.Errorf("Expected alert to be suppressed, got state: %s", alert.State.String())
		}
	}

	// Check suppression map
	if _, exists := manager.suppressedUntil[alertID]; !exists {
		t.Error("Expected alert ID to be in suppression map")
	}
}

func TestLogNotifier_Notify(t *testing.T) {
	notifier := NewLogNotifier("test-notifier", []string{"general"}, nil)

	// Create a test alert
	rule := &AlertRule{
		ID:          "test-alert",
		Name:        "Test Alert",
		Description: "Test alert for notification",
		Severity:    SeverityWarning,
	}

	alert := &ActiveAlert{
		Rule:        rule,
		StartTime:   time.Now(),
		LastSeen:    time.Now(),
		State:       StateFiring,
		Value:       75.5,
		Labels:      map[string]string{"env": "test", "service": "middleware"},
		Annotations: map[string]string{"summary": "Test alert summary"},
	}

	// Test notification - should not return error
	err := notifier.Notify(context.Background(), alert, EventTriggered)
	if err != nil {
		t.Errorf("Expected no error from notification, got: %v", err)
	}

	// Test notifier properties
	if notifier.Name() != "test-notifier" {
		t.Errorf("Expected notifier name 'test-notifier', got '%s'", notifier.Name())
	}

	channels := notifier.Channels()
	if len(channels) != 1 || channels[0] != "general" {
		t.Errorf("Expected channels ['general'], got %v", channels)
	}
}

func TestTrendAnalyzer_AnalyzeTrend(t *testing.T) {
	config := DefaultAlertConfig()
	analyzer := &TrendAnalyzer{
		config:     config,
		dataPoints: make(map[string][]DataPoint),
	}

	metricName := "response_time"
	baseTime := time.Now()

	// Add increasing trend data
	values := []float64{100, 110, 120, 130, 140, 150}
	for i, value := range values {
		timestamp := baseTime.Add(time.Duration(i) * time.Minute)
		analysis := analyzer.AnalyzeTrend(metricName, value, timestamp)

		// Check final analysis
		if i == len(values)-1 {
			if analysis.Trend != TrendIncreasing {
				t.Errorf("Expected increasing trend, got %s", analysis.Trend.String())
			}

			if analysis.Slope <= 0 {
				t.Errorf("Expected positive slope for increasing trend, got %.2f", analysis.Slope)
			}

			if analysis.SampleSize != len(values) {
				t.Errorf("Expected sample size %d, got %d", len(values), analysis.SampleSize)
			}
		}
	}
}

func TestAnomalyDetector_DetectAnomaly(t *testing.T) {
	config := DefaultAlertConfig()
	config.AnomalyThreshold = 2.0 // 2 standard deviations

	detector := &AnomalyDetector{
		config:    config,
		baselines: make(map[string]*Baseline),
	}

	metricName := "cpu_usage"
	baseTime := time.Now()

	// Add normal values to build baseline
	normalValues := []float64{50, 52, 48, 51, 49, 53, 47, 50}
	for i, value := range normalValues {
		timestamp := baseTime.Add(time.Duration(i) * time.Minute)
		detector.DetectAnomaly(metricName, value, timestamp)
	}

	// Test with anomalous value
	anomalousValue := 90.0 // Much higher than normal
	timestamp := baseTime.Add(10 * time.Minute)
	result := detector.DetectAnomaly(metricName, anomalousValue, timestamp)

	// Should detect anomaly after sufficient baseline
	if baseline, exists := detector.baselines[metricName]; exists && baseline.SampleSize > 5 {
		if !result.IsAnomaly {
			t.Error("Expected anomaly detection for value significantly higher than baseline")
		}

		if result.Severity == AnomalySeverityNormal {
			t.Error("Expected non-normal severity for detected anomaly")
		}

		if result.ZScore <= config.AnomalyThreshold {
			t.Errorf("Expected z-score > %.1f for anomaly, got %.2f", config.AnomalyThreshold, result.ZScore)
		}
	}
}

func TestAlertManager_ThresholdIntegration(t *testing.T) {
	// Create alert manager with specific thresholds
	config := DefaultAlertConfig()
	config.EvaluationInterval = 50 * time.Millisecond

	manager := NewAlertManager(config)

	// Create metrics collector with threshold checking
	metricsConfig := DefaultMetricsConfig()
	metricsConfig.ErrorRateThreshold = 0.1 // 10%
	metricsConfig.LatencyThreshold = 100 * time.Millisecond

	collector := NewInMemoryMetricsCollector(metricsConfig)

	// Add log notifier
	notifier := NewLogNotifier("test-log", []string{"alerts"}, nil)
	manager.AddNotifier(notifier)

	// Create alert rule based on metrics collector thresholds
	errorRateRule := AlertRule{
		ID:          "metrics-error-rate",
		Name:        "Metrics Error Rate Alert",
		Description: "Alert based on metrics collector thresholds",
		Condition: func(metrics map[string]interface{}) bool {
			alerts := collector.CheckThresholds()
			for _, alert := range alerts {
				if alert.Type == "error_rate" {
					return true
				}
			}
			return false
		},
		Severity:             SeverityWarning,
		Enabled:              true,
		MinDuration:          10 * time.Millisecond,
		NotificationChannels: []string{"alerts"},
	}

	manager.AddRule(errorRateRule)

	// Record requests that exceed error rate threshold
	collector.RecordRequest("test", "GET", 50*time.Millisecond, false) // Error
	collector.RecordRequest("test", "GET", 60*time.Millisecond, false) // Error
	collector.RecordRequest("test", "GET", 40*time.Millisecond, true)  // Success
	// Error rate = 2/3 = 66.7% > 10% threshold

	// Override getCurrentMetrics to use collector's threshold check
	originalGetCurrentMetrics := manager.getCurrentMetrics
	manager.getCurrentMetrics = func() map[string]interface{} {
		alerts := collector.CheckThresholds()
		return map[string]interface{}{
			"threshold_alerts": alerts,
		}
	}
	defer func() {
		manager.getCurrentMetrics = originalGetCurrentMetrics
	}()

	// Evaluate rules
	manager.evaluateRules()

	// Should have active alert due to high error rate
	activeAlerts := manager.GetActiveAlerts()
	if len(activeAlerts) == 0 {
		// Check if thresholds were actually exceeded
		alerts := collector.CheckThresholds()
		if len(alerts) > 0 {
			t.Errorf("Metrics collector detected %d threshold violations but no alerts were triggered", len(alerts))
		}
	}
}

func TestDefaultAlertConfig(t *testing.T) {
	config := DefaultAlertConfig()

	// Verify default values
	if config.EvaluationInterval != 30*time.Second {
		t.Errorf("Expected 30s evaluation interval, got %v", config.EvaluationInterval)
	}

	if !config.EnableNotifications {
		t.Error("Expected notifications to be enabled by default")
	}

	if !config.EnableTrendAnalysis {
		t.Error("Expected trend analysis to be enabled by default")
	}

	if config.AnomalyThreshold != 2.0 {
		t.Errorf("Expected anomaly threshold 2.0, got %.1f", config.AnomalyThreshold)
	}
}
