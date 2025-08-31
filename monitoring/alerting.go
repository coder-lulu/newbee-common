package monitoring

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type AlertRule struct {
	Name        string
	Description string
	Evaluate    func() bool
	LastTriggered time.Time
	Cooldown    time.Duration
}

type AlertManager struct {
	mu     sync.RWMutex
	rules  []AlertRule
	alerts []Alert
}

type Alert struct {
	Rule        string
	Description string
	Timestamp   time.Time
}

func NewAlertManager() *AlertManager {
	return &AlertManager{
		rules:  make([]AlertRule, 0),
		alerts: make([]Alert, 0),
	}
}

func (am *AlertManager) AddRule(rule AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rules = append(am.rules, rule)
}

func (am *AlertManager) EvaluateRules() []Alert {
	am.mu.Lock()
	defer am.mu.Unlock()

	currentTime := time.Now()
	triggeredAlerts := make([]Alert, 0)

	for _, rule := range am.rules {
		if currentTime.Sub(rule.LastTriggered) < rule.Cooldown {
			continue
		}

		if rule.Evaluate() {
			alert := Alert{
				Rule:        rule.Name,
				Description: rule.Description,
				Timestamp:   currentTime,
			}
			triggeredAlerts = append(triggeredAlerts, alert)
			rule.LastTriggered = currentTime
		}
	}

	am.alerts = append(am.alerts, triggeredAlerts...)
	return triggeredAlerts
}

func CreateAuthAlertRules() *AlertManager {
	alertManager := NewAlertManager()

	// 高失败率告警
	alertManager.AddRule(AlertRule{
		Name:        "High Auth Failure Rate",
		Description: "Authentication failure rate exceeds 10%",
		Evaluate: func() bool {
			totalRequests := AuthRequestTotal.WithLabelValues("total", "").Value()
			failedRequests := AuthRequestTotal.WithLabelValues("failed", "").Value()
			
			failureRate := failedRequests / totalRequests
			return failureRate > 0.1
		},
		Cooldown: 5 * time.Minute,
	})

	// 高延迟告警
	alertManager.AddRule(AlertRule{
		Name:        "High Auth Latency",
		Description: "Authentication request latency exceeds 500ms",
		Evaluate: func() bool {
			latencyVec, err := AuthRequestLatency.GetMetricWith(prometheus.Labels{
				"status": "total",
				"tenant": "",
			})
			if err != nil {
				return false
			}

			latencyMetric := latencyVec.(*prometheus.HistogramVec)
			latencyValue := latencyMetric.WithLabelValues("total", "").Buckets()[4] // 500ms bucket
			return latencyValue > 0.5
		},
		Cooldown: 10 * time.Minute,
	})

	// 安全事件告警
	alertManager.AddRule(AlertRule{
		Name:        "Suspicious Security Events",
		Description: "Multiple security violations detected",
		Evaluate: func() bool {
			violations := SecurityViolations.WithLabelValues("unauthorized_access", "").Value()
			return violations > 5
		},
		Cooldown: 15 * time.Minute,
	})

	return alertManager
}

func (am *AlertManager) SendAlerts(alerts []Alert) error {
	// TODO: 实现多渠道告警通知 (Email, Slack, PagerDuty等)
	for _, alert := range alerts {
		fmt.Printf("ALERT: %s - %s at %v\n", 
			alert.Rule, alert.Description, alert.Timestamp)
	}
	return nil
}

func StartAlertMonitoring(am *AlertManager, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		alerts := am.EvaluateRules()
		if len(alerts) > 0 {
			am.SendAlerts(alerts)
		}
	}
}