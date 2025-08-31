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

	"github.com/zeromicro/go-zero/core/logx"
)

// LogNotifier implements AlertNotifier using structured logging
type LogNotifier struct {
	name     string
	channels []string
	config   *LogNotifierConfig
}

// LogNotifierConfig defines configuration for log-based notifications
type LogNotifierConfig struct {
	LogLevel      string `json:"log_level"`      // info, warn, error
	IncludeLabels bool   `json:"include_labels"` // Include alert labels in log
	IncludeValues bool   `json:"include_values"` // Include metric values
	Structured    bool   `json:"structured"`     // Use structured logging
}

// DefaultLogNotifierConfig returns default configuration
func DefaultLogNotifierConfig() *LogNotifierConfig {
	return &LogNotifierConfig{
		LogLevel:      "warn",
		IncludeLabels: true,
		IncludeValues: true,
		Structured:    true,
	}
}

// NewLogNotifier creates a new log-based alert notifier
func NewLogNotifier(name string, channels []string, config *LogNotifierConfig) *LogNotifier {
	if config == nil {
		config = DefaultLogNotifierConfig()
	}

	return &LogNotifier{
		name:     name,
		channels: channels,
		config:   config,
	}
}

// Name returns the notifier name
func (ln *LogNotifier) Name() string {
	return ln.name
}

// Channels returns the channels this notifier handles
func (ln *LogNotifier) Channels() []string {
	return ln.channels
}

// Notify sends a notification via structured logging
func (ln *LogNotifier) Notify(ctx context.Context, alert *ActiveAlert, event AlertEventType) error {
	// Build log message
	message := fmt.Sprintf("Alert %s: %s", event.String(), alert.Rule.Name)

	// Build log fields
	fields := []logx.LogField{
		logx.Field("alert_id", alert.Rule.ID),
		logx.Field("alert_name", alert.Rule.Name),
		logx.Field("severity", alert.Rule.Severity.String()),
		logx.Field("state", alert.State.String()),
		logx.Field("event", event.String()),
		logx.Field("start_time", alert.StartTime),
		logx.Field("last_seen", alert.LastSeen),
		logx.Field("notifier", ln.name),
	}

	// Add labels if configured
	if ln.config.IncludeLabels && len(alert.Labels) > 0 {
		fields = append(fields, logx.Field("labels", alert.Labels))
	}

	// Add values if configured
	if ln.config.IncludeValues {
		fields = append(fields, logx.Field("value", alert.Value))
	}

	// Add annotations if present
	if len(alert.Annotations) > 0 {
		fields = append(fields, logx.Field("annotations", alert.Annotations))
	}

	// Add escalation info for firing alerts
	if alert.State == StateFiring {
		fields = append(fields,
			logx.Field("escalation_level", alert.EscalationLevel),
			logx.Field("notification_count", alert.NotificationCount))
	}

	// Log based on configured level and alert severity
	switch ln.determineLogLevel(alert) {
	case "error":
		logx.Errorw(message, fields...)
	case "warn":
		logx.Infow(message, fields...)
	case "info":
		logx.Infow(message, fields...)
	default:
		logx.Infow(message, fields...)
	}

	return nil
}

// determineLogLevel determines the appropriate log level based on alert severity and event
func (ln *LogNotifier) determineLogLevel(alert *ActiveAlert) string {
	// Override based on alert severity
	switch alert.Rule.Severity {
	case SeverityEmergency, SeverityCritical:
		return "error"
	case SeverityWarning:
		return "warn"
	case SeverityInfo:
		return "info"
	default:
		return ln.config.LogLevel
	}
}
