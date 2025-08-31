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

package monitoring

import (
	"fmt"
	"github.com/coder-lulu/newbee-common/middleware/types"
)

// MonitoringMiddlewareFactory 监控中间件工厂
type MonitoringMiddlewareFactory struct{}

// NewMonitoringMiddlewareFactory 创建监控中间件工厂
func NewMonitoringMiddlewareFactory() types.MiddlewareFactory {
	return &MonitoringMiddlewareFactory{}
}

// Create 创建监控中间件实例
func (f *MonitoringMiddlewareFactory) Create(config map[string]interface{}) (types.Middleware, error) {
	// 解析配置
	monitoringConfig, err := parseMonitoringConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse monitoring config: %w", err)
	}
	
	// 创建监控中间件
	return NewMonitoringMiddleware(monitoringConfig), nil
}

// GetType 获取中间件类型
func (f *MonitoringMiddlewareFactory) GetType() string {
	return types.TypeMonitoring
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	// 是否启用
	Enabled bool `json:"enabled"`
	
	// 指标收集间隔（秒）
	MetricsInterval int `json:"metrics_interval"`
	
	// 是否启用性能监控
	PerformanceEnabled bool `json:"performance_enabled"`
	
	// 是否启用内存监控
	MemoryEnabled bool `json:"memory_enabled"`
	
	// 监控端点路径
	MetricsPath string `json:"metrics_path"`
	
	// Prometheus配置
	PrometheusEnabled bool   `json:"prometheus_enabled"`
	PrometheusPrefix  string `json:"prometheus_prefix"`
}

// parseMonitoringConfig 解析监控配置
func parseMonitoringConfig(config map[string]interface{}) (*MonitoringConfig, error) {
	monitoringConfig := &MonitoringConfig{
		Enabled:            true,
		MetricsInterval:    60,
		PerformanceEnabled: true,
		MemoryEnabled:      true,
		MetricsPath:        "/metrics",
		PrometheusEnabled:  true,
		PrometheusPrefix:   "newbee_",
	}
	
	if enabled, ok := config["enabled"].(bool); ok {
		monitoringConfig.Enabled = enabled
	}
	
	if interval, ok := config["metrics_interval"].(int); ok {
		monitoringConfig.MetricsInterval = interval
	}
	
	if perfEnabled, ok := config["performance_enabled"].(bool); ok {
		monitoringConfig.PerformanceEnabled = perfEnabled
	}
	
	if memEnabled, ok := config["memory_enabled"].(bool); ok {
		monitoringConfig.MemoryEnabled = memEnabled
	}
	
	if path, ok := config["metrics_path"].(string); ok {
		monitoringConfig.MetricsPath = path
	}
	
	if promEnabled, ok := config["prometheus_enabled"].(bool); ok {
		monitoringConfig.PrometheusEnabled = promEnabled
	}
	
	if prefix, ok := config["prometheus_prefix"].(string); ok {
		monitoringConfig.PrometheusPrefix = prefix
	}
	
	return monitoringConfig, nil
}