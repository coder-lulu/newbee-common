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
	"net/http"
	"time"
	
	"github.com/coder-lulu/newbee-common/middleware/types"
)

// MonitoringMiddleware 监控中间件实现
type MonitoringMiddleware struct {
	*types.BaseMiddleware
	config *MonitoringConfig
}

// NewMonitoringMiddleware 创建监控中间件
func NewMonitoringMiddleware(config *MonitoringConfig) types.Middleware {
	base := types.NewBaseMiddleware("monitoring", types.PriorityMonitoring, config.Enabled)
	return &MonitoringMiddleware{
		BaseMiddleware: base,
		config:         config,
	}
}

// Handle 处理HTTP请求
func (m *MonitoringMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 检查是否启用
		if !m.IsEnabled() {
			next(w, r)
			return
		}
		
		// 记录开始时间
		startTime := time.Now()
		
		// 创建响应写入器包装器来捕获状态码
		wrapper := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}
		
		// 执行下一个中间件
		next(wrapper, r)
		
		// 记录指标
		duration := time.Since(startTime)
		m.recordMetrics(r, wrapper.statusCode, duration)
	}
}

// responseWriter 响应写入器包装器
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader 捕获状态码
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// recordMetrics 记录指标
func (m *MonitoringMiddleware) recordMetrics(r *http.Request, statusCode int, duration time.Duration) {
	// 这里应该实现具体的指标记录逻辑
	// 例如记录到Prometheus、StatsD等监控系统
	
	// 记录请求计数
	// 记录响应时间
	// 记录状态码分布
	// 记录错误率等
	
	// 示例：简单的日志记录
	// logx.Infow("HTTP Request Metrics",
	//     logx.Field("method", r.Method),
	//     logx.Field("path", r.URL.Path),
	//     logx.Field("status", statusCode),
	//     logx.Field("duration_ms", duration.Milliseconds()),
	// )
}