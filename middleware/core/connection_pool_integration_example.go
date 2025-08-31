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

// 连接池优化集成示例
// 演示如何集成和使用连接池优化器、监控器和报警管理器

package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
)

// ConnectionPoolExample 连接池集成示例
type ConnectionPoolExample struct {
	optimizer   *ConnectionPoolOptimizer
	redisClient redis.UniversalClient
	dbClient    *sql.DB
}

// NewConnectionPoolExample 创建连接池示例
func NewConnectionPoolExample() *ConnectionPoolExample {
	return &ConnectionPoolExample{}
}

// Initialize 初始化示例
func (cpe *ConnectionPoolExample) Initialize() error {
	// 1. 创建Redis客户端
	if err := cpe.setupRedisClient(); err != nil {
		return fmt.Errorf("failed to setup redis client: %w", err)
	}

	// 2. 创建数据库客户端
	if err := cpe.setupDBClient(); err != nil {
		return fmt.Errorf("failed to setup database client: %w", err)
	}

	// 3. 创建连接池优化器
	if err := cpe.setupOptimizer(); err != nil {
		return fmt.Errorf("failed to setup optimizer: %w", err)
	}

	return nil
}

// setupRedisClient 设置Redis客户端
func (cpe *ConnectionPoolExample) setupRedisClient() error {
	// 使用优化的Redis配置
	config := GetDefaultRedisConfig()

	// 根据环境调整配置
	cpe.adjustRedisConfigForEnvironment(config)

	// 创建Redis客户端
	options := &redis.UniversalOptions{
		Addrs:              config.Addrs,
		Password:           config.Password,
		DB:                 config.DB,
		PoolSize:           config.PoolSize,
		MinIdleConns:       config.MinIdleConns,
		ConnMaxLifetime:    config.ConnMaxLifetime,
		ConnMaxIdleTime:    config.ConnMaxIdleTime,
		DialTimeout:        config.DialTimeout,
		ReadTimeout:        config.ReadTimeout,
		WriteTimeout:       config.WriteTimeout,
		PoolTimeout:        config.PoolTimeout,
		IdleCheckFrequency: config.IdleCheckFrequency,
		MaxRetries:         config.MaxRetries,
		RetryDelayFunc: func(retry int, err error) time.Duration {
			return config.RetryDelay * time.Duration(retry+1)
		},
	}

	cpe.redisClient = redis.NewUniversalClient(options)

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := cpe.redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis connection test failed: %w", err)
	}

	log.Printf("Redis client connected successfully with pool size: %d", config.PoolSize)
	return nil
}

// setupDBClient 设置数据库客户端
func (cpe *ConnectionPoolExample) setupDBClient() error {
	// 使用优化的数据库配置
	config := GetDefaultDBConfig()

	// 根据环境调整配置
	cpe.adjustDBConfigForEnvironment(config)

	// 创建数据库连接
	// 注意：这里使用示例DSN，实际使用时需要配置真实的数据库连接信息
	dsn := "user:password@tcp(localhost:3306)/dbname?parseTime=true&timeout=5s&readTimeout=6s&writeTimeout=6s"

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// 应用连接池配置
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		// 如果数据库连接失败，我们仍然可以继续（仅用于演示）
		log.Printf("Database connection test failed (continuing anyway): %v", err)
		cpe.dbClient = nil
	} else {
		cpe.dbClient = db
		log.Printf("Database client connected successfully with max connections: %d", config.MaxOpenConns)
	}

	return nil
}

// setupOptimizer 设置优化器
func (cpe *ConnectionPoolExample) setupOptimizer() error {
	// 创建完整的连接池配置
	config := &ConnectionPoolConfig{
		Redis:      GetDefaultRedisConfig(),
		Database:   GetDefaultDBConfig(),
		AutoTuning: GetDefaultAutoTuningConfig(),
		Monitoring: cpe.getMonitoringConfig(),
		Alert:      GetDefaultAlertConfig(),
	}

	// 创建优化器
	cpe.optimizer = NewConnectionPoolOptimizer(
		cpe.redisClient,
		cpe.dbClient,
		config,
	)

	// 添加日志报警订阅者
	logSubscriber := &LogAlertSubscriber{}
	cpe.optimizer.alertManager.AddSubscriber(logSubscriber)

	// 启动优化器
	if err := cpe.optimizer.Start(); err != nil {
		return fmt.Errorf("failed to start optimizer: %w", err)
	}

	log.Println("Connection pool optimizer started successfully")
	return nil
}

// adjustRedisConfigForEnvironment 根据环境调整Redis配置
func (cpe *ConnectionPoolExample) adjustRedisConfigForEnvironment(config *OptimizedRedisConfig) {
	// 示例：根据不同环境调整配置
	env := getEnvironment()

	switch env {
	case "production":
		// 生产环境：更大的连接池，更长的超时
		config.PoolSize = config.PoolSize * 2
		config.ReadTimeout = time.Second * 5
		config.WriteTimeout = time.Second * 5
		config.ConnMaxLifetime = time.Hour * 2

	case "staging":
		// 预发布环境：中等配置
		config.PoolSize = config.PoolSize * 3 / 2
		config.ConnMaxLifetime = time.Hour

	case "development":
		// 开发环境：较小的连接池
		config.PoolSize = config.PoolSize / 2
		config.MinIdleConns = config.MinIdleConns / 2

	default:
		// 默认配置保持不变
	}

	// 示例Redis地址配置
	config.Addrs = []string{"localhost:6379"}
	config.Password = ""
	config.DB = 0
}

// adjustDBConfigForEnvironment 根据环境调整数据库配置
func (cpe *ConnectionPoolExample) adjustDBConfigForEnvironment(config *OptimizedDBConfig) {
	env := getEnvironment()

	switch env {
	case "production":
		// 生产环境：更多连接，更长生命周期
		config.MaxOpenConns = config.MaxOpenConns * 2
		config.MaxIdleConns = config.MaxIdleConns * 2
		config.ConnMaxLifetime = time.Hour * 4
		config.QueryTimeout = time.Second * 60

	case "staging":
		// 预发布环境：中等配置
		config.MaxOpenConns = config.MaxOpenConns * 3 / 2
		config.ConnMaxLifetime = time.Hour * 2

	case "development":
		// 开发环境：较少连接
		config.MaxOpenConns = config.MaxOpenConns / 2
		config.MaxIdleConns = config.MaxIdleConns / 2
		config.QueryTimeout = time.Second * 10

	default:
		// 默认配置保持不变
	}
}

// getMonitoringConfig 获取监控配置
func (cpe *ConnectionPoolExample) getMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		EnableMetrics:       true,
		MetricsInterval:     time.Second * 30,
		MetricsRetention:    time.Hour * 24,
		EnableHealthCheck:   true,
		HealthCheckInterval: time.Minute * 5,
		EnableAlerts:        true,
		AlertRules: []AlertRule{
			{
				Name:        "high_pool_usage",
				Condition:   "pool_usage > 0.8",
				Severity:    "warning",
				Description: "Connection pool usage is high",
			},
			{
				Name:        "connection_errors",
				Condition:   "error_rate > 0.01",
				Severity:    "critical",
				Description: "High connection error rate detected",
			},
		},
	}
}

// getEnvironment 获取当前环境
func getEnvironment() string {
	// 简单的环境检测逻辑
	// 实际实现中可能从环境变量或配置文件中读取
	return "development"
}

// RunExample 运行示例
func (cpe *ConnectionPoolExample) RunExample() error {
	log.Println("Starting connection pool optimization example...")

	// 初始化
	if err := cpe.Initialize(); err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	// 运行示例操作
	ctx := context.Background()

	// 1. 执行一些Redis操作来生成指标
	cpe.performRedisOperations(ctx)

	// 2. 执行一些数据库操作（如果可用）
	if cpe.dbClient != nil {
		cpe.performDBOperations(ctx)
	}

	// 3. 等待一段时间让监控收集指标
	log.Println("Waiting for metrics collection...")
	time.Sleep(time.Minute)

	// 4. 获取并显示指标
	cpe.displayMetrics()

	// 5. 显示自适应调整历史
	cpe.displayAdjustmentHistory()

	// 6. 显示报警统计
	cpe.displayAlertStatistics()

	// 7. 测试报警功能
	cpe.testAlertSystem()

	// 8. 生成性能报告
	cpe.generatePerformanceReport()

	return nil
}

// performRedisOperations 执行Redis操作
func (cpe *ConnectionPoolExample) performRedisOperations(ctx context.Context) {
	log.Println("Performing Redis operations...")

	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("test:key:%d", i)
		value := fmt.Sprintf("value_%d", i)

		// SET操作
		if err := cpe.redisClient.Set(ctx, key, value, time.Minute).Err(); err != nil {
			log.Printf("Redis SET error: %v", err)
		}

		// GET操作
		if _, err := cpe.redisClient.Get(ctx, key).Result(); err != nil {
			log.Printf("Redis GET error: %v", err)
		}

		// 模拟一些负载
		if i%10 == 0 {
			time.Sleep(time.Millisecond * 10)
		}
	}

	log.Println("Redis operations completed")
}

// performDBOperations 执行数据库操作
func (cpe *ConnectionPoolExample) performDBOperations(ctx context.Context) {
	log.Println("Performing database operations...")

	for i := 0; i < 50; i++ {
		// 简单的查询操作
		rows, err := cpe.dbClient.QueryContext(ctx, "SELECT 1 as test_col")
		if err != nil {
			log.Printf("Database query error: %v", err)
			continue
		}
		rows.Close()

		// 模拟一些负载
		if i%5 == 0 {
			time.Sleep(time.Millisecond * 5)
		}
	}

	log.Println("Database operations completed")
}

// displayMetrics 显示指标
func (cpe *ConnectionPoolExample) displayMetrics() {
	log.Println("=== Connection Pool Metrics ===")

	metrics, err := cpe.optimizer.GetConnectionPoolMetrics()
	if err != nil {
		log.Printf("Failed to get metrics: %v", err)
		return
	}

	// 显示Redis指标
	if metrics.Redis != nil {
		log.Printf("Redis Metrics:")
		log.Printf("  Total Connections: %d", metrics.Redis.TotalConns)
		log.Printf("  Idle Connections: %d", metrics.Redis.IdleConns)
		log.Printf("  Hits: %d", metrics.Redis.Hits)
		log.Printf("  Misses: %d", metrics.Redis.Misses)
		log.Printf("  Average Command Time: %v", metrics.Redis.AvgCmdTime)
		log.Printf("  Connection Errors: %d", metrics.Redis.ConnErrors)
	}

	// 显示数据库指标
	if metrics.Database != nil {
		log.Printf("Database Metrics:")
		log.Printf("  Open Connections: %d", metrics.Database.OpenConnections)
		log.Printf("  In Use Connections: %d", metrics.Database.InUseConnections)
		log.Printf("  Idle Connections: %d", metrics.Database.IdleConnections)
		log.Printf("  Wait Count: %d", metrics.Database.WaitCount)
		log.Printf("  Wait Duration: %v", metrics.Database.WaitDuration)
	}

	// 显示系统指标
	if metrics.System != nil {
		log.Printf("System Metrics:")
		log.Printf("  Goroutine Count: %d", metrics.System.GoroutineCount)
		log.Printf("  Heap Size: %d bytes", metrics.System.HeapSize)
		log.Printf("  Heap In Use: %d bytes", metrics.System.HeapInUse)
		log.Printf("  GC Pause Time: %v", metrics.System.GCPauseTime)
	}
}

// displayAdjustmentHistory 显示调整历史
func (cpe *ConnectionPoolExample) displayAdjustmentHistory() {
	log.Println("=== Auto-tuning Adjustment History ===")

	history := cpe.optimizer.GetAdjustmentHistory()
	if len(history) == 0 {
		log.Println("No adjustments have been made yet")
		return
	}

	for _, record := range history {
		status := "SUCCESS"
		if !record.Successful {
			status = "FAILED"
		}

		log.Printf("[%s] %s %s.%s: %d -> %d (%s) [%s]",
			record.Timestamp.Format("15:04:05"),
			status,
			record.Type,
			record.Parameter,
			record.OldValue,
			record.NewValue,
			record.Reason,
		)
	}
}

// displayAlertStatistics 显示报警统计
func (cpe *ConnectionPoolExample) displayAlertStatistics() {
	log.Println("=== Alert Statistics ===")

	stats := cpe.optimizer.alertManager.GetAlertStatistics(time.Hour)

	log.Printf("Total Alerts (last hour): %d", stats.TotalAlerts)
	log.Printf("Resolved Alerts: %d", stats.ResolvedAlerts)
	log.Printf("Resolution Rate: %.2f%%", stats.ResolutionRate*100)
	log.Printf("Average Resolution Time: %v", stats.AvgResolutionTime)

	if len(stats.AlertsByType) > 0 {
		log.Println("Alerts by Type:")
		for alertType, count := range stats.AlertsByType {
			log.Printf("  %s: %d", alertType, count)
		}
	}

	if len(stats.AlertsByLevel) > 0 {
		log.Println("Alerts by Level:")
		for level, count := range stats.AlertsByLevel {
			log.Printf("  %s: %d", level, count)
		}
	}
}

// testAlertSystem 测试报警系统
func (cpe *ConnectionPoolExample) testAlertSystem() {
	log.Println("=== Testing Alert System ===")

	// 发送测试报警
	if err := cpe.optimizer.alertManager.TestAlert(); err != nil {
		log.Printf("Failed to send test alert: %v", err)
	} else {
		log.Println("Test alert sent successfully")
	}

	// 等待报警处理
	time.Sleep(time.Second * 2)

	// 显示活跃报警
	activeAlerts := cpe.optimizer.alertManager.GetActiveAlerts()
	log.Printf("Active alerts: %d", len(activeAlerts))

	for _, alert := range activeAlerts {
		log.Printf("  [%s] %s: %s", alert.Level, alert.Type, alert.Title)
	}
}

// generatePerformanceReport 生成性能报告
func (cpe *ConnectionPoolExample) generatePerformanceReport() {
	log.Println("=== Performance Report ===")

	report, err := cpe.optimizer.monitor.GetPerformanceReport()
	if err != nil {
		log.Printf("Failed to generate performance report: %v", err)
		return
	}

	log.Printf("Overall Health: %s", report.OverallHealth)

	if report.Redis != nil {
		log.Printf("Redis Health Score: %.1f/100", report.Redis.HealthScore)
		log.Printf("Redis Pool Usage: %.2f%%", report.Redis.PoolUsage*100)
		log.Printf("Redis Hit Rate: %.2f%%", report.Redis.HitRate*100)
		log.Printf("Redis Error Rate: %.4f%%", report.Redis.ErrorRate*100)
	}

	if report.Database != nil {
		log.Printf("Database Health Score: %.1f/100", report.Database.HealthScore)
		log.Printf("Database Pool Usage: %.2f%%", report.Database.PoolUsage*100)
		log.Printf("Database Connection Efficiency: %.2f%%", report.Database.ConnectionEfficiency*100)
	}

	if report.System != nil {
		log.Printf("System Health Score: %.1f/100", report.System.HealthScore)
		log.Printf("System CPU Usage: %.2f%%", report.System.CPUUsage*100)
		log.Printf("System Memory Usage: %.2f%%", report.System.MemoryUsage*100)
	}

	if len(report.Recommendations) > 0 {
		log.Println("Recommendations:")
		for _, recommendation := range report.Recommendations {
			log.Printf("  - %s", recommendation)
		}
	}
}

// Cleanup 清理资源
func (cpe *ConnectionPoolExample) Cleanup() {
	log.Println("Cleaning up resources...")

	if cpe.optimizer != nil {
		if err := cpe.optimizer.Stop(); err != nil {
			log.Printf("Failed to stop optimizer: %v", err)
		}
	}

	if cpe.redisClient != nil {
		if err := cpe.redisClient.Close(); err != nil {
			log.Printf("Failed to close Redis client: %v", err)
		}
	}

	if cpe.dbClient != nil {
		if err := cpe.dbClient.Close(); err != nil {
			log.Printf("Failed to close database client: %v", err)
		}
	}

	log.Println("Cleanup completed")
}

// RunConnectionPoolExample 运行连接池优化示例
func RunConnectionPoolExample() {
	example := NewConnectionPoolExample()

	// 运行示例
	if err := example.RunExample(); err != nil {
		log.Fatalf("Example failed: %v", err)
	}

	// 等待一段时间观察自适应调整
	log.Println("Observing auto-tuning for 2 minutes...")
	time.Sleep(time.Minute * 2)

	// 最终显示结果
	example.displayMetrics()
	example.displayAdjustmentHistory()

	// 清理资源
	example.Cleanup()

	log.Println("Connection pool optimization example completed successfully!")
}

// 配置相关的辅助结构体（如果不存在的话）
type MonitoringConfig struct {
	EnableMetrics       bool          `json:"enable_metrics"`
	MetricsInterval     time.Duration `json:"metrics_interval"`
	MetricsRetention    time.Duration `json:"metrics_retention"`
	EnableHealthCheck   bool          `json:"enable_health_check"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	EnableAlerts        bool          `json:"enable_alerts"`
	AlertRules          []AlertRule   `json:"alert_rules"`
}

type AlertRule struct {
	Name        string `json:"name"`
	Condition   string `json:"condition"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}
