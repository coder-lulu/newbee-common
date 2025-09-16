// Copyright 2024 The NewBee Authors. All Rights Reserved.

// 监控系统使用示例
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/monitoring"
)

func main() {
	// 1. 创建监控管理器
	fmt.Println("=== NewBee 监控系统演示 ===")
	
	// 使用生产环境预设配置
	manager, err := monitoring.CreateProductionMonitoringSetup()
	if err != nil {
		log.Fatalf("Failed to create monitoring manager: %v", err)
	}
	
	// 启动监控
	ctx := context.Background()
	if err := manager.Start(ctx); err != nil {
		log.Fatalf("Failed to start monitoring: %v", err)
	}
	defer manager.Stop()
	
	fmt.Println("✅ 监控系统已启动")
	
	// 2. 演示缓存监控
	demonstrateCacheMonitoring(manager)
	
	// 3. 演示安全事件监控
	demonstrateSecurityMonitoring(manager, ctx)
	
	// 4. 生成监控报告
	generateMonitoringReports(manager)
	
	// 5. 查看监控概览
	showMonitoringOverview(manager)
	
	fmt.Println("\n🎉 监控系统演示完成")
	fmt.Println("📊 监控数据可通过 http://localhost:9090/monitoring/* 访问")
}

func demonstrateCacheMonitoring(manager *monitoring.MonitoringManager) {
	fmt.Println("\n--- 缓存监控演示 ---")
	
	// 注：在实际使用中，这里会创建和包装真实的缓存
	fmt.Println("🔄 缓存监控已就绪 (演示模式)")
	
	// 获取缓存指标
	cacheMetrics := manager.GetMonitoringOverview()
	fmt.Printf("✅ 缓存监控配置完成，活跃告警数: %d\n", cacheMetrics.ActiveAlertsCount)
}

func demonstrateSecurityMonitoring(manager *monitoring.MonitoringManager, ctx context.Context) {
	fmt.Println("\n--- 安全事件监控演示 ---")
	
	// 模拟各种安全事件
	fmt.Println("🚨 模拟安全违规事件...")
	
	// 1. 租户跨访问尝试
	manager.RecordTenantViolation(ctx, "tenant_123", "user_456", "/api/v1/users", 
		map[string]interface{}{
			"attempted_tenant": "tenant_999",
			"reason":          "cross_tenant_access",
		})
	
	// 2. 认证失败
	manager.RecordAuthFailure(ctx, "invalid_token", 
		map[string]interface{}{
			"token_type": "JWT",
			"error":     "signature verification failed",
		})
	
	// 3. 权限违规
	manager.RecordPermissionViolation(ctx, "tenant_123", "user_456", "/api/v1/admin", "admin", 
		map[string]interface{}{
			"required_permission": "admin",
			"user_permissions":   []string{"user", "read"},
		})
	
	// 4. 限流触发
	manager.RecordRateLimitViolation(ctx, "tenant_123", 100, 
		map[string]interface{}{
			"current_rate": 150,
			"window":      "1 minute",
		})
	
	fmt.Println("✅ 安全事件记录完成")
}

func generateMonitoringReports(manager *monitoring.MonitoringManager) {
	fmt.Println("\n--- 监控报告生成 ---")
	
	reporter := monitoring.NewMonitoringReporter(manager)
	
	// 生成性能报告
	fmt.Println("📈 生成性能报告...")
	perfReport := reporter.GeneratePerformanceReport()
	fmt.Printf("性能报告: 中间件数量=%d, 总请求=%d\n", 
		len(perfReport.MiddlewareStats), perfReport.Summary.TotalRequests)
	
	// 生成缓存报告
	fmt.Println("🗄️ 生成缓存报告...")
	cacheReport := reporter.GenerateCacheReport()
	fmt.Printf("缓存报告: 缓存数量=%d, 总命中=%d, 总未命中=%d\n", 
		cacheReport.Summary.TotalCaches, cacheReport.Summary.TotalHits, cacheReport.Summary.TotalMisses)
	
	// 生成安全报告
	fmt.Println("🔒 生成安全报告...")
	secReport := reporter.GenerateSecurityReport()
	fmt.Printf("安全报告: 总违规=%d, 可疑IP数量=%d\n", 
		secReport.Summary.TotalViolations, secReport.Summary.SuspiciousIPCount)
	
	// 生成健康报告
	fmt.Println("💚 生成健康报告...")
	healthReport := reporter.GenerateHealthReport()
	fmt.Printf("健康报告: 整体状态=%s, 组件数量=%d\n", 
		healthReport.OverallStatus, len(healthReport.ComponentsHealth))
	
	fmt.Println("✅ 所有报告生成完成")
}

func showMonitoringOverview(manager *monitoring.MonitoringManager) {
	fmt.Println("\n--- 监控系统概览 ---")
	
	overview := manager.GetMonitoringOverview()
	
	fmt.Printf("📊 监控状态: %s\n", overview.Status)
	fmt.Printf("⏰ 启动时间: %s\n", overview.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("⏱️ 运行时长: %v\n", overview.Uptime)
	fmt.Printf("🚨 活跃告警: %d\n", overview.ActiveAlertsCount)
	
	fmt.Println("\n🔧 组件状态:")
	for component, status := range overview.ComponentsStatus {
		fmt.Printf("  - %s: %s\n", component, status)
	}
	
	// 获取健康报告
	healthReport := manager.GetHealthReport()
	fmt.Printf("\n💚 整体健康状态: %s\n", healthReport.OverallStatus)
	fmt.Printf("📊 健康摘要: 总计=%d, 健康=%d, 降级=%d, 不健康=%d\n",
		healthReport.Summary.TotalComponents,
		healthReport.Summary.HealthyComponents,
		healthReport.Summary.DegradedComponents,
		healthReport.Summary.UnhealthyComponents)
}

// 演示最佳实践助手
func demonstrateBestPractices(manager *monitoring.MonitoringManager) {
	fmt.Println("\n--- 最佳实践验证 ---")
	
	practices := monitoring.NewMonitoringBestPractices(manager)
	
	// 验证配置
	issues := practices.ValidateConfiguration()
	if len(issues) > 0 {
		fmt.Println("⚠️ 配置问题:")
		for _, issue := range issues {
			fmt.Printf("  - [%s] %s: %s\n", issue.Severity, issue.Component, issue.Issue)
		}
	} else {
		fmt.Println("✅ 监控配置验证通过")
	}
	
	// 获取优化建议
	suggestions := practices.GetOptimizationSuggestions()
	if len(suggestions) > 0 {
		fmt.Println("\n💡 优化建议:")
		for _, suggestion := range suggestions {
			fmt.Printf("  - [%s] %s: %s\n", 
				suggestion.Priority, suggestion.Component, suggestion.Suggestion)
		}
	} else {
		fmt.Println("✅ 系统运行良好，暂无优化建议")
	}
}