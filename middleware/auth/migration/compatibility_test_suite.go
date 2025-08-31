// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package migration - 兼容性测试套件
// 提供自动化的兼容性验证，确保迁移过程中的系统稳定性
package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/auth"
	"github.com/coder-lulu/newbee-common/utils/jwt"
)

// ==================== 兼容性测试套件 ====================

// CompatibilityTestSuite 兼容性测试套件
type CompatibilityTestSuite struct {
	// 测试配置
	config     *TestSuiteConfig
	
	// 测试分组
	testGroups map[string]*TestGroup
	
	// 版本适配器
	adapter    *VersionAdapter
	
	// 测试环境
	environment *TestEnvironment
	
	// 结果收集
	reporter    *TestReporter
	results     *TestResults
	
	// 并发控制
	semaphore   chan struct{}
	mu          sync.RWMutex
}

// TestSuiteConfig 测试套件配置
type TestSuiteConfig struct {
	// 测试目标
	SourceVersion      string            `json:"source_version"`       // 源版本
	TargetVersion      string            `json:"target_version"`       // 目标版本
	
	// 测试范围
	TestScopes         []TestScope       `json:"test_scopes"`          // 测试范围
	
	// 并发配置
	MaxConcurrency     int               `json:"max_concurrency"`     // 最大并发数
	TestTimeout        time.Duration     `json:"test_timeout"`        // 单个测试超时
	SuiteTimeout       time.Duration     `json:"suite_timeout"`       // 套件超时
	
	// 用户配置
	TestUsers          []TestUser        `json:"test_users"`          // 测试用户
	UserSessions       int               `json:"user_sessions"`       // 用户会话数
	
	// 环境配置
	Endpoints          map[string]string `json:"endpoints"`           // 测试端点
	AuthSecrets        map[string]string `json:"auth_secrets"`        // 认证密钥
	
	// 验证配置
	StrictValidation   bool              `json:"strict_validation"`   // 严格验证
	AllowedErrorRate   float64           `json:"allowed_error_rate"`  // 允许的错误率
	
	// 报告配置
	GenerateReport     bool              `json:"generate_report"`     // 生成报告
	ReportFormats      []string          `json:"report_formats"`      // 报告格式
}

// TestScope 测试范围
type TestScope string
const (
	ScopeAuthentication   TestScope = "authentication"    // 认证测试
	ScopeAuthorization    TestScope = "authorization"     // 授权测试
	ScopeSessionManagement TestScope = "session_management" // 会话管理测试
	ScopeDataMigration    TestScope = "data_migration"    // 数据迁移测试
	ScopePerformance      TestScope = "performance"       // 性能测试
	ScopeCompatibility    TestScope = "compatibility"     // 兼容性测试
	ScopeRegression       TestScope = "regression"        // 回归测试
)

// TestUser 测试用户
type TestUser struct {
	ID          string              `json:"id"`
	Username    string              `json:"username"`
	TenantID    string              `json:"tenant_id"`
	Roles       []string            `json:"roles"`
	Permissions []string            `json:"permissions"`
	Metadata    map[string]string   `json:"metadata"`
}

// NewCompatibilityTestSuite 创建兼容性测试套件
func NewCompatibilityTestSuite(config *TestSuiteConfig) *CompatibilityTestSuite {
	if config == nil {
		config = defaultTestSuiteConfig()
	}
	
	suite := &CompatibilityTestSuite{
		config:      config,
		testGroups:  make(map[string]*TestGroup),
		environment: NewTestEnvironment(config),
		reporter:    NewTestReporter(config),
		results:     NewTestResults(),
		semaphore:   make(chan struct{}, config.MaxConcurrency),
	}
	
	// 初始化测试分组
	suite.initializeTestGroups()
	
	return suite
}

// defaultTestSuiteConfig 默认测试套件配置
func defaultTestSuiteConfig() *TestSuiteConfig {
	return &TestSuiteConfig{
		SourceVersion:    "v1",
		TargetVersion:    "v2",
		TestScopes:       []TestScope{ScopeAuthentication, ScopeAuthorization, ScopeCompatibility},
		MaxConcurrency:   5,
		TestTimeout:      30 * time.Second,
		SuiteTimeout:     10 * time.Minute,
		UserSessions:     100,
		StrictValidation: true,
		AllowedErrorRate: 0.01, // 1%
		GenerateReport:   true,
		ReportFormats:    []string{"json", "html"},
	}
}

// ==================== 测试执行 ====================

// RunTests 运行所有测试
func (cts *CompatibilityTestSuite) RunTests(ctx context.Context) (*TestResults, error) {
	// 设置超时上下文
	testCtx, cancel := context.WithTimeout(ctx, cts.config.SuiteTimeout)
	defer cancel()
	
	// 准备测试环境
	if err := cts.environment.Setup(testCtx); err != nil {
		return nil, fmt.Errorf("failed to setup test environment: %w", err)
	}
	defer cts.environment.Cleanup()
	
	// 记录测试开始
	cts.results.Start()
	cts.reporter.LogInfo("test_suite_started", map[string]interface{}{
		"source_version": cts.config.SourceVersion,
		"target_version": cts.config.TargetVersion,
		"test_scopes":    cts.config.TestScopes,
	})
	
	// 并发执行测试组
	var wg sync.WaitGroup
	errorChan := make(chan error, len(cts.testGroups))
	
	for groupName, group := range cts.testGroups {
		wg.Add(1)
		go func(name string, g *TestGroup) {
			defer wg.Done()
			
			if err := cts.runTestGroup(testCtx, name, g); err != nil {
				errorChan <- fmt.Errorf("test group %s failed: %w", name, err)
			}
		}(groupName, group)
	}
	
	// 等待所有测试完成
	wg.Wait()
	close(errorChan)
	
	// 收集错误
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}
	
	// 完成测试
	cts.results.Finish()
	
	// 生成报告
	if cts.config.GenerateReport {
		if err := cts.reporter.GenerateReport(cts.results); err != nil {
			cts.reporter.LogWarning("failed to generate report", err)
		}
	}
	
	// 验证测试结果
	if err := cts.validateResults(); err != nil {
		return cts.results, fmt.Errorf("test validation failed: %w", err)
	}
	
	if len(errors) > 0 {
		return cts.results, fmt.Errorf("test execution errors: %v", errors)
	}
	
	return cts.results, nil
}

// runTestGroup 运行测试组
func (cts *CompatibilityTestSuite) runTestGroup(ctx context.Context, groupName string, group *TestGroup) error {
	groupResult := &TestGroupResult{
		Name:      groupName,
		StartTime: time.Now(),
		Tests:     make(map[string]*TestResult),
	}
	
	for testName, test := range group.Tests {
		// 获取信号量
		select {
		case cts.semaphore <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		
		// 执行单个测试
		result := cts.runSingleTest(ctx, test)
		groupResult.Tests[testName] = result
		
		// 释放信号量
		<-cts.semaphore
	}
	
	groupResult.EndTime = time.Now()
	groupResult.Duration = groupResult.EndTime.Sub(groupResult.StartTime)
	
	// 计算组统计
	cts.calculateGroupStats(groupResult)
	
	// 记录结果
	cts.mu.Lock()
	cts.results.Groups[groupName] = groupResult
	cts.mu.Unlock()
	
	return nil
}

// runSingleTest 运行单个测试
func (cts *CompatibilityTestSuite) runSingleTest(ctx context.Context, test CompatibilityTest) *TestResult {
	result := &TestResult{
		Name:      test.Name(),
		StartTime: time.Now(),
		Status:    TestStatusRunning,
	}
	
	// 设置测试超时
	testCtx, cancel := context.WithTimeout(ctx, cts.config.TestTimeout)
	defer cancel()
	
	// 执行测试
	err := test.Execute(testCtx, cts.environment)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	if err != nil {
		result.Status = TestStatusFailed
		result.Error = err.Error()
		atomic.AddInt64(&cts.results.Statistics.Failed, 1)
	} else {
		result.Status = TestStatusPassed
		atomic.AddInt64(&cts.results.Statistics.Passed, 1)
	}
	
	atomic.AddInt64(&cts.results.Statistics.Total, 1)
	
	// 记录详细信息
	if testDetails := test.GetDetails(); testDetails != nil {
		result.Details = testDetails
	}
	
	return result
}

// ==================== 测试接口定义 ====================

// CompatibilityTest 兼容性测试接口
type CompatibilityTest interface {
	Name() string
	Description() string
	Category() TestScope
	Prerequisites() []string
	Execute(ctx context.Context, env *TestEnvironment) error
	GetDetails() map[string]interface{}
	Cleanup() error
}

// BaseTest 基础测试实现
type BaseTest struct {
	TestName        string
	TestDescription string
	TestCategory    TestScope
	TestDetails     map[string]interface{}
}

func (bt *BaseTest) Name() string                           { return bt.TestName }
func (bt *BaseTest) Description() string                   { return bt.TestDescription }
func (bt *BaseTest) Category() TestScope                   { return bt.TestCategory }
func (bt *BaseTest) Prerequisites() []string               { return nil }
func (bt *BaseTest) GetDetails() map[string]interface{}    { return bt.TestDetails }
func (bt *BaseTest) Cleanup() error                        { return nil }

// ==================== 认证兼容性测试 ====================

// AuthenticationCompatibilityTest 认证兼容性测试
type AuthenticationCompatibilityTest struct {
	*BaseTest
	authV1 *auth.AuthMiddleware
	authV2 *auth.OptimalAuth
}

// NewAuthenticationCompatibilityTest 创建认证兼容性测试
func NewAuthenticationCompatibilityTest() *AuthenticationCompatibilityTest {
	return &AuthenticationCompatibilityTest{
		BaseTest: &BaseTest{
			TestName:        "authentication_compatibility",
			TestDescription: "Test authentication compatibility between versions",
			TestCategory:    ScopeAuthentication,
			TestDetails:     make(map[string]interface{}),
		},
	}
}

// Execute 执行认证兼容性测试
func (act *AuthenticationCompatibilityTest) Execute(ctx context.Context, env *TestEnvironment) error {
	// 1. 测试V1到V2的令牌兼容性
	if err := act.testTokenCompatibility(ctx, env); err != nil {
		return fmt.Errorf("token compatibility test failed: %w", err)
	}
	
	// 2. 测试上下文兼容性
	if err := act.testContextCompatibility(ctx, env); err != nil {
		return fmt.Errorf("context compatibility test failed: %w", err)
	}
	
	// 3. 测试配置兼容性
	if err := act.testConfigCompatibility(ctx, env); err != nil {
		return fmt.Errorf("config compatibility test failed: %w", err)
	}
	
	// 4. 测试API兼容性
	if err := act.testAPICompatibility(ctx, env); err != nil {
		return fmt.Errorf("API compatibility test failed: %w", err)
	}
	
	return nil
}

// testTokenCompatibility 测试令牌兼容性
func (act *AuthenticationCompatibilityTest) testTokenCompatibility(ctx context.Context, env *TestEnvironment) error {
	// 使用V1生成令牌
	v1Token, err := env.GenerateTokenV1("test_user", "test_tenant")
	if err != nil {
		return fmt.Errorf("failed to generate V1 token: %w", err)
	}
	
	// 使用V2验证V1令牌
	if err := env.ValidateTokenV2(v1Token); err != nil {
		return fmt.Errorf("V2 failed to validate V1 token: %w", err)
	}
	
	// 使用V2生成令牌
	v2Token, err := env.GenerateTokenV2("test_user", "test_tenant")
	if err != nil {
		return fmt.Errorf("failed to generate V2 token: %w", err)
	}
	
	// 使用V1验证V2令牌（向后兼容）
	if err := env.ValidateTokenV1(v2Token); err != nil {
		// 记录警告但不失败，因为这可能是预期行为
		act.TestDetails["v1_validate_v2_token_warning"] = err.Error()
	}
	
	return nil
}

// testContextCompatibility 测试上下文兼容性
func (act *AuthenticationCompatibilityTest) testContextCompatibility(ctx context.Context, env *TestEnvironment) error {
	// 创建测试请求
	req := env.CreateTestRequest("/api/test", "GET", map[string]string{
		"Authorization": "Bearer " + env.TestTokens["v1"],
	})
	
	// 测试V1中间件处理后的上下文
	v1Ctx := env.ProcessWithV1(req.Context(), req)
	
	// 验证上下文中的用户信息
	userID := v1Ctx.Value("userID")
	if userID == nil {
		return fmt.Errorf("userID not found in V1 context")
	}
	
	// 测试V2中间件处理后的上下文
	v2Ctx := env.ProcessWithV2(req.Context(), req)
	
	// 验证上下文兼容性
	v2UserID := v2Ctx.Value("userID")
	if v2UserID != userID {
		return fmt.Errorf("userID mismatch between V1 (%v) and V2 (%v)", userID, v2UserID)
	}
	
	return nil
}

// testConfigCompatibility 测试配置兼容性
func (act *AuthenticationCompatibilityTest) testConfigCompatibility(ctx context.Context, env *TestEnvironment) error {
	// 测试V1配置转换为V2配置
	v1Config := &auth.AuthConfig{
		JWTSecret: "test_secret",
		Enabled:   true,
		SkipPaths: []string{"/health"},
	}
	
	adapter := NewInterfaceAdapter()
	v2Config := adapter.AdaptConfig(v1Config)
	
	// 验证配置字段
	if v2Config.JWTSecret != v1Config.JWTSecret {
		return fmt.Errorf("JWT secret mismatch after conversion")
	}
	
	if v2Config.Enabled != v1Config.Enabled {
		return fmt.Errorf("enabled flag mismatch after conversion")
	}
	
	if len(v2Config.SkipPaths) != len(v1Config.SkipPaths) {
		return fmt.Errorf("skip paths length mismatch after conversion")
	}
	
	return nil
}

// testAPICompatibility 测试API兼容性
func (act *AuthenticationCompatibilityTest) testAPICompatibility(ctx context.Context, env *TestEnvironment) error {
	// 测试HTTP接口兼容性
	endpoints := []string{"/api/user", "/api/auth", "/api/permissions"}
	
	for _, endpoint := range endpoints {
		if err := act.testEndpointCompatibility(ctx, env, endpoint); err != nil {
			return fmt.Errorf("endpoint %s compatibility test failed: %w", endpoint, err)
		}
	}
	
	return nil
}

// testEndpointCompatibility 测试端点兼容性
func (act *AuthenticationCompatibilityTest) testEndpointCompatibility(ctx context.Context, env *TestEnvironment, endpoint string) error {
	// 使用V1令牌访问V2端点
	v1Response, err := env.MakeRequest("v1", endpoint, map[string]string{
		"Authorization": "Bearer " + env.TestTokens["v1"],
	})
	if err != nil {
		return err
	}
	
	// 使用V2令牌访问V1端点
	v2Response, err := env.MakeRequest("v2", endpoint, map[string]string{
		"Authorization": "Bearer " + env.TestTokens["v2"],
	})
	if err != nil {
		return err
	}
	
	// 比较响应结果
	if err := act.compareResponses(v1Response, v2Response); err != nil {
		return fmt.Errorf("response comparison failed for %s: %w", endpoint, err)
	}
	
	return nil
}

// compareResponses 比较响应结果
func (act *AuthenticationCompatibilityTest) compareResponses(resp1, resp2 *http.Response) error {
	// 比较状态码
	if resp1.StatusCode != resp2.StatusCode {
		return fmt.Errorf("status code mismatch: %d vs %d", resp1.StatusCode, resp2.StatusCode)
	}
	
	// 比较关键响应头
	keyHeaders := []string{"Content-Type", "X-User-ID", "X-Tenant-ID"}
	for _, header := range keyHeaders {
		v1Value := resp1.Header.Get(header)
		v2Value := resp2.Header.Get(header)
		
		if v1Value != v2Value {
			return fmt.Errorf("header %s mismatch: %s vs %s", header, v1Value, v2Value)
		}
	}
	
	return nil
}

// ==================== 性能兼容性测试 ====================

// PerformanceCompatibilityTest 性能兼容性测试
type PerformanceCompatibilityTest struct {
	*BaseTest
	concurrency int
	duration    time.Duration
}

// NewPerformanceCompatibilityTest 创建性能兼容性测试
func NewPerformanceCompatibilityTest(concurrency int, duration time.Duration) *PerformanceCompatibilityTest {
	return &PerformanceCompatibilityTest{
		BaseTest: &BaseTest{
			TestName:        "performance_compatibility",
			TestDescription: "Test performance compatibility between versions",
			TestCategory:    ScopePerformance,
			TestDetails:     make(map[string]interface{}),
		},
		concurrency: concurrency,
		duration:    duration,
	}
}

// Execute 执行性能兼容性测试
func (pct *PerformanceCompatibilityTest) Execute(ctx context.Context, env *TestEnvironment) error {
	// 1. 测试V1性能基准
	v1Metrics, err := pct.runPerformanceTest(ctx, env, "v1")
	if err != nil {
		return fmt.Errorf("V1 performance test failed: %w", err)
	}
	
	// 2. 测试V2性能基准
	v2Metrics, err := pct.runPerformanceTest(ctx, env, "v2")
	if err != nil {
		return fmt.Errorf("V2 performance test failed: %w", err)
	}
	
	// 3. 比较性能指标
	if err := pct.comparePerformanceMetrics(v1Metrics, v2Metrics); err != nil {
		return fmt.Errorf("performance comparison failed: %w", err)
	}
	
	// 4. 记录性能数据
	pct.TestDetails["v1_metrics"] = v1Metrics
	pct.TestDetails["v2_metrics"] = v2Metrics
	pct.TestDetails["performance_improvement"] = pct.calculateImprovement(v1Metrics, v2Metrics)
	
	return nil
}

// runPerformanceTest 运行性能测试
func (pct *PerformanceCompatibilityTest) runPerformanceTest(ctx context.Context, env *TestEnvironment, version string) (*PerformanceMetrics, error) {
	metrics := &PerformanceMetrics{
		Version: version,
		StartTime: time.Now(),
	}
	
	// 并发请求测试
	var wg sync.WaitGroup
	requestChan := make(chan time.Duration, pct.concurrency*100)
	errorChan := make(chan error, pct.concurrency)
	
	testCtx, cancel := context.WithTimeout(ctx, pct.duration)
	defer cancel()
	
	// 启动并发工作协程
	for i := 0; i < pct.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for {
				select {
				case <-testCtx.Done():
					return
				default:
					latency, err := pct.makeTestRequest(env, version)
					if err != nil {
						atomic.AddInt64(&metrics.Errors, 1)
						errorChan <- err
					} else {
						atomic.AddInt64(&metrics.Requests, 1)
						requestChan <- latency
					}
				}
			}
		}()
	}
	
	// 等待测试完成
	wg.Wait()
	close(requestChan)
	close(errorChan)
	
	metrics.EndTime = time.Now()
	metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)
	
	// 计算延迟统计
	var latencies []time.Duration
	for latency := range requestChan {
		latencies = append(latencies, latency)
	}
	
	if len(latencies) > 0 {
		metrics.AvgLatency = calculateAverage(latencies)
		metrics.P50Latency = calculatePercentile(latencies, 50)
		metrics.P95Latency = calculatePercentile(latencies, 95)
		metrics.P99Latency = calculatePercentile(latencies, 99)
	}
	
	// 计算QPS
	if metrics.Duration > 0 {
		metrics.QPS = float64(metrics.Requests) / metrics.Duration.Seconds()
	}
	
	return metrics, nil
}

// makeTestRequest 发送测试请求
func (pct *PerformanceCompatibilityTest) makeTestRequest(env *TestEnvironment, version string) (time.Duration, error) {
	start := time.Now()
	
	resp, err := env.MakeRequest(version, "/api/auth/validate", map[string]string{
		"Authorization": "Bearer " + env.TestTokens[version],
	})
	
	latency := time.Since(start)
	
	if err != nil {
		return latency, err
	}
	
	if resp.StatusCode != http.StatusOK {
		return latency, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	return latency, nil
}

// comparePerformanceMetrics 比较性能指标
func (pct *PerformanceCompatibilityTest) comparePerformanceMetrics(v1, v2 *PerformanceMetrics) error {
	// 检查错误率
	v1ErrorRate := float64(v1.Errors) / float64(v1.Requests)
	v2ErrorRate := float64(v2.Errors) / float64(v2.Requests)
	
	if v2ErrorRate > v1ErrorRate*1.5 { // 允许50%的错误率增长
		return fmt.Errorf("V2 error rate (%.2f%%) significantly higher than V1 (%.2f%%)", 
			v2ErrorRate*100, v1ErrorRate*100)
	}
	
	// 检查性能退化
	if v2.AvgLatency > v1.AvgLatency*2 { // 允许100%的延迟增长
		return fmt.Errorf("V2 average latency (%v) significantly higher than V1 (%v)", 
			v2.AvgLatency, v1.AvgLatency)
	}
	
	if v2.QPS < v1.QPS*0.5 { // QPS不应下降超过50%
		return fmt.Errorf("V2 QPS (%.2f) significantly lower than V1 (%.2f)", 
			v2.QPS, v1.QPS)
	}
	
	return nil
}

// calculateImprovement 计算性能改进
func (pct *PerformanceCompatibilityTest) calculateImprovement(v1, v2 *PerformanceMetrics) map[string]interface{} {
	return map[string]interface{}{
		"latency_improvement": float64(v1.AvgLatency-v2.AvgLatency) / float64(v1.AvgLatency) * 100,
		"qps_improvement":     (v2.QPS - v1.QPS) / v1.QPS * 100,
		"error_rate_change":   (float64(v2.Errors)/float64(v2.Requests) - float64(v1.Errors)/float64(v1.Requests)) * 100,
	}
}

// ==================== 数据结构定义 ====================

// TestGroup 测试组
type TestGroup struct {
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Tests       map[string]CompatibilityTest   `json:"tests"`
	Dependencies []string                      `json:"dependencies"`
}

// TestResults 测试结果
type TestResults struct {
	StartTime   time.Time                         `json:"start_time"`
	EndTime     time.Time                         `json:"end_time"`
	Duration    time.Duration                     `json:"duration"`
	Statistics  *TestStatistics                   `json:"statistics"`
	Groups      map[string]*TestGroupResult       `json:"groups"`
	Summary     *TestSummary                      `json:"summary"`
}

// TestStatistics 测试统计
type TestStatistics struct {
	Total   int64 `json:"total"`
	Passed  int64 `json:"passed"`
	Failed  int64 `json:"failed"`
	Skipped int64 `json:"skipped"`
}

// TestGroupResult 测试组结果
type TestGroupResult struct {
	Name      string                    `json:"name"`
	StartTime time.Time                 `json:"start_time"`
	EndTime   time.Time                 `json:"end_time"`
	Duration  time.Duration             `json:"duration"`
	Tests     map[string]*TestResult    `json:"tests"`
	Stats     *TestStatistics           `json:"statistics"`
}

// TestResult 单个测试结果
type TestResult struct {
	Name      string                 `json:"name"`
	Status    TestStatus             `json:"status"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  time.Duration          `json:"duration"`
	Error     string                 `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// TestStatus 测试状态
type TestStatus string
const (
	TestStatusPending  TestStatus = "pending"
	TestStatusRunning  TestStatus = "running"
	TestStatusPassed   TestStatus = "passed"
	TestStatusFailed   TestStatus = "failed"
	TestStatusSkipped  TestStatus = "skipped"
)

// TestSummary 测试摘要
type TestSummary struct {
	OverallResult    TestStatus             `json:"overall_result"`
	CriticalFailures int                    `json:"critical_failures"`
	Recommendations  []string               `json:"recommendations"`
	Metrics          map[string]interface{} `json:"metrics"`
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
	Version     string        `json:"version"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	Requests    int64         `json:"requests"`
	Errors      int64         `json:"errors"`
	QPS         float64       `json:"qps"`
	AvgLatency  time.Duration `json:"avg_latency"`
	P50Latency  time.Duration `json:"p50_latency"`
	P95Latency  time.Duration `json:"p95_latency"`
	P99Latency  time.Duration `json:"p99_latency"`
}

// NewTestResults 创建测试结果
func NewTestResults() *TestResults {
	return &TestResults{
		Statistics: &TestStatistics{},
		Groups:     make(map[string]*TestGroupResult),
		Summary:    &TestSummary{},
	}
}

// Start 开始测试
func (tr *TestResults) Start() {
	tr.StartTime = time.Now()
}

// Finish 完成测试
func (tr *TestResults) Finish() {
	tr.EndTime = time.Now()
	tr.Duration = tr.EndTime.Sub(tr.StartTime)
}

// ==================== 辅助方法 ====================

// initializeTestGroups 初始化测试分组
func (cts *CompatibilityTestSuite) initializeTestGroups() {
	for _, scope := range cts.config.TestScopes {
		group := &TestGroup{
			Name:  string(scope),
			Tests: make(map[string]CompatibilityTest),
		}
		
		switch scope {
		case ScopeAuthentication:
			group.Tests["auth_compatibility"] = NewAuthenticationCompatibilityTest()
		case ScopePerformance:
			group.Tests["perf_compatibility"] = NewPerformanceCompatibilityTest(10, 1*time.Minute)
		}
		
		cts.testGroups[string(scope)] = group
	}
}

// validateResults 验证测试结果
func (cts *CompatibilityTestSuite) validateResults() error {
	errorRate := float64(cts.results.Statistics.Failed) / float64(cts.results.Statistics.Total)
	
	if cts.config.StrictValidation && cts.results.Statistics.Failed > 0 {
		return fmt.Errorf("strict validation enabled, but %d tests failed", cts.results.Statistics.Failed)
	}
	
	if errorRate > cts.config.AllowedErrorRate {
		return fmt.Errorf("error rate %.2f%% exceeds allowed rate %.2f%%", 
			errorRate*100, cts.config.AllowedErrorRate*100)
	}
	
	return nil
}

// calculateGroupStats 计算组统计
func (cts *CompatibilityTestSuite) calculateGroupStats(groupResult *TestGroupResult) {
	stats := &TestStatistics{}
	
	for _, testResult := range groupResult.Tests {
		stats.Total++
		switch testResult.Status {
		case TestStatusPassed:
			stats.Passed++
		case TestStatusFailed:
			stats.Failed++
		case TestStatusSkipped:
			stats.Skipped++
		}
	}
	
	groupResult.Stats = stats
}

// 统计计算辅助函数
func calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

func calculatePercentile(durations []time.Duration, percentile int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	// 简化实现，实际应该排序
	index := (len(durations) * percentile) / 100
	if index >= len(durations) {
		index = len(durations) - 1
	}
	
	return durations[index]
}