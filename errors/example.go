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

package errors

import (
	"context"
	"fmt"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// ExampleUsage 演示统一错误处理的使用
func ExampleUsage() {
	ctx := context.Background()

	// 1. 基本错误创建和处理
	fmt.Println("=== 基本错误处理示例 ===")

	// 创建验证错误
	validationErr := Validation("用户名不能为空")
	fmt.Printf("验证错误: %s\n", validationErr.Error())
	fmt.Printf("用户消息: %s\n", GetUserMessage(validationErr))

	// 创建业务错误
	businessErr := Business("订单状态不允许取消")
	businessErr.WithContext("order_id", "12345").WithContext("status", "completed")
	fmt.Printf("业务错误: %s\n", businessErr.Error())

	// 创建数据库错误
	dbErr := DatabaseWithCause("用户查询失败", fmt.Errorf("connection timeout"))
	fmt.Printf("数据库错误: %s\n", dbErr.Error())
	fmt.Printf("可重试: %v, 重试间隔: %v\n", IsRetryable(dbErr), GetRetryAfter(dbErr))

	// 2. 错误处理器使用
	fmt.Println("\n=== 错误处理器示例 ===")

	// 注册自定义处理器
	RegisterHandler(customErrorHandler)

	// 处理错误
	processedErr := Handle(ctx, validationErr)
	fmt.Printf("处理后的错误: %s\n", processedErr.Error())

	// 3. 错误包装和链式调用
	fmt.Println("\n=== 错误包装示例 ===")

	originalErr := fmt.Errorf("network connection failed")
	wrappedErr := Wrap(originalErr, ErrCodeNetwork, "外部服务调用失败")
	wrappedErr.WithSeverity(SeverityHigh).WithRetry(true, 10*time.Second)

	fmt.Printf("包装错误: %s\n", wrappedErr.Error())
	fmt.Printf("严重程度: %s\n", GetSeverity(wrappedErr))

	// 4. 重试机制演示
	fmt.Println("\n=== 重试机制示例 ===")

	retryCount := 0
	err := RetryWithBackoff(ctx, func() error {
		retryCount++
		if retryCount < 3 {
			return Database("模拟数据库连接失败")
		}
		return nil
	}, 3)

	if err != nil {
		fmt.Printf("重试失败: %s\n", err.Error())
	} else {
		fmt.Printf("重试成功，共重试 %d 次\n", retryCount-1)
	}

	// 5. HTTP 错误响应演示
	fmt.Println("\n=== HTTP 错误响应示例 ===")

	httpAdapter := NewHTTPErrorAdapter().WithDetails(true).WithTrace(true)
	statusCode, response := httpAdapter.ToHTTPResponse(businessErr)
	fmt.Printf("HTTP 状态码: %d\n", statusCode)
	fmt.Printf("HTTP 响应: %s\n", response.ToJSON())

	// 6. 配置错误演示
	fmt.Println("\n=== 配置错误示例 ===")

	configErr := Config("数据库连接配置缺失")
	configErr.WithContext("config_key", "database.host")
	fmt.Printf("配置错误: %s\n", configErr.Error())
	fmt.Printf("严重程度: %s\n", configErr.Severity)

	// 7. 错误恢复演示
	fmt.Println("\n=== 错误恢复示例 ===")

	func() {
		defer Recovery(ctx)
		// 模拟 panic
		panic("模拟系统崩溃")
	}()

	fmt.Println("Panic 已被捕获并转换为错误")
}

// ToJSON 将 HTTP 错误响应转换为 JSON
func (r *HTTPErrorResponse) ToJSON() string {
	return fmt.Sprintf(`{
  "success": %v,
  "code": "%s",
  "message": "%s",
  "details": "%s",
  "timestamp": %d,
  "retryable": %v,
  "trace_id": "%s"
}`, r.Success, r.Code, r.Message, r.Details, r.Timestamp, r.Retryable, r.TraceID)
}

// customErrorHandler 自定义错误处理器
func customErrorHandler(ctx context.Context, err *UnifiedError) error {
	// 添加自定义逻辑，如发送告警、记录特殊日志等
	if err.Severity == SeverityCritical {
		logx.Errorw("Critical error detected, sending alert",
			logx.Field("error_code", string(err.Code)),
			logx.Field("error_message", err.Message),
			logx.Field("context", err.Context))

		// 这里可以集成告警系统
		// alertService.SendAlert(err)
	}

	return nil
}

// DemoBusinessLogic 演示业务逻辑中的错误处理
func DemoBusinessLogic() error {
	ctx := context.Background()

	// 模拟业务逻辑
	user, err := getUserFromDatabase("user123")
	if err != nil {
		return HandleDatabase(ctx, "获取用户信息", err)
	}

	if user == nil {
		return HandleBusiness(ctx, "用户不存在")
	}

	// 验证用户权限
	if !hasPermission(user, "read_orders") {
		return Handle(ctx, Forbidden("用户没有查看订单的权限").WithContext("user_id", "user123"))
	}

	return nil
}

// 模拟函数
func getUserFromDatabase(userID string) (interface{}, error) {
	// 模拟数据库查询
	return nil, fmt.Errorf("database connection timeout")
}

func hasPermission(user interface{}, permission string) bool {
	return false
}

// WithSeverity 添加设置严重程度的方法
func (e *UnifiedError) WithSeverity(severity ErrorSeverity) *UnifiedError {
	e.Severity = severity
	return e
}

// DemoErrorPatterns 演示常见错误模式
func DemoErrorPatterns() {
	ctx := context.Background()

	fmt.Println("=== 常见错误模式演示 ===")

	// 1. 参数验证错误
	if err := validateUserInput(""); err != nil {
		Handle(ctx, err)
	}

	// 2. 资源不存在错误
	if err := findResource("nonexistent"); err != nil {
		Handle(ctx, err)
	}

	// 3. 权限检查错误
	if err := checkPermissions("user123", "admin"); err != nil {
		Handle(ctx, err)
	}

	// 4. 外部服务调用错误
	if err := callExternalService(); err != nil {
		Handle(ctx, err)
	}

	// 5. 配置相关错误
	if err := loadConfiguration(); err != nil {
		Handle(ctx, err)
	}
}

func validateUserInput(input string) error {
	if input == "" {
		return ValidationWithDetails("输入不能为空", "required field is missing")
	}
	return nil
}

func findResource(id string) error {
	if id == "nonexistent" {
		return NotFound("资源")
	}
	return nil
}

func checkPermissions(userID, requiredRole string) error {
	if requiredRole == "admin" {
		return Forbidden("需要管理员权限")
	}
	return nil
}

func callExternalService() error {
	return Wrap(fmt.Errorf("connection refused"), ErrCodeNetwork, "外部服务不可用")
}

func loadConfiguration() error {
	return Config("配置文件格式错误")
}
