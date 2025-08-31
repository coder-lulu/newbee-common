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

// TestMemoryPoolOptimizer_GoroutineLifecycle 测试goroutine生命周期管理
func TestMemoryPoolOptimizer_GoroutineLifecycle(t *testing.T) {
	config := &MemoryPoolConfig{
		CleanupInterval:   time.Millisecond * 100,
		GCForceInterval:   time.Millisecond * 100,
		MemoryThresholdMB: 1024,
	}

	optimizer := NewMemoryPoolOptimizer(config)

	// 创建带取消的context
	ctx, cancel := context.WithCancel(context.Background())

	// 启动优化器
	err := optimizer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start optimizer: %v", err)
	}

	// 等待一段时间确保goroutine启动
	time.Sleep(time.Millisecond * 50)

	// 取消context应该能够停止goroutine
	cancel()

	// 等待goroutine清理
	time.Sleep(time.Millisecond * 200)

	// 调用Stop进行最终清理
	optimizer.Stop()

	t.Log("Goroutine lifecycle test passed")
}

// TestMemoryPoolOptimizer_ConcurrentAccess 测试并发访问安全性
func TestMemoryPoolOptimizer_ConcurrentAccess(t *testing.T) {
	optimizer := NewMemoryPoolOptimizer(nil)

	// 并发获取和释放对象
	const numGoroutines = 10
	const numOperations = 100

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()

			for j := 0; j < numOperations; j++ {
				// 测试权限结果对象池
				result := optimizer.GetPermissionResult()
				result.DataScope = "test"
				optimizer.PutPermissionResult(result)

				// 测试权限请求对象池
				request := optimizer.GetPermissionRequest()
				request.TenantID = uint64(j)
				optimizer.PutPermissionRequest(request)

				// 测试字符串构建器池
				builder := optimizer.GetStringBuilder()
				builder.WriteString("test")
				optimizer.PutStringBuilder(builder)

				// 测试切片池
				slice := optimizer.GetStringSlice()
				slice = append(slice, "test")
				optimizer.PutStringSlice(slice)
			}
		}()
	}

	// 等待所有goroutine完成
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// 获取统计信息
	stats := optimizer.GetStats()
	if stats.TotalGets == 0 {
		t.Error("Expected some gets, got 0")
	}

	if stats.HitRate < 0 || stats.HitRate > 1 {
		t.Errorf("Invalid hit rate: %f", stats.HitRate)
	}

	t.Logf("Concurrent access test passed. Hit rate: %.2f%%", stats.HitRate*100)
}

// TestMemoryPoolOptimizer_StatsReset 测试统计信息重置的原子性
func TestMemoryPoolOptimizer_StatsReset(t *testing.T) {
	optimizer := NewMemoryPoolOptimizer(nil)

	// 生成一些统计数据
	for i := 0; i < 100; i++ {
		result := optimizer.GetPermissionResult()
		optimizer.PutPermissionResult(result)
	}

	// 并发重置统计信息
	done := make(chan bool, 2)

	go func() {
		defer func() { done <- true }()
		for i := 0; i < 10; i++ {
			optimizer.ResetStats()
			time.Sleep(time.Millisecond)
		}
	}()

	go func() {
		defer func() { done <- true }()
		for i := 0; i < 10; i++ {
			stats := optimizer.GetStats()
			_ = stats // 使用stats避免编译器警告
			time.Sleep(time.Millisecond)
		}
	}()

	// 等待完成
	<-done
	<-done

	t.Log("Stats reset test passed")
}

// TestKeyBuilder_Performance 测试键构建器性能
func TestKeyBuilder_Performance(t *testing.T) {
	builder := NewKeyBuilder()

	// 基准测试
	const numOperations = 1000

	start := time.Now()
	for i := 0; i < numOperations; i++ {
		key := builder.BuildPermissionKey(uint64(i), "admin", "read")
		if len(key) == 0 {
			t.Error("Empty key generated")
		}
	}
	duration := time.Since(start)

	avgLatency := duration / numOperations
	if avgLatency > time.Microsecond*10 {
		t.Errorf("Key building too slow: %v per operation", avgLatency)
	}

	t.Logf("Key building performance: %v per operation", avgLatency)
}

// TestConfigValidation 测试配置验证
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *MemoryPoolConfig
		expectedValid bool
	}{
		{
			name:          "nil config should use defaults",
			config:        nil,
			expectedValid: true,
		},
		{
			name: "valid config",
			config: &MemoryPoolConfig{
				MaxObjectsPerPool: 500,
				CleanupInterval:   time.Minute,
				EnableMetrics:     true,
				PreAllocateSize:   50,
			},
			expectedValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optimizer := NewMemoryPoolOptimizer(tt.config)
			if optimizer == nil && tt.expectedValid {
				t.Error("Expected valid optimizer, got nil")
			}
			if optimizer != nil && !tt.expectedValid {
				t.Error("Expected nil optimizer, got valid instance")
			}
		})
	}
}

// Mock Builder implementation for testing
type MockBuilder struct {
	content string
	cap     int
}

func (mb *MockBuilder) WriteString(s string) (int, error) {
	mb.content += s
	return len(s), nil
}

func (mb *MockBuilder) WriteByte(c byte) error {
	mb.content += string(c)
	return nil
}

func (mb *MockBuilder) String() string {
	return mb.content
}

func (mb *MockBuilder) Reset() {
	mb.content = ""
}

func (mb *MockBuilder) Grow(n int) {
	mb.cap += n
}

func (mb *MockBuilder) Cap() int {
	return mb.cap
}
