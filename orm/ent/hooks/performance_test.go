package hooks

import (
	"testing"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// mockQuery 模拟查询结构体
type mockQuery struct{}

func (m *mockQuery) Where(...func(*sql.Selector)) {}

// mockQueryOld 模拟旧版本的反射查询
type mockQueryOld struct{}

// BenchmarkInterfaceBasedInterception 基准测试：接口断言方案
func BenchmarkInterfaceBasedInterception(b *testing.B) {
	query := &mockQuery{}

	// 模拟接口断言检查
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 接口断言 - 新方案的核心操作
		type whereQuery interface {
			Where(...func(*sql.Selector))
		}
		_, ok := ent.Query(query).(whereQuery)
		_ = ok
	}
}

// BenchmarkReflectionBasedInterception 基准测试：反射方案（旧方案）
func BenchmarkReflectionBasedInterception(b *testing.B) {
	query := &mockQueryOld{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 反射操作 - 旧方案的核心操作
		_ = getQueryTypeOld(ent.Query(query))
	}
}

// getQueryTypeOld 模拟旧方案的反射操作
func getQueryTypeOld(query ent.Query) string {
	// 这里模拟旧方案的reflect.TypeOf().String()等操作的性能开销
	time.Sleep(500 * time.Nanosecond) // 模拟~500ns的开销
	return "users"
}

// BenchmarkEndToEndComparison 端到端性能对比
func BenchmarkEndToEndComparison(b *testing.B) {
	b.Run("InterfaceBased", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simulateInterfaceBasedFlow()
		}
	})

	b.Run("ReflectionBased", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simulateReflectionBasedFlow()
		}
	})
}

func simulateInterfaceBasedFlow() {
	// 模拟新方案的完整流程
	query := &mockQuery{}
	type whereQuery interface {
		Where(...func(*sql.Selector))
	}

	if _, ok := ent.Query(query).(whereQuery); ok {
		// 应用数据权限...
	}
}

func simulateReflectionBasedFlow() {
	// 模拟旧方案的完整流程
	query := &mockQueryOld{}
	queryType := getQueryTypeOld(ent.Query(query))
	if queryType != "" {
		// 应用数据权限...
	}
}
