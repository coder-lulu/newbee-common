package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockAuditStorage 模拟存储实现
type MockAuditStorage struct{}

func (m *MockAuditStorage) Save(ctx context.Context, events []AuditEvent) error {
	return nil
}

func (m *MockAuditStorage) Close() error {
	return nil
}

// BenchmarkAuditMiddleware 基准测试
func BenchmarkAuditMiddleware(b *testing.B) {
	config := &AuditConfig{
		Enabled:    true,
		BufferSize: 10000,
		SkipPaths:  []string{},
	}

	storage := &MockAuditStorage{}
	middleware := New(config, storage)
	defer middleware.Stop()

	handler := middleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req = req.WithContext(WithUserID(WithTenantID(req.Context(), "tenant1"), "user1"))
			rr := httptest.NewRecorder()
			handler(rr, req)
		}
	})
}

// BenchmarkObjectPoolUsage 对象池使用基准测试
func BenchmarkObjectPoolUsage(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := auditEventPool.Get().(*AuditEvent)
			event.Reset()
			event.Method = "GET"
			event.Path = "/test"
			auditEventPool.Put(event)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := &AuditEvent{
				Method: "GET",
				Path:   "/test",
			}
			_ = event
		}
	})
}

// BenchmarkSecurityValidation 安全验证基准测试
func BenchmarkSecurityValidation(b *testing.B) {
	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"2001:db8::1",
		"invalid-ip",
		"'; DROP TABLE--",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := testIPs[i%len(testIPs)]
		isValidIP(ip)
		isValidID(ip) // 测试ID验证性能
	}
}
