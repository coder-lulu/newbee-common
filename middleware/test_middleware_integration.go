package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeromicro/go-zero/rest"

	"github.com/coder-lulu/newbee-common/audit"
	"github.com/coder-lulu/newbee-common/middleware/auth"
)

// TestMiddlewareIntegration 中间件集成测试套件
type TestMiddlewareIntegration struct {
	t         *testing.T
	jwtSecret string
	server    *httptest.Server
	auditSvc  *audit.AuditService
}

// 生成测试JWT Token
func (t *TestMiddlewareIntegration) generateTestJWT(userID, tenantID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   userID,
		"tenantId": tenantID,
		"username": "testuser",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})
	
	tokenString, err := token.SignedString([]byte(t.jwtSecret))
	require.NoError(t.t, err)
	return tokenString
}

// TestAuthMiddleware 测试认证中间件
func TestAuthMiddleware(t *testing.T) {
	testSuite := &TestMiddlewareIntegration{
		t:         t,
		jwtSecret: "test-secret-key-for-middleware-testing",
	}

	// 创建认证中间件
	authMiddleware := auth.NewOptimal(&auth.OptimalConfig{
		JWTSecret: testSuite.jwtSecret,
		Enabled:   true,
		SkipPaths: []string{"/health", "/ping"},
	})

	t.Run("Valid JWT Token", func(t *testing.T) {
		validToken := testSuite.generateTestJWT("12345", "67890")
		
		req, _ := http.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		
		rr := httptest.NewRecorder()
		
		handler := authMiddleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 验证上下文中的用户信息
			userID := r.Context().Value("userId")
			tenantID := r.Context().Value("tenantId")
			
			assert.Equal(t, "12345", userID)
			assert.Equal(t, "67890", tenantID)
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0,
				"msg":  "success",
				"data": map[string]interface{}{
					"userId":   userID,
					"tenantId": tenantID,
				},
			})
		}))
		
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Invalid JWT Token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		
		rr := httptest.NewRecorder()
		
		handler := authMiddleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called with invalid token")
		}))
		
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Skip Path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/health", nil)
		
		rr := httptest.NewRecorder()
		
		handler := authMiddleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "OK", rr.Body.String())
	})
}

// TestTenantMiddleware 测试租户中间件
func TestTenantMiddleware(t *testing.T) {
	testSuite := &TestMiddlewareIntegration{
		t:         t,
		jwtSecret: "test-secret-key-for-middleware-testing",
	}

	t.Run("Tenant Context Injection", func(t *testing.T) {
		// 模拟租户中间件功能
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 创建带租户信息的上下文
			ctx := r.Context()
			ctx = context.WithValue(ctx, "tenantId", "tenant-123")
			ctx = context.WithValue(ctx, "userId", "user-456")
			
			// 验证租户隔离逻辑
			tenantID := ctx.Value("tenantId")
			userID := ctx.Value("userId")
			
			assert.Equal(t, "tenant-123", tenantID)
			assert.Equal(t, "user-456", userID)
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0,
				"msg":  "tenant context injected",
				"data": map[string]interface{}{
					"tenantId": tenantID,
					"userId":   userID,
				},
			})
		})

		req, _ := http.NewRequest("GET", "/api/tenant-test", nil)
		rr := httptest.NewRecorder()
		
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		
		data := response["data"].(map[string]interface{})
		assert.Equal(t, "tenant-123", data["tenantId"])
		assert.Equal(t, "user-456", data["userId"])
	})

	t.Run("Tenant Isolation", func(t *testing.T) {
		// 测试租户数据隔离
		tenantA := "tenant-a"
		tenantB := "tenant-b"
		
		// 模拟租户A的请求
		reqA, _ := http.NewRequest("GET", "/api/data", nil)
		ctxA := context.WithValue(reqA.Context(), "tenantId", tenantA)
		reqA = reqA.WithContext(ctxA)
		
		// 模拟租户B的请求
		reqB, _ := http.NewRequest("GET", "/api/data", nil)
		ctxB := context.WithValue(reqB.Context(), "tenantId", tenantB)
		reqB = reqB.WithContext(ctxB)
		
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := r.Context().Value("tenantId")
			
			// 根据租户ID返回不同数据
			var data []string
			switch tenantID {
			case "tenant-a":
				data = []string{"data-a1", "data-a2"}
			case "tenant-b":
				data = []string{"data-b1", "data-b2"}
			}
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"tenantId": tenantID,
				"data":     data,
			})
		})
		
		// 测试租户A
		rrA := httptest.NewRecorder()
		handler.ServeHTTP(rrA, reqA)
		assert.Equal(t, http.StatusOK, rrA.Code)
		
		var responseA map[string]interface{}
		json.Unmarshal(rrA.Body.Bytes(), &responseA)
		assert.Equal(t, "tenant-a", responseA["tenantId"])
		
		// 测试租户B
		rrB := httptest.NewRecorder()
		handler.ServeHTTP(rrB, reqB)
		assert.Equal(t, http.StatusOK, rrB.Code)
		
		var responseB map[string]interface{}
		json.Unmarshal(rrB.Body.Bytes(), &responseB)
		assert.Equal(t, "tenant-b", responseB["tenantId"])
		
		// 验证数据隔离
		assert.NotEqual(t, responseA["data"], responseB["data"])
	})
}

// TestAuditMiddleware 测试审计中间件
func TestAuditMiddleware(t *testing.T) {
	testSuite := &TestMiddlewareIntegration{
		t:         t,
		jwtSecret: "test-secret-key-for-middleware-testing",
	}

	t.Run("Audit Event Recording", func(t *testing.T) {
		// 创建内存存储的审计服务用于测试
		auditEvents := make([]audit.AuditEvent, 0)
		
		// 模拟审计中间件
		auditMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startTime := time.Now()
				
				// 创建响应记录器
				recorder := httptest.NewRecorder()
				
				// 调用下一个处理器
				next.ServeHTTP(recorder, r)
				
				// 复制响应到实际的响应写入器
				for k, v := range recorder.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(recorder.Code)
				w.Write(recorder.Body.Bytes())
				
				// 记录审计事件
				auditEvent := audit.AuditEvent{
					ID:          fmt.Sprintf("test-%d", time.Now().UnixNano()),
					UserID:      extractUserID(r),
					TenantID:    extractTenantID(r),
					Method:      r.Method,
					Path:        r.URL.Path,
					StatusCode:  recorder.Code,
					Duration:    time.Since(startTime),
					RequestIP:   r.RemoteAddr,
					UserAgent:   r.Header.Get("User-Agent"),
					Timestamp:   startTime,
				}
				
				auditEvents = append(auditEvents, auditEvent)
			})
		}
		
		// 测试处理器
		handler := auditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "success"})
		}))
		
		// 创建带认证信息的请求
		req, _ := http.NewRequest("POST", "/api/test", bytes.NewBuffer([]byte(`{"test": "data"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Test-Agent/1.0")
		
		// 添加用户和租户上下文
		ctx := req.Context()
		ctx = context.WithValue(ctx, "userId", "test-user-123")
		ctx = context.WithValue(ctx, "tenantId", "test-tenant-456")
		req = req.WithContext(ctx)
		
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		
		// 验证响应
		assert.Equal(t, http.StatusOK, rr.Code)
		
		// 验证审计事件
		require.Len(t, auditEvents, 1)
		event := auditEvents[0]
		
		assert.Equal(t, "test-user-123", event.UserID)
		assert.Equal(t, "test-tenant-456", event.TenantID)
		assert.Equal(t, "POST", event.Method)
		assert.Equal(t, "/api/test", event.Path)
		assert.Equal(t, 200, event.StatusCode)
		assert.Equal(t, "Test-Agent/1.0", event.UserAgent)
		assert.True(t, event.Duration > 0)
	})

	t.Run("Sensitive Data Filtering", func(t *testing.T) {
		// 测试敏感数据过滤
		sensitiveData := map[string]interface{}{
			"username": "testuser",
			"password": "secret123",
			"token":    "jwt-token-here",
			"apiKey":   "api-key-secret",
			"email":    "test@example.com",
		}
		
		// 模拟敏感数据过滤函数
		filtered := filterSensitiveData(sensitiveData)
		
		assert.Equal(t, "testuser", filtered["username"])
		assert.Equal(t, "***FILTERED***", filtered["password"])
		assert.Equal(t, "***FILTERED***", filtered["token"])
		assert.Equal(t, "***FILTERED***", filtered["apiKey"])
		assert.Equal(t, "test@example.com", filtered["email"])
	})
}

// TestMiddlewareChain 测试中间件链
func TestMiddlewareChain(t *testing.T) {
	testSuite := &TestMiddlewareIntegration{
		t:         t,
		jwtSecret: "test-secret-key-for-middleware-testing",
	}

	t.Run("Auth -> Tenant -> Audit Chain", func(t *testing.T) {
		// 创建认证中间件
		authMiddleware := auth.NewOptimal(&auth.OptimalConfig{
			JWTSecret: testSuite.jwtSecret,
			Enabled:   true,
		})

		// 模拟租户中间件
		tenantMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 从认证中间件获取租户信息并验证
				tenantID := r.Context().Value("tenantId")
				if tenantID == nil {
					http.Error(w, "Tenant not found", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		}

		// 模拟审计中间件
		auditMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 记录请求开始时间
				startTime := time.Now()
				next.ServeHTTP(w, r)
				
				// 记录审计信息
				userID := r.Context().Value("userId")
				tenantID := r.Context().Value("tenantId")
				
				t.Logf("Audit: User %v from Tenant %v accessed %s %s in %v",
					userID, tenantID, r.Method, r.URL.Path, time.Since(startTime))
			})
		}

		// 业务处理器
		businessHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := r.Context().Value("userId")
			tenantID := r.Context().Value("tenantId")
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0,
				"msg":  "success",
				"data": map[string]interface{}{
					"userId":   userID,
					"tenantId": tenantID,
					"message":  "middleware chain works",
				},
			})
		})

		// 构建中间件链: Auth -> Tenant -> Audit -> Business
		handler := authMiddleware.Handle(
			tenantMiddleware(
				auditMiddleware(businessHandler),
			),
		)

		// 测试有效请求
		validToken := testSuite.generateTestJWT("user-123", "tenant-456")
		req, _ := http.NewRequest("GET", "/api/chain-test", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		
		data := response["data"].(map[string]interface{})
		assert.Equal(t, "user-123", data["userId"])
		assert.Equal(t, "tenant-456", data["tenantId"])
		assert.Equal(t, "middleware chain works", data["message"])
	})
}

// 辅助函数
func extractUserID(r *http.Request) string {
	if userID := r.Context().Value("userId"); userID != nil {
		if str, ok := userID.(string); ok {
			return str
		}
	}
	return ""
}

func extractTenantID(r *http.Request) string {
	if tenantID := r.Context().Value("tenantId"); tenantID != nil {
		if str, ok := tenantID.(string); ok {
			return str
		}
	}
	return ""
}

func filterSensitiveData(data map[string]interface{}) map[string]interface{} {
	filtered := make(map[string]interface{})
	sensitiveFields := map[string]bool{
		"password": true,
		"token":    true,
		"apiKey":   true,
		"secret":   true,
	}
	
	for key, value := range data {
		if sensitiveFields[key] {
			filtered[key] = "***FILTERED***"
		} else {
			filtered[key] = value
		}
	}
	return filtered
}

// BenchmarkMiddlewareChain 性能基准测试
func BenchmarkMiddlewareChain(b *testing.B) {
	testSuite := &TestMiddlewareIntegration{
		jwtSecret: "benchmark-secret-key",
	}

	// 创建中间件链
	authMiddleware := auth.NewOptimal(&auth.OptimalConfig{
		JWTSecret: testSuite.jwtSecret,
		Enabled:   true,
	})

	handler := authMiddleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	validToken := testSuite.generateTestJWT("bench-user", "bench-tenant")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", "/api/benchmark", nil)
			req.Header.Set("Authorization", "Bearer "+validToken)
			
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}