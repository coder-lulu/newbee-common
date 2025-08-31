// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

import (
	"bytes"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestObjectPoolPerformance demonstrates the performance improvement with object pools
func TestObjectPoolPerformance(t *testing.T) {
	// Create framework with pools enabled
	engine := NewCoreEngine()
	config := &FrameworkConfig{
		Name:           "perf-test",
		Version:        "1.0.0",
		Environment:    "test",
		MetricsEnabled: true,
		PluginConfigs:  make(map[string]PluginConfig),
	}

	if err := engine.Initialize(config); err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	if err := engine.Start(); err != nil {
		t.Fatalf("Failed to start framework: %v", err)
	}
	defer engine.Stop()

	// Test with pools enabled
	t.Run("WithPools", func(t *testing.T) {
		engine.SetPoolEnabled(true)
		runPerformanceTest(t, engine, "with-pools")
	})

	// Test with pools disabled
	t.Run("WithoutPools", func(t *testing.T) {
		engine.SetPoolEnabled(false)
		runPerformanceTest(t, engine, "without-pools")
	})

	// Display pool metrics
	metrics := engine.GetPoolMetrics()
	t.Logf("Pool metrics: %+v", metrics)
}

func runPerformanceTest(t *testing.T, engine *CoreEngine, testName string) {
	const numRequests = 1000
	const numConcurrent = 10

	handler := engine.CreateHandler()

	// Start memory tracking
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()

	// Run concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numRequests/numConcurrent; j++ {
				req := httptest.NewRequest("POST", "/test/path", bytes.NewReader([]byte(`{"test": "data", "user": "john@example.com"}`)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "Test Agent")
				req.Header.Set("Authorization", "Bearer token123")

				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	// Measure memory usage
	runtime.GC()
	runtime.ReadMemStats(&m2)

	memUsed := m2.TotalAlloc - m1.TotalAlloc

	t.Logf("%s - %d requests in %v (%.2f req/sec), memory used: %d bytes",
		testName, numRequests, duration, float64(numRequests)/duration.Seconds(), memUsed)
}

// BenchmarkRequestPooling benchmarks request object pooling
func BenchmarkRequestPooling(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		pool := NewRequestPool()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req := pool.Get()
				req.Method = "GET"
				req.Path = "/test"
				req.Headers["Content-Type"] = []string{"application/json"}
				pool.Put(req)
			}
		})
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req := &Request{
					Headers: make(map[string][]string),
					Context: make(map[string]interface{}),
				}
				req.Method = "GET"
				req.Path = "/test"
				req.Headers["Content-Type"] = []string{"application/json"}
				// No pooling - just let GC handle it
			}
		})
	})
}

// BenchmarkResponsePooling benchmarks response object pooling
func BenchmarkResponsePooling(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		pool := NewResponsePool()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				resp := pool.Get()
				resp.StatusCode = 200
				resp.Headers["Content-Type"] = []string{"application/json"}
				resp.Body = []byte(`{"success": true}`)
				pool.Put(resp)
			}
		})
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				resp := &Response{
					Headers:  make(map[string][]string),
					Metadata: make(map[string]interface{}),
				}
				resp.StatusCode = 200
				resp.Headers["Content-Type"] = []string{"application/json"}
				resp.Body = []byte(`{"success": true}`)
				// No pooling - just let GC handle it
			}
		})
	})
}

// BenchmarkBufferPooling benchmarks buffer pooling
func BenchmarkBufferPooling(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		pool := NewBufferPool(64 * 1024)
		data := []byte("some test data to write to buffer")
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := pool.Get()
				buf.Write(data)
				pool.Put(buf)
			}
		})
	})

	b.Run("WithoutPool", func(b *testing.B) {
		data := []byte("some test data to write to buffer")
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := bytes.NewBuffer(make([]byte, 0, 1024))
				buf.Write(data)
				// No pooling - just let GC handle it
			}
		})
	})
}

// BenchmarkStringInterning benchmarks string interning
func BenchmarkStringInterning(b *testing.B) {
	strings := []string{
		"application/json",
		"text/html",
		"text/plain",
		"application/xml",
		"GET", "POST", "PUT", "DELETE",
		"/api/users", "/api/orders", "/api/products",
	}

	b.Run("WithInterning", func(b *testing.B) {
		pool := NewStringPool()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				for _, s := range strings {
					_ = pool.Intern(s)
				}
			}
		})
	})

	b.Run("WithoutInterning", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				for _, s := range strings {
					_ = s // Just use string as-is
				}
			}
		})
	})
}

// TestPoolMetrics verifies pool metrics are collected correctly
func TestPoolMetrics(t *testing.T) {
	requestPool := NewRequestPool()
	responsePool := NewResponsePool()
	bufferPool := NewBufferPool(1024)
	stringPool := NewStringPool()

	// Use pools to generate metrics
	req := requestPool.Get()
	req.Method = "GET"
	requestPool.Put(req)

	resp := responsePool.Get()
	resp.StatusCode = 200
	responsePool.Put(resp)

	buf := bufferPool.Get()
	buf.WriteString("test")
	bufferPool.Put(buf)

	_ = stringPool.Intern("test-string")

	// Check metrics
	reqMetrics := requestPool.GetMetrics()
	if reqMetrics.Gets == 0 {
		t.Error("Request pool metrics not recorded")
	}

	respMetrics := responsePool.GetMetrics()
	if respMetrics.Gets == 0 {
		t.Error("Response pool metrics not recorded")
	}

	bufMetrics := bufferPool.GetMetrics()
	if bufMetrics.Gets == 0 {
		t.Error("Buffer pool metrics not recorded")
	}

	strMetrics := stringPool.GetMetrics()
	if strMetrics.Lookups == 0 {
		t.Error("String pool metrics not recorded")
	}

	t.Logf("Request metrics: %+v", reqMetrics)
	t.Logf("Response metrics: %+v", respMetrics)
	t.Logf("Buffer metrics: %+v", bufMetrics)
	t.Logf("String metrics: %+v", strMetrics)
}

// TestHTTPRequestConversion tests the optimized HTTP request conversion
func TestHTTPRequestConversion(t *testing.T) {
	engine := NewCoreEngine()
	config := &FrameworkConfig{
		Name:          "test-conversion",
		Version:       "1.0.0",
		Environment:   "test",
		PluginConfigs: make(map[string]PluginConfig),
	}

	if err := engine.Initialize(config); err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	// Create test HTTP request
	body := `{"user": "test", "data": "example"}`
	httpReq := httptest.NewRequest("POST", "/api/test", bytes.NewReader([]byte(body)))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "Test Agent")
	httpReq.Header.Set("X-Custom-Header", "custom-value")

	// Convert with pools enabled
	engine.SetPoolEnabled(true)
	req1 := engine.convertHTTPRequest(httpReq)

	// Verify conversion
	if req1.Method != "POST" {
		t.Errorf("Expected method POST, got %s", req1.Method)
	}
	if req1.Path != "/api/test" {
		t.Errorf("Expected path /api/test, got %s", req1.Path)
	}
	if string(req1.Body) != body {
		t.Errorf("Expected body %s, got %s", body, string(req1.Body))
	}
	if req1.Headers["Content-Type"][0] != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", req1.Headers["Content-Type"][0])
	}

	// Return to pool
	engine.GetPoolManager().PutRequest(req1)

	// Get metrics
	metrics := engine.GetPoolMetrics()
	t.Logf("Pool metrics after conversion: %+v", metrics)
}

// TestConcurrentPoolUsage tests concurrent access to pools
func TestConcurrentPoolUsage(t *testing.T) {
	const numGoroutines = 100
	const numOperations = 1000

	engine := NewCoreEngine()
	config := &FrameworkConfig{
		Name:          "test-concurrent",
		Version:       "1.0.0",
		Environment:   "test",
		PluginConfigs: make(map[string]PluginConfig),
	}

	if err := engine.Initialize(config); err != nil {
		t.Fatalf("Failed to initialize framework: %v", err)
	}

	var wg sync.WaitGroup

	// Test concurrent request pool usage
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				req := engine.GetPoolManager().GetRequest()
				req.Method = "GET"
				req.Path = "/test"
				engine.GetPoolManager().PutRequest(req)
			}
		}()
	}

	wg.Wait()

	// Verify metrics
	metrics := engine.GetPoolMetrics()
	reqMetrics := metrics["request_pool"].(RequestPoolMetrics)

	expectedOps := int64(numGoroutines * numOperations)
	if reqMetrics.Gets != expectedOps {
		t.Errorf("Expected %d gets, got %d", expectedOps, reqMetrics.Gets)
	}
	if reqMetrics.Puts != expectedOps {
		t.Errorf("Expected %d puts, got %d", expectedOps, reqMetrics.Puts)
	}

	t.Logf("Concurrent test completed - operations: %d, metrics: %+v", expectedOps, reqMetrics)
}
