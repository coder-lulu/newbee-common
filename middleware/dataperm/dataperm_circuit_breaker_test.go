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

package dataperm

import (
	"context"
	"testing"
	"time"

	"github.com/coder-lulu/newbee-common/i18n"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
)

// MockRPCClient simulates an RPC client for testing
type MockRPCClient struct{}

func (m *MockRPCClient) InitRoleDataPermToRedis(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

func (m *MockRPCClient) InitDeptDataPermToRedis(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

func TestDataPermMiddleware_CircuitBreakerConfig(t *testing.T) {
	// Test basic circuit breaker configuration
	config := &DataPermConfig{
		EnableTenantMode:      false,
		DefaultTenantId:       entenum.TenantDefaultId,
		CircuitBreakerEnabled: true,
		L1CacheEnabled:        false,
		RedisCircuitBreaker: &CircuitBreakerConfig{
			Name:                    "test-redis",
			FailureThreshold:        3,
			FailureRate:             0.5,
			MinimumRequestThreshold: 2,
			MaxRequests:             5,
			Interval:                60 * time.Second,
			Timeout:                 1 * time.Second,
		},
		TimeoutConfig: &TimeoutConfig{
			RequestTimeout: 1 * time.Second,
		},
	}

	// Skip Redis client for basic configuration test
	middleware := NewDataPermMiddleware(nil, nil, nil, config)

	// Check circuit breaker stats structure
	stats := middleware.GetCircuitBreakerStats()
	if len(stats) == 0 {
		t.Error("Expected circuit breaker stats to be available")
	}

	// Should have redis and rpc circuit breaker stats
	if _, exists := stats["redis"]; !exists {
		t.Error("Expected redis circuit breaker stats")
	}

	if _, exists := stats["rpc"]; !exists {
		t.Error("Expected rpc circuit breaker stats")
	}

	t.Logf("Circuit breaker stats structure: %+v", stats)
}

func TestDataPermMiddleware_RPCCircuitBreaker(t *testing.T) {
	mockRPC := &MockRPCClient{}
	trans := &i18n.Translator{}

	config := &DataPermConfig{
		EnableTenantMode:      false,
		DefaultTenantId:       entenum.TenantDefaultId,
		CircuitBreakerEnabled: true,
		L1CacheEnabled:        false,
		RPCCircuitBreaker: &CircuitBreakerConfig{
			Name:                    "test-rpc",
			FailureThreshold:        3,
			FailureRate:             0.5,
			MinimumRequestThreshold: 2,
			MaxRequests:             5,
			Interval:                60 * time.Second,
			Timeout:                 2 * time.Second,
		},
		TimeoutConfig: &TimeoutConfig{
			HandlerTimeout: 1 * time.Second,
		},
	}

	middleware := NewDataPermMiddleware(nil, mockRPC, trans, config)

	// Check circuit breaker stats
	stats := middleware.GetCircuitBreakerStats()
	rpcStats, ok := stats["rpc"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected rpc circuit breaker stats")
	}

	state, ok := rpcStats["state"].(string)
	if !ok {
		t.Fatal("Expected rpc circuit breaker state")
	}

	// Initially should be closed
	if state != "CLOSED" {
		t.Errorf("Expected initial RPC circuit breaker state to be CLOSED, got: %s", state)
	}

	t.Logf("RPC Circuit breaker stats: %+v", stats)
}

func TestDataPermMiddleware_CircuitBreakerReset(t *testing.T) {
	mockRPC := &MockRPCClient{}
	trans := &i18n.Translator{}

	config := &DataPermConfig{
		EnableTenantMode:      false,
		DefaultTenantId:       entenum.TenantDefaultId,
		CircuitBreakerEnabled: true,
		L1CacheEnabled:        false,
		RedisCircuitBreaker: &CircuitBreakerConfig{
			Name:                    "test-reset",
			FailureThreshold:        2,
			FailureRate:             0.5,
			MinimumRequestThreshold: 2,
			MaxRequests:             5,
			Interval:                60 * time.Second,
			Timeout:                 1 * time.Second,
		},
	}

	middleware := NewDataPermMiddleware(nil, mockRPC, trans, config)

	// Check initial circuit breaker state
	stats := middleware.GetCircuitBreakerStats()
	redisStats := stats["redis"].(map[string]interface{})
	state := redisStats["state"].(string)

	if state != "CLOSED" {
		t.Errorf("Expected initial circuit breaker to be CLOSED, got: %s", state)
	}

	// Reset circuit breakers - should not panic
	middleware.ResetCircuitBreakers()

	// Check that circuit breaker is still closed
	stats = middleware.GetCircuitBreakerStats()
	redisStats = stats["redis"].(map[string]interface{})
	state = redisStats["state"].(string)

	if state != "CLOSED" {
		t.Errorf("Expected circuit breaker to be CLOSED after reset, got: %s", state)
	}
}

func TestDataPermMiddleware_TimeoutConfig(t *testing.T) {
	mockRPC := &MockRPCClient{}
	trans := &i18n.Translator{}

	// Test with custom timeout configuration
	config := &DataPermConfig{
		EnableTenantMode:      false,
		DefaultTenantId:       entenum.TenantDefaultId,
		CircuitBreakerEnabled: true,
		L1CacheEnabled:        false,
		TimeoutConfig: &TimeoutConfig{
			RequestTimeout:  500 * time.Millisecond,
			HandlerTimeout:  2 * time.Second,
			ShutdownTimeout: 5 * time.Second,
		},
	}

	middleware := NewDataPermMiddleware(nil, mockRPC, trans, config)

	// Verify timeout configuration is applied
	if middleware.Config.TimeoutConfig.RequestTimeout != 500*time.Millisecond {
		t.Errorf("Expected RequestTimeout to be 500ms, got: %v", middleware.Config.TimeoutConfig.RequestTimeout)
	}

	if middleware.Config.TimeoutConfig.HandlerTimeout != 2*time.Second {
		t.Errorf("Expected HandlerTimeout to be 2s, got: %v", middleware.Config.TimeoutConfig.HandlerTimeout)
	}
}

func TestDataPermMiddleware_DisabledCircuitBreaker(t *testing.T) {
	mockRPC := &MockRPCClient{}
	trans := &i18n.Translator{}

	// Test with circuit breaker disabled
	config := &DataPermConfig{
		EnableTenantMode:      false,
		DefaultTenantId:       entenum.TenantDefaultId,
		CircuitBreakerEnabled: false, // Disabled
		L1CacheEnabled:        false,
	}

	middleware := NewDataPermMiddleware(nil, mockRPC, trans, config)

	// Circuit breaker stats should be empty
	stats := middleware.GetCircuitBreakerStats()
	if len(stats) != 0 {
		t.Errorf("Expected empty circuit breaker stats when disabled, got: %+v", stats)
	}

	// Reset should not panic
	middleware.ResetCircuitBreakers()

	// Verify circuit breakers are not initialized
	if middleware.redisCircuitBreaker != nil {
		t.Error("Expected redis circuit breaker to be nil when disabled")
	}

	if middleware.rpcCircuitBreaker != nil {
		t.Error("Expected rpc circuit breaker to be nil when disabled")
	}
}
