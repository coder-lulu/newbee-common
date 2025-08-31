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

package state

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Mock implementations for testing interfaces

// MockStateManager implements StateManager interface
type MockStateManager struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

func NewMockStateManager() *MockStateManager {
	return &MockStateManager{
		data: make(map[string]interface{}),
	}
}

func (m *MockStateManager) GetState(ctx context.Context, key string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if value, exists := m.data[key]; exists {
		return value, nil
	}
	return nil, fmt.Errorf("state key %s not found", key)
}

func (m *MockStateManager) SetState(ctx context.Context, key string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[key] = value
	return nil
}

func (m *MockStateManager) DeleteState(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

func (m *MockStateManager) GetStates(ctx context.Context, keys []string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})
	for _, key := range keys {
		if value, exists := m.data[key]; exists {
			result[key] = value
		}
	}
	return result, nil
}

func (m *MockStateManager) SetStates(ctx context.Context, states map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, value := range states {
		m.data[key] = value
	}
	return nil
}

func (m *MockStateManager) ListStates(ctx context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key := range m.data {
		if prefix == "" || len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// MockStateObserver implements StateObserver interface
type MockStateObserver struct {
	changes []StateChange
	mu      sync.Mutex
}

type StateChange struct {
	Key      string
	OldValue interface{}
	NewValue interface{}
	Action   string // "changed" or "deleted"
}

func NewMockStateObserver() *MockStateObserver {
	return &MockStateObserver{
		changes: make([]StateChange, 0),
	}
}

func (m *MockStateObserver) OnStateChanged(ctx context.Context, key string, oldValue, newValue interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.changes = append(m.changes, StateChange{
		Key:      key,
		OldValue: oldValue,
		NewValue: newValue,
		Action:   "changed",
	})
}

func (m *MockStateObserver) OnStateDeleted(ctx context.Context, key string, oldValue interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.changes = append(m.changes, StateChange{
		Key:      key,
		OldValue: oldValue,
		NewValue: nil,
		Action:   "deleted",
	})
}

func (m *MockStateObserver) GetChanges() []StateChange {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	changes := make([]StateChange, len(m.changes))
	copy(changes, m.changes)
	return changes
}

func (m *MockStateObserver) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.changes = m.changes[:0]
}

// MockStateBroadcaster implements StateBroadcaster interface
type MockStateBroadcaster struct {
	subscribers map[string][]*MockStateObserver
	mu          sync.RWMutex
}

func NewMockStateBroadcaster() *MockStateBroadcaster {
	return &MockStateBroadcaster{
		subscribers: make(map[string][]*MockStateObserver),
	}
}

func (m *MockStateBroadcaster) Subscribe(ctx context.Context, pattern string, observer StateObserver) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mockObserver, ok := observer.(*MockStateObserver)
	if !ok {
		return fmt.Errorf("observer must be *MockStateObserver for testing")
	}

	m.subscribers[pattern] = append(m.subscribers[pattern], mockObserver)
	return nil
}

func (m *MockStateBroadcaster) Unsubscribe(ctx context.Context, pattern string, observer StateObserver) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mockObserver, ok := observer.(*MockStateObserver)
	if !ok {
		return fmt.Errorf("observer must be *MockStateObserver for testing")
	}

	subscribers := m.subscribers[pattern]
	for i, sub := range subscribers {
		if sub == mockObserver {
			m.subscribers[pattern] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}
	return nil
}

func (m *MockStateBroadcaster) Broadcast(ctx context.Context, key string, oldValue, newValue interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for pattern, subscribers := range m.subscribers {
		if m.matchPattern(pattern, key) {
			for _, subscriber := range subscribers {
				if newValue == nil {
					subscriber.OnStateDeleted(ctx, key, oldValue)
				} else {
					subscriber.OnStateChanged(ctx, key, oldValue, newValue)
				}
			}
		}
	}
	return nil
}

func (m *MockStateBroadcaster) matchPattern(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(key) >= len(prefix) && key[:len(prefix)] == prefix
	}
	return pattern == key
}

// MockStateProvider implements StateProvider interface
type MockStateProvider struct {
	name        string
	initialized bool
	closed      bool
	healthy     bool
}

func NewMockStateProvider(name string) *MockStateProvider {
	return &MockStateProvider{
		name:    name,
		healthy: true,
	}
}

func (m *MockStateProvider) GetName() string {
	return m.name
}

func (m *MockStateProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	if m.closed {
		return errors.New("provider is closed")
	}
	m.initialized = true
	return nil
}

func (m *MockStateProvider) Close(ctx context.Context) error {
	m.closed = true
	m.initialized = false
	return nil
}

func (m *MockStateProvider) HealthCheck(ctx context.Context) error {
	if m.closed {
		return errors.New("provider is closed")
	}
	if !m.healthy {
		return errors.New("provider is unhealthy")
	}
	return nil
}

func (m *MockStateProvider) SetHealthy(healthy bool) {
	m.healthy = healthy
}

// Test StateManager Interface
func TestMockStateManager_BasicOperations(t *testing.T) {
	manager := NewMockStateManager()
	ctx := context.Background()

	// Test SetState and GetState
	key := "test:key"
	value := "test_value"

	err := manager.SetState(ctx, key, value)
	if err != nil {
		t.Errorf("SetState should not return error, got: %v", err)
	}

	result, err := manager.GetState(ctx, key)
	if err != nil {
		t.Errorf("GetState should not return error, got: %v", err)
	}
	if result != value {
		t.Errorf("GetState result = %v; expected %v", result, value)
	}

	// Test GetState for non-existent key
	_, err = manager.GetState(ctx, "non:existent")
	if err == nil {
		t.Error("GetState should return error for non-existent key")
	}

	// Test DeleteState
	err = manager.DeleteState(ctx, key)
	if err != nil {
		t.Errorf("DeleteState should not return error, got: %v", err)
	}

	_, err = manager.GetState(ctx, key)
	if err == nil {
		t.Error("GetState should return error after DeleteState")
	}
}

func TestMockStateManager_BatchOperations(t *testing.T) {
	manager := NewMockStateManager()
	ctx := context.Background()

	// Test SetStates
	states := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	err := manager.SetStates(ctx, states)
	if err != nil {
		t.Errorf("SetStates should not return error, got: %v", err)
	}

	// Test GetStates
	keys := []string{"key1", "key2", "key3", "non_existent"}
	result, err := manager.GetStates(ctx, keys)
	if err != nil {
		t.Errorf("GetStates should not return error, got: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("GetStates should return 3 items, got %d", len(result))
	}
	if result["key1"] != "value1" {
		t.Error("GetStates should return correct values")
	}
	if result["key2"] != 123 {
		t.Error("GetStates should return correct values")
	}
	if result["key3"] != true {
		t.Error("GetStates should return correct values")
	}

	// Test ListStates
	allKeys, err := manager.ListStates(ctx, "")
	if err != nil {
		t.Errorf("ListStates should not return error, got: %v", err)
	}
	if len(allKeys) != 3 {
		t.Errorf("ListStates should return 3 keys, got %d", len(allKeys))
	}

	// Test ListStates with prefix
	prefixKeys, err := manager.ListStates(ctx, "key")
	if err != nil {
		t.Errorf("ListStates with prefix should not return error, got: %v", err)
	}
	if len(prefixKeys) != 3 {
		t.Errorf("ListStates with prefix should return 3 keys, got %d", len(prefixKeys))
	}

	emptyKeys, err := manager.ListStates(ctx, "nonexistent")
	if err != nil {
		t.Errorf("ListStates with non-matching prefix should not return error, got: %v", err)
	}
	if len(emptyKeys) != 0 {
		t.Errorf("ListStates with non-matching prefix should return 0 keys, got %d", len(emptyKeys))
	}
}

func TestMockStateManager_ConcurrentAccess(t *testing.T) {
	manager := NewMockStateManager()
	ctx := context.Background()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 50

	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key_%d_%d", id, j)
				value := fmt.Sprintf("value_%d_%d", id, j)
				err := manager.SetState(ctx, key, value)
				if err != nil {
					t.Errorf("Concurrent SetState failed: %v", err)
				}
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key_%d_%d", id, j)
				_, _ = manager.GetState(ctx, key) // May not exist yet, so ignore error
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	allKeys, err := manager.ListStates(ctx, "")
	if err != nil {
		t.Errorf("ListStates after concurrent access failed: %v", err)
	}
	if len(allKeys) != numGoroutines*numOperations {
		t.Errorf("Expected %d keys after concurrent writes, got %d", numGoroutines*numOperations, len(allKeys))
	}
}

// Test StateObserver Interface
func TestMockStateObserver(t *testing.T) {
	observer := NewMockStateObserver()
	ctx := context.Background()

	// Test OnStateChanged
	observer.OnStateChanged(ctx, "key1", "old_value", "new_value")
	observer.OnStateChanged(ctx, "key2", nil, "initial_value")

	// Test OnStateDeleted
	observer.OnStateDeleted(ctx, "key3", "deleted_value")

	changes := observer.GetChanges()
	if len(changes) != 3 {
		t.Errorf("Expected 3 changes, got %d", len(changes))
	}

	// Verify changes
	if changes[0].Key != "key1" || changes[0].OldValue != "old_value" || changes[0].NewValue != "new_value" || changes[0].Action != "changed" {
		t.Error("First change not recorded correctly")
	}

	if changes[1].Key != "key2" || changes[1].OldValue != nil || changes[1].NewValue != "initial_value" || changes[1].Action != "changed" {
		t.Error("Second change not recorded correctly")
	}

	if changes[2].Key != "key3" || changes[2].OldValue != "deleted_value" || changes[2].NewValue != nil || changes[2].Action != "deleted" {
		t.Error("Delete change not recorded correctly")
	}

	// Test Reset
	observer.Reset()
	changes = observer.GetChanges()
	if len(changes) != 0 {
		t.Errorf("Expected 0 changes after reset, got %d", len(changes))
	}
}

// Test StateBroadcaster Interface
func TestMockStateBroadcaster(t *testing.T) {
	broadcaster := NewMockStateBroadcaster()
	ctx := context.Background()

	// Create observers
	observer1 := NewMockStateObserver()
	observer2 := NewMockStateObserver()

	// Subscribe observers
	err := broadcaster.Subscribe(ctx, "user:*", observer1)
	if err != nil {
		t.Errorf("Subscribe should not return error, got: %v", err)
	}

	err = broadcaster.Subscribe(ctx, "*", observer2)
	if err != nil {
		t.Errorf("Subscribe should not return error, got: %v", err)
	}

	// Broadcast change
	err = broadcaster.Broadcast(ctx, "user:123", nil, "new_user_data")
	if err != nil {
		t.Errorf("Broadcast should not return error, got: %v", err)
	}

	// Check observer1 (subscribed to "user:*")
	changes1 := observer1.GetChanges()
	if len(changes1) != 1 {
		t.Errorf("Observer1 should receive 1 change, got %d", len(changes1))
	}
	if changes1[0].Key != "user:123" || changes1[0].NewValue != "new_user_data" {
		t.Error("Observer1 did not receive correct change")
	}

	// Check observer2 (subscribed to "*")
	changes2 := observer2.GetChanges()
	if len(changes2) != 1 {
		t.Errorf("Observer2 should receive 1 change, got %d", len(changes2))
	}
	if changes2[0].Key != "user:123" || changes2[0].NewValue != "new_user_data" {
		t.Error("Observer2 did not receive correct change")
	}

	// Broadcast non-matching change
	observer1.Reset()
	observer2.Reset()

	err = broadcaster.Broadcast(ctx, "config:setting", "old_value", "new_value")
	if err != nil {
		t.Errorf("Broadcast should not return error, got: %v", err)
	}

	// Check that only observer2 receives this change
	changes1 = observer1.GetChanges()
	if len(changes1) != 0 {
		t.Errorf("Observer1 should not receive non-matching change, got %d", len(changes1))
	}

	changes2 = observer2.GetChanges()
	if len(changes2) != 1 {
		t.Errorf("Observer2 should receive wildcard change, got %d", len(changes2))
	}

	// Test Unsubscribe
	err = broadcaster.Unsubscribe(ctx, "user:*", observer1)
	if err != nil {
		t.Errorf("Unsubscribe should not return error, got: %v", err)
	}

	observer1.Reset()
	observer2.Reset()

	err = broadcaster.Broadcast(ctx, "user:456", nil, "another_user")
	if err != nil {
		t.Errorf("Broadcast should not return error, got: %v", err)
	}

	// observer1 should not receive anything after unsubscribe
	changes1 = observer1.GetChanges()
	if len(changes1) != 0 {
		t.Errorf("Observer1 should not receive changes after unsubscribe, got %d", len(changes1))
	}

	// observer2 should still receive changes
	changes2 = observer2.GetChanges()
	if len(changes2) != 1 {
		t.Errorf("Observer2 should still receive changes, got %d", len(changes2))
	}
}

// Test StateProvider Interface
func TestMockStateProvider(t *testing.T) {
	provider := NewMockStateProvider("test_provider")
	ctx := context.Background()

	// Test GetName
	if provider.GetName() != "test_provider" {
		t.Errorf("GetName() = %s; expected 'test_provider'", provider.GetName())
	}

	// Test Initialize
	config := map[string]interface{}{
		"host": "localhost",
		"port": 6379,
	}

	err := provider.Initialize(ctx, config)
	if err != nil {
		t.Errorf("Initialize should not return error, got: %v", err)
	}

	// Test HealthCheck
	err = provider.HealthCheck(ctx)
	if err != nil {
		t.Errorf("HealthCheck should not return error, got: %v", err)
	}

	// Test unhealthy state
	provider.SetHealthy(false)
	err = provider.HealthCheck(ctx)
	if err == nil {
		t.Error("HealthCheck should return error when unhealthy")
	}

	provider.SetHealthy(true)

	// Test Close
	err = provider.Close(ctx)
	if err != nil {
		t.Errorf("Close should not return error, got: %v", err)
	}

	// Test operations after close
	err = provider.HealthCheck(ctx)
	if err == nil {
		t.Error("HealthCheck should return error after close")
	}

	err = provider.Initialize(ctx, config)
	if err == nil {
		t.Error("Initialize should return error after close")
	}
}

func TestMockStateBroadcaster_PatternMatching(t *testing.T) {
	broadcaster := NewMockStateBroadcaster()

	tests := []struct {
		pattern string
		key     string
		matches bool
	}{
		{"*", "any.key", true},
		{"*", "", true},
		{"user:*", "user:123", true},
		{"user:*", "user:456:profile", true},
		{"user:*", "config:setting", false},
		{"user:123", "user:123", true},
		{"user:123", "user:456", false},
		{"config:*", "config:database", true},
		{"config:*", "user:config", false},
	}

	for _, test := range tests {
		result := broadcaster.matchPattern(test.pattern, test.key)
		if result != test.matches {
			t.Errorf("matchPattern(%s, %s) = %v; expected %v", test.pattern, test.key, result, test.matches)
		}
	}
}
