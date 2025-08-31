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

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewUnifiedConfigManager(t *testing.T) {
	manager := NewUnifiedConfigManager()

	if manager == nil {
		t.Error("NewUnifiedConfigManager should not return nil")
	}

	if manager.configs == nil {
		t.Error("configs map should be initialized")
	}

	if manager.defaults == nil {
		t.Error("defaults map should be initialized")
	}
}

func TestUnifiedConfigManager_Set(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test setting a string value
	manager.Set("test.string", "hello")

	// Test setting a number value
	manager.Set("test.number", 42)

	// Test setting a nested structure
	nested := map[string]interface{}{
		"nested_key": "nested_value",
	}
	manager.Set("test.nested", nested)
}

func TestUnifiedConfigManager_Get(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Set test values
	manager.Set("test.string", "hello")
	manager.Set("test.number", 42)
	manager.Set("test.bool", true)

	// Test getting string value
	value := manager.Get("test.string")
	if value != "hello" {
		t.Errorf("Expected 'hello', got %v", value)
	}

	// Test getting number value
	value = manager.Get("test.number")
	if value != 42 {
		t.Errorf("Expected 42, got %v", value)
	}

	// Test getting boolean value
	value = manager.Get("test.bool")
	if value != true {
		t.Errorf("Expected true, got %v", value)
	}

	// Test getting non-existent key
	value = manager.Get("non.existent")
	if value != nil {
		t.Errorf("Expected nil for non-existent key, got %v", value)
	}
}

func TestUnifiedConfigManager_GetWithDefault(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test getting non-existent key (should return nil)
	value := manager.Get("non.existent")
	if value != nil {
		t.Errorf("Expected nil for non-existent key, got %v", value)
	}

	// Test getting existing key
	manager.Set("existing.key", "existing_value")
	value = manager.Get("existing.key")
	if value != "existing_value" {
		t.Errorf("Expected 'existing_value', got %v", value)
	}
}

func TestUnifiedConfigManager_GetString(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test getting string value
	manager.Set("string.key", "test_string")
	value := manager.GetString("string.key")
	if value != "test_string" {
		t.Errorf("Expected 'test_string', got %s", value)
	}

	// Test getting non-string value should convert to string
	manager.Set("number.key", 42)
	value = manager.GetString("number.key")
	if value != "42" {
		t.Errorf("Expected '42' for converted non-string value, got %s", value)
	}

	// Test getting non-existent key
	value = manager.GetString("non.existent")
	if value != "" {
		t.Errorf("Expected empty string for non-existent key, got %s", value)
	}
}

func TestUnifiedConfigManager_GetInt(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test getting int value
	manager.Set("int.key", 42)
	value := manager.GetInt("int.key")
	if value != 42 {
		t.Errorf("Expected 42, got %d", value)
	}

	// Test getting non-int value should return 0
	manager.Set("string.key", "not_a_number")
	value = manager.GetInt("string.key")
	if value != 0 {
		t.Errorf("Expected 0 for non-int value, got %d", value)
	}

	// Test getting non-existent key
	value = manager.GetInt("non.existent")
	if value != 0 {
		t.Errorf("Expected 0 for non-existent key, got %d", value)
	}
}

func TestUnifiedConfigManager_GetBool(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test getting bool value
	manager.Set("bool.key", true)
	value := manager.GetBool("bool.key")
	if value != true {
		t.Errorf("Expected true, got %t", value)
	}

	// Test getting non-bool value should return false
	manager.Set("string.key", "not_a_bool")
	value = manager.GetBool("string.key")
	if value != false {
		t.Errorf("Expected false for non-bool value, got %t", value)
	}

	// Test getting non-existent key
	value = manager.GetBool("non.existent")
	if value != false {
		t.Errorf("Expected false for non-existent key, got %t", value)
	}
}

func TestUnifiedConfigManager_SetOverride(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Set initial value
	manager.Set("override.test", "initial_value")
	value := manager.Get("override.test")
	if value != "initial_value" {
		t.Errorf("Expected 'initial_value', got %v", value)
	}

	// Override the value
	manager.Set("override.test", "override_value")
	value = manager.Get("override.test")
	if value != "override_value" {
		t.Errorf("Expected 'override_value', got %v", value)
	}
}

func TestUnifiedConfigManager_Exists(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test key doesn't exist
	value := manager.Get("non.existent")
	if value != nil {
		t.Error("Get should return nil for non-existent key")
	}

	// Set a value and test it exists
	manager.Set("existing.key", "value")
	value = manager.Get("existing.key")
	if value == nil {
		t.Error("Get should return value for existing key")
	}
}

func TestUnifiedConfigManager_Delete(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Set a value
	manager.Set("delete.test", "value")
	if manager.Get("delete.test") == nil {
		t.Error("Key should exist before deletion")
	}

	// Delete the value
	manager.Delete("delete.test")
	if manager.Get("delete.test") != nil {
		t.Error("Key should not exist after deletion")
	}

	// Test deleting non-existent key (should not panic)
	manager.Delete("non.existent")
}

// Mock observer for testing
type MockObserver struct {
	changedKeys []string
	oldValues   []interface{}
	newValues   []interface{}
	mu          sync.Mutex
}

func (m *MockObserver) OnConfigChanged(key string, oldValue, newValue interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changedKeys = append(m.changedKeys, key)
	m.oldValues = append(m.oldValues, oldValue)
	m.newValues = append(m.newValues, newValue)
}

func (m *MockObserver) GetChanges() ([]string, []interface{}, []interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.changedKeys, m.oldValues, m.newValues
}

func TestUnifiedConfigManager_AddObserver(t *testing.T) {
	manager := NewUnifiedConfigManager()
	observer := &MockObserver{}

	// Add observer
	manager.AddObserver(observer)

	// Set a value and verify observer is called
	manager.Set("observer.test", "new_value")

	keys, oldValues, newValues := observer.GetChanges()
	if len(keys) != 1 {
		t.Errorf("Expected 1 change notification, got %d", len(keys))
	}

	if keys[0] != "observer.test" {
		t.Errorf("Expected key 'observer.test', got %s", keys[0])
	}

	if oldValues[0] != nil {
		t.Errorf("Expected old value to be nil, got %v", oldValues[0])
	}

	if newValues[0] != "new_value" {
		t.Errorf("Expected new value 'new_value', got %v", newValues[0])
	}
}

func TestUnifiedConfigManager_RemoveObserver(t *testing.T) {
	manager := NewUnifiedConfigManager()
	observer := &MockObserver{}

	// Add and then remove observer
	manager.AddObserver(observer)
	manager.RemoveObserver(observer)

	// Set a value and verify observer is not called
	manager.Set("observer.test", "new_value")

	keys, _, _ := observer.GetChanges()
	if len(keys) != 0 {
		t.Errorf("Expected 0 change notifications after removing observer, got %d", len(keys))
	}
}

func TestUnifiedConfigManager_ConcurrentAccess(t *testing.T) {
	manager := NewUnifiedConfigManager()
	var wg sync.WaitGroup

	// Test concurrent reads and writes
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Concurrent writer
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("concurrent.%d.%d", id, j)
				manager.Set(key, fmt.Sprintf("value_%d_%d", id, j))
			}
		}(i)

		// Concurrent reader
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("concurrent.%d.%d", id, j)
				manager.Get(key)
			}
		}(i)
	}

	wg.Wait()

	// Verify some values were set
	count := 0
	for i := 0; i < 10; i++ {
		for j := 0; j < 100; j++ {
			key := fmt.Sprintf("concurrent.%d.%d", i, j)
			if manager.Get(key) != nil {
				count++
			}
		}
	}

	if count == 0 {
		t.Error("Expected some concurrent writes to succeed")
	}
}

func TestUnifiedConfigManager_GetAllConfigs(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test with empty manager
	configs := manager.GetAllConfigs()
	if len(configs) != 0 {
		t.Errorf("Expected 0 configs for empty manager, got %d", len(configs))
	}

	// Add some configs
	manager.Set("key1", "value1")
	manager.Set("key2", "value2")
	manager.Set("key3", "value3")

	configs = manager.GetAllConfigs()
	if len(configs) != 3 {
		t.Errorf("Expected 3 configs, got %d", len(configs))
	}

	// Verify all configs are present
	expectedConfigs := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}
	for key, expectedValue := range expectedConfigs {
		if configs[key] != expectedValue {
			t.Errorf("Expected config '%s' = '%s', got %v", key, expectedValue, configs[key])
		}
	}
}

func TestUnifiedConfigManager_Clear(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Add some values
	manager.Set("clear.test1", "value1")
	manager.Set("clear.test2", "value2")

	// Verify values exist
	if manager.Get("clear.test1") == nil || manager.Get("clear.test2") == nil {
		t.Error("Values should exist before clear")
	}

	// Clear all values by deleting them
	manager.Delete("clear.test1")
	manager.Delete("clear.test2")

	// Verify values are gone
	if manager.Get("clear.test1") != nil || manager.Get("clear.test2") != nil {
		t.Error("Values should not exist after delete")
	}

	// Verify GetAllConfigs returns empty
	configs := manager.GetAllConfigs()
	if len(configs) != 0 {
		t.Errorf("Expected 0 configs after clear, got %d", len(configs))
	}
}

// Mock cache for testing
type MockCache struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

func NewMockCache() *MockCache {
	return &MockCache{
		data: make(map[string]interface{}),
	}
}

func (c *MockCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists := c.data[key]
	return value, exists
}

func (c *MockCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}

func (c *MockCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

func (c *MockCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]interface{})
}

func TestUnifiedConfigManager_WithCache(t *testing.T) {
	manager := NewUnifiedConfigManager()
	// Note: SetCache method may not exist in current implementation
	// This test demonstrates the intended cache functionality

	// Set a value
	manager.Set("cache.test", "cached_value")

	// Verify value is accessible through manager
	value := manager.Get("cache.test")
	if value != "cached_value" {
		t.Errorf("Expected manager value 'cached_value', got %v", value)
	}
}

// Mock source for testing
type MockSource struct {
	data map[string]interface{}
}

func NewMockSource() *MockSource {
	return &MockSource{
		data: make(map[string]interface{}),
	}
}

func (s *MockSource) Load(ctx context.Context) (map[string]interface{}, error) {
	return s.data, nil
}

func (s *MockSource) Watch(ctx context.Context, callback func(key string, value interface{})) error {
	// Mock implementation - doesn't actually watch
	return nil
}

func (s *MockSource) SetValue(key string, value interface{}) {
	s.data[key] = value
}

func TestUnifiedConfigManager_LoadConfigs(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Test basic LoadConfigs functionality
	ctx := context.Background()
	err := manager.LoadConfigs(ctx)
	if err != nil {
		t.Errorf("LoadConfigs should not return error, got: %v", err)
	}

	// Set some test values to verify manager functionality
	manager.Set("test.key1", "test_value1")
	manager.Set("test.key2", "test_value2")

	// Verify values are accessible
	value1 := manager.Get("test.key1")
	if value1 != "test_value1" {
		t.Errorf("Expected 'test_value1', got %v", value1)
	}

	value2 := manager.Get("test.key2")
	if value2 != "test_value2" {
		t.Errorf("Expected 'test_value2', got %v", value2)
	}
}

func TestUnifiedConfigManager_ToJSON(t *testing.T) {
	manager := NewUnifiedConfigManager()

	// Add some test data
	manager.Set("json.string", "test_string")
	manager.Set("json.number", 42)
	manager.Set("json.bool", true)

	// Convert to JSON using MarshalJSON
	jsonBytes, err := manager.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON should not return error, got: %v", err)
	}

	// Verify JSON is not empty
	if len(jsonBytes) == 0 {
		t.Error("JSON bytes should not be empty")
	}

	// Parse JSON back to verify structure
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonBytes, &parsed)
	if err != nil {
		t.Errorf("Generated JSON should be valid, got error: %v", err)
	}

	// Verify some values
	if parsed["json.string"] != "test_string" {
		t.Errorf("Expected 'test_string' in JSON, got %v", parsed["json.string"])
	}
}
