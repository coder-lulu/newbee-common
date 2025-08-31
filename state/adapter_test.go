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
	"time"
)

// InMemoryStateManager provides an in-memory implementation for testing
type InMemoryStateManager struct {
	data      map[string]interface{}
	observers []StateObserver
	mu        sync.RWMutex
}

func NewInMemoryStateManager() *InMemoryStateManager {
	return &InMemoryStateManager{
		data:      make(map[string]interface{}),
		observers: make([]StateObserver, 0),
	}
}

func (ism *InMemoryStateManager) GetState(ctx context.Context, key string) (interface{}, error) {
	ism.mu.RLock()
	defer ism.mu.RUnlock()

	if value, exists := ism.data[key]; exists {
		return value, nil
	}
	return nil, fmt.Errorf("state key %s not found", key)
}

func (ism *InMemoryStateManager) SetState(ctx context.Context, key string, value interface{}) error {
	ism.mu.Lock()
	defer ism.mu.Unlock()

	oldValue := ism.data[key]
	ism.data[key] = value

	// Notify observers
	go func() {
		for _, observer := range ism.observers {
			observer.OnStateChanged(ctx, key, oldValue, value)
		}
	}()

	return nil
}

func (ism *InMemoryStateManager) DeleteState(ctx context.Context, key string) error {
	ism.mu.Lock()
	defer ism.mu.Unlock()

	if oldValue, exists := ism.data[key]; exists {
		delete(ism.data, key)

		// Notify observers
		go func() {
			for _, observer := range ism.observers {
				observer.OnStateDeleted(ctx, key, oldValue)
			}
		}()

		return nil
	}
	return fmt.Errorf("state key %s not found", key)
}

func (ism *InMemoryStateManager) GetStates(ctx context.Context, keys []string) (map[string]interface{}, error) {
	ism.mu.RLock()
	defer ism.mu.RUnlock()

	result := make(map[string]interface{})
	for _, key := range keys {
		if value, exists := ism.data[key]; exists {
			result[key] = value
		}
	}
	return result, nil
}

func (ism *InMemoryStateManager) SetStates(ctx context.Context, states map[string]interface{}) error {
	ism.mu.Lock()
	defer ism.mu.Unlock()

	for key, value := range states {
		oldValue := ism.data[key]
		ism.data[key] = value

		// Notify observers (async to avoid deadlock)
		go func(k string, old, new interface{}) {
			for _, observer := range ism.observers {
				observer.OnStateChanged(ctx, k, old, new)
			}
		}(key, oldValue, value)
	}
	return nil
}

func (ism *InMemoryStateManager) ListStates(ctx context.Context, prefix string) ([]string, error) {
	ism.mu.RLock()
	defer ism.mu.RUnlock()

	var keys []string
	for key := range ism.data {
		if prefix == "" || (len(key) >= len(prefix) && key[:len(prefix)] == prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (ism *InMemoryStateManager) AddObserver(observer StateObserver) {
	ism.mu.Lock()
	defer ism.mu.Unlock()

	ism.observers = append(ism.observers, observer)
}

func (ism *InMemoryStateManager) RemoveObserver(observer StateObserver) {
	ism.mu.Lock()
	defer ism.mu.Unlock()

	for i, obs := range ism.observers {
		if obs == observer {
			ism.observers = append(ism.observers[:i], ism.observers[i+1:]...)
			break
		}
	}
}

// CacheableInMemoryStateManager extends InMemoryStateManager with cache functionality
type CacheableInMemoryStateManager struct {
	*InMemoryStateManager
	cache     map[string]*CacheEntry
	cacheSize int
	cacheMu   sync.RWMutex
}

type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
	Hits      int64
}

func NewCacheableInMemoryStateManager(cacheSize int) *CacheableInMemoryStateManager {
	return &CacheableInMemoryStateManager{
		InMemoryStateManager: NewInMemoryStateManager(),
		cache:                make(map[string]*CacheEntry),
		cacheSize:            cacheSize,
	}
}

func (cism *CacheableInMemoryStateManager) GetState(ctx context.Context, key string) (interface{}, error) {
	// Try cache first
	cism.cacheMu.RLock()
	if entry, exists := cism.cache[key]; exists && (entry.ExpiresAt.IsZero() || time.Now().Before(entry.ExpiresAt)) {
		entry.Hits++
		value := entry.Value
		cism.cacheMu.RUnlock()
		return value, nil
	}
	cism.cacheMu.RUnlock()

	// Get from underlying storage
	value, err := cism.InMemoryStateManager.GetState(ctx, key)
	if err == nil {
		// Cache the result
		cism.cacheMu.Lock()
		if len(cism.cache) < cism.cacheSize {
			cism.cache[key] = &CacheEntry{
				Value:     value,
				ExpiresAt: time.Now().Add(5 * time.Minute), // Default TTL
				Hits:      1,
			}
		}
		cism.cacheMu.Unlock()
	}
	return value, err
}

func (cism *CacheableInMemoryStateManager) SetState(ctx context.Context, key string, value interface{}) error {
	// Update cache
	cism.InvalidateCache(ctx, key)

	return cism.InMemoryStateManager.SetState(ctx, key, value)
}

func (cism *CacheableInMemoryStateManager) InvalidateCache(ctx context.Context, key string) error {
	cism.cacheMu.Lock()
	defer cism.cacheMu.Unlock()

	delete(cism.cache, key)
	return nil
}

func (cism *CacheableInMemoryStateManager) InvalidatePattern(ctx context.Context, pattern string) error {
	cism.cacheMu.Lock()
	defer cism.cacheMu.Unlock()

	for key := range cism.cache {
		if cism.matchPattern(pattern, key) {
			delete(cism.cache, key)
		}
	}
	return nil
}

func (cism *CacheableInMemoryStateManager) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	cism.cacheMu.RLock()
	defer cism.cacheMu.RUnlock()

	totalHits := int64(0)
	entryCount := len(cism.cache)
	expiredCount := 0

	now := time.Now()
	for _, entry := range cism.cache {
		totalHits += entry.Hits
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_entries":   entryCount,
		"total_hits":      totalHits,
		"expired_entries": expiredCount,
		"cache_size":      cism.cacheSize,
	}, nil
}

func (cism *CacheableInMemoryStateManager) matchPattern(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(key) >= len(prefix) && key[:len(prefix)] == prefix
	}
	return pattern == key
}

// AsyncInMemoryStateManager provides async operations
type AsyncInMemoryStateManager struct {
	*InMemoryStateManager
}

func NewAsyncInMemoryStateManager() *AsyncInMemoryStateManager {
	return &AsyncInMemoryStateManager{
		InMemoryStateManager: NewInMemoryStateManager(),
	}
}

func (aism *AsyncInMemoryStateManager) SetStateAsync(ctx context.Context, key string, value interface{}) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		defer close(errChan)
		err := aism.InMemoryStateManager.SetState(ctx, key, value)
		errChan <- err
	}()

	return errChan
}

func (aism *AsyncInMemoryStateManager) SetStatesAsync(ctx context.Context, states map[string]interface{}) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		defer close(errChan)
		err := aism.InMemoryStateManager.SetStates(ctx, states)
		errChan <- err
	}()

	return errChan
}

func (aism *AsyncInMemoryStateManager) DeleteStateAsync(ctx context.Context, key string) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		defer close(errChan)
		err := aism.InMemoryStateManager.DeleteState(ctx, key)
		errChan <- err
	}()

	return errChan
}

// Test InMemoryStateManager
func TestInMemoryStateManager_BasicOperations(t *testing.T) {
	manager := NewInMemoryStateManager()
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

func TestInMemoryStateManager_BatchOperations(t *testing.T) {
	manager := NewInMemoryStateManager()
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
}

func TestInMemoryStateManager_Observers(t *testing.T) {
	manager := NewInMemoryStateManager()
	observer := NewMockStateObserver()
	ctx := context.Background()

	manager.AddObserver(observer)

	// Test state change notification
	err := manager.SetState(ctx, "test:key", "test_value")
	if err != nil {
		t.Errorf("SetState should not return error, got: %v", err)
	}

	// Wait a bit for async notification
	time.Sleep(10 * time.Millisecond)

	changes := observer.GetChanges()
	if len(changes) != 1 {
		t.Errorf("Observer should receive 1 change, got %d", len(changes))
	}

	change := changes[0]
	if change.Key != "test:key" || change.NewValue != "test_value" || change.Action != "changed" {
		t.Error("Observer should receive correct change notification")
	}

	// Test state deletion notification
	observer.Reset()
	err = manager.DeleteState(ctx, "test:key")
	if err != nil {
		t.Errorf("DeleteState should not return error, got: %v", err)
	}

	// Wait a bit for async notification
	time.Sleep(10 * time.Millisecond)

	changes = observer.GetChanges()
	if len(changes) != 1 {
		t.Errorf("Observer should receive 1 deletion, got %d", len(changes))
	}

	change = changes[0]
	if change.Key != "test:key" || change.OldValue != "test_value" || change.Action != "deleted" {
		t.Error("Observer should receive correct deletion notification")
	}

	// Test observer removal
	manager.RemoveObserver(observer)
	observer.Reset()

	manager.SetState(ctx, "new:key", "new_value")
	time.Sleep(10 * time.Millisecond)

	changes = observer.GetChanges()
	if len(changes) != 0 {
		t.Errorf("Observer should not receive changes after removal, got %d", len(changes))
	}
}

// Test CacheableInMemoryStateManager
func TestCacheableInMemoryStateManager_CacheOperations(t *testing.T) {
	manager := NewCacheableInMemoryStateManager(10)
	ctx := context.Background()

	// Set initial state
	err := manager.SetState(ctx, "cached:key", "cached_value")
	if err != nil {
		t.Errorf("SetState should not return error, got: %v", err)
	}

	// First get should populate cache
	value1, err := manager.GetState(ctx, "cached:key")
	if err != nil {
		t.Errorf("GetState should not return error, got: %v", err)
	}
	if value1 != "cached_value" {
		t.Error("GetState should return correct value")
	}

	// Second get should hit cache
	value2, err := manager.GetState(ctx, "cached:key")
	if err != nil {
		t.Errorf("GetState should not return error, got: %v", err)
	}
	if value2 != "cached_value" {
		t.Error("GetState should return cached value")
	}

	// Check cache stats
	stats, err := manager.GetCacheStats(ctx)
	if err != nil {
		t.Errorf("GetCacheStats should not return error, got: %v", err)
	}

	if stats["total_entries"].(int) != 1 {
		t.Error("Cache should have 1 entry")
	}
	if stats["total_hits"].(int64) != 2 {
		t.Error("Cache should have 2 hits")
	}

	// Test cache invalidation
	err = manager.InvalidateCache(ctx, "cached:key")
	if err != nil {
		t.Errorf("InvalidateCache should not return error, got: %v", err)
	}

	// Check that cache is empty
	stats, _ = manager.GetCacheStats(ctx)
	if stats["total_entries"].(int) != 0 {
		t.Error("Cache should be empty after invalidation")
	}
}

func TestCacheableInMemoryStateManager_PatternInvalidation(t *testing.T) {
	manager := NewCacheableInMemoryStateManager(10)
	ctx := context.Background()

	// Set multiple states to populate cache
	states := map[string]interface{}{
		"user:123":       "user_data",
		"user:456":       "user_data2",
		"config:setting": "setting_value",
	}

	for key, value := range states {
		manager.SetState(ctx, key, value)
		manager.GetState(ctx, key) // Populate cache
	}

	// Verify cache has entries
	stats, _ := manager.GetCacheStats(ctx)
	if stats["total_entries"].(int) != 3 {
		t.Error("Cache should have 3 entries")
	}

	// Invalidate user:* pattern
	err := manager.InvalidatePattern(ctx, "user:*")
	if err != nil {
		t.Errorf("InvalidatePattern should not return error, got: %v", err)
	}

	// Check that only config entry remains
	stats, _ = manager.GetCacheStats(ctx)
	if stats["total_entries"].(int) != 1 {
		t.Error("Cache should have 1 entry after pattern invalidation")
	}
}

// Test AsyncInMemoryStateManager
func TestAsyncInMemoryStateManager_AsyncOperations(t *testing.T) {
	manager := NewAsyncInMemoryStateManager()
	ctx := context.Background()

	// Test SetStateAsync
	errChan := manager.SetStateAsync(ctx, "async:key", "async_value")
	err := <-errChan
	if err != nil {
		t.Errorf("SetStateAsync should not return error, got: %v", err)
	}

	// Verify state was set
	value, err := manager.GetState(ctx, "async:key")
	if err != nil {
		t.Errorf("GetState should not return error after async set, got: %v", err)
	}
	if value != "async_value" {
		t.Error("GetState should return value set asynchronously")
	}

	// Test SetStatesAsync
	states := map[string]interface{}{
		"async:key1": "value1",
		"async:key2": "value2",
	}

	errChan = manager.SetStatesAsync(ctx, states)
	err = <-errChan
	if err != nil {
		t.Errorf("SetStatesAsync should not return error, got: %v", err)
	}

	// Verify states were set
	result, err := manager.GetStates(ctx, []string{"async:key1", "async:key2"})
	if err != nil {
		t.Errorf("GetStates should not return error, got: %v", err)
	}
	if len(result) != 2 {
		t.Error("GetStates should return 2 async-set states")
	}

	// Test DeleteStateAsync
	errChan = manager.DeleteStateAsync(ctx, "async:key1")
	err = <-errChan
	if err != nil {
		t.Errorf("DeleteStateAsync should not return error, got: %v", err)
	}

	// Verify state was deleted
	_, err = manager.GetState(ctx, "async:key1")
	if err == nil {
		t.Error("GetState should return error after async delete")
	}
}

func TestAsyncInMemoryStateManager_ConcurrentAsyncOperations(t *testing.T) {
	manager := NewAsyncInMemoryStateManager()
	ctx := context.Background()

	numOperations := 100
	errChannels := make([]<-chan error, 0, numOperations)

	// Start multiple async operations
	for i := 0; i < numOperations; i++ {
		key := fmt.Sprintf("concurrent:key:%d", i)
		value := fmt.Sprintf("value_%d", i)
		errChan := manager.SetStateAsync(ctx, key, value)
		errChannels = append(errChannels, errChan)
	}

	// Wait for all operations to complete
	for i, errChan := range errChannels {
		err := <-errChan
		if err != nil {
			t.Errorf("Async operation %d should not return error, got: %v", i, err)
		}
	}

	// Verify all states were set
	keys, err := manager.ListStates(ctx, "concurrent:key:")
	if err != nil {
		t.Errorf("ListStates should not return error, got: %v", err)
	}
	if len(keys) != numOperations {
		t.Errorf("ListStates should return %d keys, got %d", numOperations, len(keys))
	}
}

// Error injection for testing error handling
type ErrorInjectingStateManager struct {
	*InMemoryStateManager
	getError    error
	setError    error
	deleteError error
}

func NewErrorInjectingStateManager() *ErrorInjectingStateManager {
	return &ErrorInjectingStateManager{
		InMemoryStateManager: NewInMemoryStateManager(),
	}
}

func (eism *ErrorInjectingStateManager) GetState(ctx context.Context, key string) (interface{}, error) {
	if eism.getError != nil {
		return nil, eism.getError
	}
	return eism.InMemoryStateManager.GetState(ctx, key)
}

func (eism *ErrorInjectingStateManager) SetState(ctx context.Context, key string, value interface{}) error {
	if eism.setError != nil {
		return eism.setError
	}
	return eism.InMemoryStateManager.SetState(ctx, key, value)
}

func (eism *ErrorInjectingStateManager) DeleteState(ctx context.Context, key string) error {
	if eism.deleteError != nil {
		return eism.deleteError
	}
	return eism.InMemoryStateManager.DeleteState(ctx, key)
}

func (eism *ErrorInjectingStateManager) SetGetError(err error) {
	eism.getError = err
}

func (eism *ErrorInjectingStateManager) SetSetError(err error) {
	eism.setError = err
}

func (eism *ErrorInjectingStateManager) SetDeleteError(err error) {
	eism.deleteError = err
}

func TestErrorInjectingStateManager(t *testing.T) {
	manager := NewErrorInjectingStateManager()
	ctx := context.Background()

	// Test GetState error
	manager.SetGetError(errors.New("get error"))
	_, err := manager.GetState(ctx, "test:key")
	if err == nil || err.Error() != "get error" {
		t.Error("GetState should return injected error")
	}

	// Test SetState error
	manager.SetGetError(nil)
	manager.SetSetError(errors.New("set error"))
	err = manager.SetState(ctx, "test:key", "value")
	if err == nil || err.Error() != "set error" {
		t.Error("SetState should return injected error")
	}

	// Test DeleteState error
	manager.SetSetError(nil)
	manager.SetDeleteError(errors.New("delete error"))
	err = manager.DeleteState(ctx, "test:key")
	if err == nil || err.Error() != "delete error" {
		t.Error("DeleteState should return injected error")
	}
}
