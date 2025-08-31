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
	"testing"
)

func TestDataPermScope_String(t *testing.T) {
	tests := []struct {
		scope    DataPermScope
		expected string
	}{
		{DataPermAll, "all"},
		{DataPermCustomDept, "custom_dept"},
		{DataPermOwnDeptAndSub, "own_dept_and_sub"},
		{DataPermOwnDept, "own_dept"},
		{DataPermOwn, "own"},
		{DataPermScope(99), "unknown"},
	}

	for _, test := range tests {
		result := test.scope.String()
		if result != test.expected {
			t.Errorf("DataPermScope(%d).String() = %s; expected %s", test.scope, result, test.expected)
		}
	}
}

func TestDataPermScope_Value(t *testing.T) {
	tests := []struct {
		scope    DataPermScope
		expected uint8
	}{
		{DataPermAll, 1},
		{DataPermCustomDept, 2},
		{DataPermOwnDeptAndSub, 3},
		{DataPermOwnDept, 4},
		{DataPermOwn, 5},
	}

	for _, test := range tests {
		result := test.scope.Value()
		if result != test.expected {
			t.Errorf("DataPermScope(%d).Value() = %d; expected %d", test.scope, result, test.expected)
		}
	}
}

func TestDataPermScopeFromValue(t *testing.T) {
	tests := []struct {
		value    uint8
		expected DataPermScope
	}{
		{1, DataPermAll},
		{2, DataPermCustomDept},
		{3, DataPermOwnDeptAndSub},
		{4, DataPermOwnDept},
		{5, DataPermOwn},
		{99, DataPermOwn}, // Invalid value should return DataPermOwn
	}

	for _, test := range tests {
		result := DataPermScopeFromValue(test.value)
		if result != test.expected {
			t.Errorf("DataPermScopeFromValue(%d) = %d; expected %d", test.value, result, test.expected)
		}
	}
}

func TestDataPermScope_IsValid(t *testing.T) {
	tests := []struct {
		scope    DataPermScope
		expected bool
	}{
		{DataPermAll, true},
		{DataPermCustomDept, true},
		{DataPermOwnDeptAndSub, true},
		{DataPermOwnDept, true},
		{DataPermOwn, true},
		{DataPermScope(0), false},
		{DataPermScope(6), false},
		{DataPermScope(99), false},
	}

	for _, test := range tests {
		result := test.scope.IsValid()
		if result != test.expected {
			t.Errorf("DataPermScope(%d).IsValid() = %v; expected %v", test.scope, result, test.expected)
		}
	}
}

func TestNewConstantManager(t *testing.T) {
	cm := NewConstantManager()

	if cm == nil {
		t.Error("NewConstantManager() should not return nil")
	}

	if cm.constants == nil {
		t.Error("ConstantManager.constants should be initialized")
	}
}

func TestConstantManager_SetAndGetConstant(t *testing.T) {
	cm := NewConstantManager()

	// Test setting and getting string
	cm.SetConstant("test.string", "test_value")
	value, exists := cm.GetConstant("test.string")
	if !exists {
		t.Error("Constant should exist after setting")
	}
	if value != "test_value" {
		t.Errorf("Expected 'test_value', got %v", value)
	}

	// Test setting and getting uint64
	cm.SetConstant("test.uint64", uint64(123))
	value, exists = cm.GetConstant("test.uint64")
	if !exists {
		t.Error("Constant should exist after setting")
	}
	if value != uint64(123) {
		t.Errorf("Expected uint64(123), got %v", value)
	}

	// Test getting non-existent constant
	_, exists = cm.GetConstant("non.existent")
	if exists {
		t.Error("Non-existent constant should not exist")
	}
}

func TestConstantManager_GetString(t *testing.T) {
	cm := NewConstantManager()

	// Test getting string constant
	cm.SetConstant("test.string", "hello")
	str, err := cm.GetString("test.string")
	if err != nil {
		t.Errorf("GetString should not return error for string constant, got: %v", err)
	}
	if str != "hello" {
		t.Errorf("Expected 'hello', got %s", str)
	}

	// Test getting non-string constant
	cm.SetConstant("test.number", 123)
	_, err = cm.GetString("test.number")
	if err == nil {
		t.Error("GetString should return error for non-string constant")
	}

	// Test getting non-existent constant
	_, err = cm.GetString("non.existent")
	if err == nil {
		t.Error("GetString should return error for non-existent constant")
	}
}

func TestConstantManager_GetUint64(t *testing.T) {
	cm := NewConstantManager()

	tests := []struct {
		key      string
		value    interface{}
		expected uint64
		hasError bool
	}{
		{"test.uint64", uint64(123), 123, false},
		{"test.int", int(456), 456, false},
		{"test.int64", int64(789), 789, false},
		{"test.string", "not_a_number", 0, true},
		{"test.bool", true, 0, true},
	}

	for _, test := range tests {
		cm.SetConstant(test.key, test.value)
		result, err := cm.GetUint64(test.key)

		if test.hasError {
			if err == nil {
				t.Errorf("GetUint64(%s) should return error", test.key)
			}
		} else {
			if err != nil {
				t.Errorf("GetUint64(%s) should not return error, got: %v", test.key, err)
			}
			if result != test.expected {
				t.Errorf("GetUint64(%s) = %d; expected %d", test.key, result, test.expected)
			}
		}
	}

	// Test getting non-existent constant
	_, err := cm.GetUint64("non.existent")
	if err == nil {
		t.Error("GetUint64 should return error for non-existent constant")
	}
}

func TestConstantManager_GetUint8(t *testing.T) {
	cm := NewConstantManager()

	tests := []struct {
		key      string
		value    interface{}
		expected uint8
		hasError bool
	}{
		{"test.uint8", uint8(123), 123, false},
		{"test.int", int(45), 45, false},
		{"test.int64", int64(67), 67, false},
		{"test.uint64", uint64(89), 89, false},
		{"test.string", "not_a_number", 0, true},
		{"test.bool", false, 0, true},
	}

	for _, test := range tests {
		cm.SetConstant(test.key, test.value)
		result, err := cm.GetUint8(test.key)

		if test.hasError {
			if err == nil {
				t.Errorf("GetUint8(%s) should return error", test.key)
			}
		} else {
			if err != nil {
				t.Errorf("GetUint8(%s) should not return error, got: %v", test.key, err)
			}
			if result != test.expected {
				t.Errorf("GetUint8(%s) = %d; expected %d", test.key, result, test.expected)
			}
		}
	}

	// Test getting non-existent constant
	_, err := cm.GetUint8("non.existent")
	if err == nil {
		t.Error("GetUint8 should return error for non-existent constant")
	}
}

func TestConstantManager_Initialize(t *testing.T) {
	cm := NewConstantManager()
	cm.Initialize()

	// Test default tenant ID
	tenantID, err := cm.GetUint64("tenant.default_id")
	if err != nil {
		t.Errorf("Initialize should set tenant.default_id, got error: %v", err)
	}
	if tenantID != 1 {
		t.Errorf("Expected default tenant ID 1, got %d", tenantID)
	}

	// Test data permission constants
	dataPermTests := []struct {
		key      string
		expected uint8
	}{
		{"data_perm.all", uint8(DataPermAll)},
		{"data_perm.custom_dept", uint8(DataPermCustomDept)},
		{"data_perm.own_dept_and_sub", uint8(DataPermOwnDeptAndSub)},
		{"data_perm.own_dept", uint8(DataPermOwnDept)},
		{"data_perm.own", uint8(DataPermOwn)},
	}

	for _, test := range dataPermTests {
		value, err := cm.GetUint8(test.key)
		if err != nil {
			t.Errorf("Initialize should set %s, got error: %v", test.key, err)
		}
		if value != test.expected {
			t.Errorf("Expected %s = %d, got %d", test.key, test.expected, value)
		}
	}
}

func TestGetDefaultConstantManager(t *testing.T) {
	cm := GetDefaultConstantManager()

	if cm == nil {
		t.Error("GetDefaultConstantManager() should not return nil")
	}

	// Test that default constants are initialized
	tenantID, err := cm.GetUint64("tenant.default_id")
	if err != nil {
		t.Error("Default constant manager should have tenant.default_id initialized")
	}
	if tenantID != 1 {
		t.Errorf("Expected default tenant ID 1, got %d", tenantID)
	}
}

func TestGlobalConvenienceFunctions(t *testing.T) {
	// Test GetConstant
	value, exists := GetConstant("tenant.default_id")
	if !exists {
		t.Error("GetConstant should find tenant.default_id")
	}
	if value != uint64(1) {
		t.Errorf("Expected tenant.default_id = 1, got %v", value)
	}

	// Test GetUint64Constant
	tenantID, err := GetUint64Constant("tenant.default_id")
	if err != nil {
		t.Errorf("GetUint64Constant should not return error, got: %v", err)
	}
	if tenantID != 1 {
		t.Errorf("Expected tenant ID 1, got %d", tenantID)
	}

	// Test GetUint8Constant
	scope, err := GetUint8Constant("data_perm.all")
	if err != nil {
		t.Errorf("GetUint8Constant should not return error, got: %v", err)
	}
	if scope != uint8(DataPermAll) {
		t.Errorf("Expected data_perm.all = %d, got %d", uint8(DataPermAll), scope)
	}

	// Test non-existent constant
	_, err = GetStringConstant("non.existent")
	if err == nil {
		t.Error("GetStringConstant should return error for non-existent constant")
	}
}

func TestStateKeyGenerator(t *testing.T) {
	// Test NewStateKeyGenerator
	gen := NewStateKeyGenerator("test")
	if gen == nil {
		t.Error("NewStateKeyGenerator should not return nil")
	}
	if gen.prefix != "test" {
		t.Errorf("Expected prefix 'test', got %s", gen.prefix)
	}

	// Test GenerateKey
	key := gen.GenerateKey("part1", "part2", "part3")
	expected := "test:part1:part2:part3"
	if key != expected {
		t.Errorf("GenerateKey result = %s; expected %s", key, expected)
	}

	// Test GenerateUserKey
	userKey := gen.GenerateUserKey("user123", "profile")
	expected = "test:user:user123:profile"
	if userKey != expected {
		t.Errorf("GenerateUserKey result = %s; expected %s", userKey, expected)
	}

	// Test GenerateTenantKey
	tenantKey := gen.GenerateTenantKey("tenant456", "config")
	expected = "test:tenant:tenant456:config"
	if tenantKey != expected {
		t.Errorf("GenerateTenantKey result = %s; expected %s", tenantKey, expected)
	}

	// Test GenerateDeptKey
	deptKey := gen.GenerateDeptKey("dept789", "members")
	expected = "test:dept:dept789:members"
	if deptKey != expected {
		t.Errorf("GenerateDeptKey result = %s; expected %s", deptKey, expected)
	}
}

func TestStateKeyGenerator_EmptyParts(t *testing.T) {
	gen := NewStateKeyGenerator("test")

	// Test with no parts
	key := gen.GenerateKey()
	expected := "test"
	if key != expected {
		t.Errorf("GenerateKey with no parts = %s; expected %s", key, expected)
	}

	// Test with empty strings
	key = gen.GenerateKey("", "part", "")
	expected = "test::part:"
	if key != expected {
		t.Errorf("GenerateKey with empty parts = %s; expected %s", key, expected)
	}
}

func TestStateKeyConstants(t *testing.T) {
	tests := []struct {
		key      StateKey
		expected string
	}{
		{DataPermScopeKey, "data_perm:scope"},
		{CustomDeptKey, "data_perm:custom_dept"},
		{SubDeptKey, "data_perm:sub_dept"},
		{UserDeptKey, "user:dept"},
		{DefaultTenantKey, "tenant:default"},
		{ActiveTenantKey, "tenant:active"},
		{TenantConfigKey, "tenant:config"},
	}

	for _, test := range tests {
		if string(test.key) != test.expected {
			t.Errorf("StateKey %v = %s; expected %s", test.key, string(test.key), test.expected)
		}
	}
}
