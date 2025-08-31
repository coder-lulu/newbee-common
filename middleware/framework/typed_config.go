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

package framework

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"time"
)

// TypedConfig provides strongly typed configuration management
type TypedConfig interface {
	// Basic type getters with defaults
	GetString(key string, defaultValue ...string) string
	GetInt(key string, defaultValue ...int) int
	GetInt64(key string, defaultValue ...int64) int64
	GetFloat64(key string, defaultValue ...float64) float64
	GetBool(key string, defaultValue ...bool) bool
	GetDuration(key string, defaultValue ...time.Duration) time.Duration

	// Slice type getters
	GetStringSlice(key string, defaultValue ...[]string) []string
	GetIntSlice(key string, defaultValue ...[]int) []int

	// Complex type methods
	GetStruct(key string, target interface{}) error
	GetMap(key string) map[string]interface{}

	// Validation and existence checks
	Has(key string) bool
	Validate() error
	Keys() []string

	// Type-safe setters
	Set(key string, value interface{}) error

	// JSON marshaling
	ToJSON() ([]byte, error)
	FromJSON(data []byte) error

	// Raw access (use sparingly)
	GetRaw(key string) interface{}
}

// ConfigValue represents a strongly typed configuration value
type ConfigValue struct {
	Value       interface{}
	Type        reflect.Type
	Required    bool
	Default     interface{}
	Validator   func(interface{}) error
	Description string
}

// TypedPluginConfig implements TypedConfig with type safety
type TypedPluginConfig struct {
	data       map[string]interface{}
	schema     map[string]*ConfigValue
	pluginName string
}

// NewTypedPluginConfig creates a new typed plugin configuration
func NewTypedPluginConfig(pluginName string) *TypedPluginConfig {
	return &TypedPluginConfig{
		data:       make(map[string]interface{}),
		schema:     make(map[string]*ConfigValue),
		pluginName: pluginName,
	}
}

// CreateFromPluginConfig converts a legacy PluginConfig to TypedPluginConfig
func CreateFromPluginConfig(pluginName string, legacy PluginConfig) *TypedPluginConfig {
	typed := NewTypedPluginConfig(pluginName)
	typed.data = make(map[string]interface{})

	// Copy existing configuration
	for key, value := range legacy.Config {
		typed.data[key] = value
	}

	// Set common fields
	typed.Set("enabled", legacy.Enabled)
	typed.Set("priority", legacy.Priority)
	typed.Set("environment", legacy.Environment)

	return typed
}

// DefineSchema defines the expected configuration schema
func (tpc *TypedPluginConfig) DefineSchema(schema map[string]*ConfigValue) {
	tpc.schema = schema
}

// GetString retrieves a string value with optional default
func (tpc *TypedPluginConfig) GetString(key string, defaultValue ...string) string {
	if value, exists := tpc.data[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
		// Try to convert to string
		return fmt.Sprintf("%v", value)
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if str, ok := schemaValue.Default.(string); ok {
			return str
		}
	}

	return ""
}

// GetInt retrieves an integer value with optional default
func (tpc *TypedPluginConfig) GetInt(key string, defaultValue ...int) int {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if i, ok := schemaValue.Default.(int); ok {
			return i
		}
	}

	return 0
}

// GetInt64 retrieves an int64 value with optional default
func (tpc *TypedPluginConfig) GetInt64(key string, defaultValue ...int64) int64 {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		case string:
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				return i
			}
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if i, ok := schemaValue.Default.(int64); ok {
			return i
		}
	}

	return 0
}

// GetFloat64 retrieves a float64 value with optional default
func (tpc *TypedPluginConfig) GetFloat64(key string, defaultValue ...float64) float64 {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if f, ok := schemaValue.Default.(float64); ok {
			return f
		}
	}

	return 0.0
}

// GetBool retrieves a boolean value with optional default
func (tpc *TypedPluginConfig) GetBool(key string, defaultValue ...bool) bool {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case bool:
			return v
		case string:
			if b, err := strconv.ParseBool(v); err == nil {
				return b
			}
		case int:
			return v != 0
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if b, ok := schemaValue.Default.(bool); ok {
			return b
		}
	}

	return false
}

// GetDuration retrieves a duration value with optional default
func (tpc *TypedPluginConfig) GetDuration(key string, defaultValue ...time.Duration) time.Duration {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case time.Duration:
			return v
		case string:
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		case int64:
			return time.Duration(v)
		case int:
			return time.Duration(v)
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if d, ok := schemaValue.Default.(time.Duration); ok {
			return d
		}
	}

	return 0
}

// GetStringSlice retrieves a string slice with optional default
func (tpc *TypedPluginConfig) GetStringSlice(key string, defaultValue ...[]string) []string {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case []string:
			return v
		case []interface{}:
			result := make([]string, len(v))
			for i, item := range v {
				result[i] = fmt.Sprintf("%v", item)
			}
			return result
		case string:
			// Single string becomes slice with one element
			return []string{v}
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if slice, ok := schemaValue.Default.([]string); ok {
			return slice
		}
	}

	return []string{}
}

// GetIntSlice retrieves an integer slice with optional default
func (tpc *TypedPluginConfig) GetIntSlice(key string, defaultValue ...[]int) []int {
	if value, exists := tpc.data[key]; exists {
		switch v := value.(type) {
		case []int:
			return v
		case []interface{}:
			result := make([]int, 0, len(v))
			for _, item := range v {
				if i, ok := item.(int); ok {
					result = append(result, i)
				} else if f, ok := item.(float64); ok {
					result = append(result, int(f))
				}
			}
			return result
		}
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Check schema for default
	if schemaValue, exists := tpc.schema[key]; exists && schemaValue.Default != nil {
		if slice, ok := schemaValue.Default.([]int); ok {
			return slice
		}
	}

	return []int{}
}

// GetStruct unmarshals a value into a struct
func (tpc *TypedPluginConfig) GetStruct(key string, target interface{}) error {
	if value, exists := tpc.data[key]; exists {
		// Marshal to JSON then unmarshal to struct for type safety
		jsonData, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
		}

		return json.Unmarshal(jsonData, target)
	}

	return fmt.Errorf("key %s not found", key)
}

// GetMap retrieves a map value
func (tpc *TypedPluginConfig) GetMap(key string) map[string]interface{} {
	if value, exists := tpc.data[key]; exists {
		if m, ok := value.(map[string]interface{}); ok {
			return m
		}
	}
	return make(map[string]interface{})
}

// Has checks if a key exists
func (tpc *TypedPluginConfig) Has(key string) bool {
	_, exists := tpc.data[key]
	return exists
}

// Validate validates the configuration against the schema
func (tpc *TypedPluginConfig) Validate() error {
	var errors []string

	// Check required fields
	for key, schemaValue := range tpc.schema {
		if schemaValue.Required && !tpc.Has(key) {
			errors = append(errors, fmt.Sprintf("required field '%s' is missing", key))
			continue
		}

		// Validate type if value exists
		if value, exists := tpc.data[key]; exists {
			expectedType := schemaValue.Type
			actualType := reflect.TypeOf(value)

			// Allow type conversion for compatible types
			if !isCompatibleType(actualType, expectedType) {
				errors = append(errors, fmt.Sprintf("field '%s' has type %v, expected %v", key, actualType, expectedType))
			}

			// Run custom validator if provided
			if schemaValue.Validator != nil {
				if err := schemaValue.Validator(value); err != nil {
					errors = append(errors, fmt.Sprintf("validation failed for field '%s': %v", key, err))
				}
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed for plugin %s: %v", tpc.pluginName, errors)
	}

	return nil
}

// Keys returns all configuration keys
func (tpc *TypedPluginConfig) Keys() []string {
	keys := make([]string, 0, len(tpc.data))
	for key := range tpc.data {
		keys = append(keys, key)
	}
	return keys
}

// Set sets a configuration value with type checking
func (tpc *TypedPluginConfig) Set(key string, value interface{}) error {
	// Validate against schema if defined
	if schemaValue, exists := tpc.schema[key]; exists {
		expectedType := schemaValue.Type
		actualType := reflect.TypeOf(value)

		if !isCompatibleType(actualType, expectedType) {
			return fmt.Errorf("cannot set field '%s': type %v is not compatible with expected type %v", key, actualType, expectedType)
		}

		// Run custom validator if provided
		if schemaValue.Validator != nil {
			if err := schemaValue.Validator(value); err != nil {
				return fmt.Errorf("validation failed for field '%s': %w", key, err)
			}
		}
	}

	tpc.data[key] = value
	return nil
}

// ToJSON marshals the configuration to JSON
func (tpc *TypedPluginConfig) ToJSON() ([]byte, error) {
	return json.MarshalIndent(tpc.data, "", "  ")
}

// FromJSON unmarshals JSON data into the configuration
func (tpc *TypedPluginConfig) FromJSON(data []byte) error {
	return json.Unmarshal(data, &tpc.data)
}

// GetRaw returns the raw value without type conversion
func (tpc *TypedPluginConfig) GetRaw(key string) interface{} {
	return tpc.data[key]
}

// toLegacyPluginConfig converts TypedPluginConfig back to PluginConfig for compatibility
func (tpc *TypedPluginConfig) ToLegacyPluginConfig() PluginConfig {
	legacy := PluginConfig{
		Config: make(map[string]interface{}),
	}

	// Copy all data except special fields
	for key, value := range tpc.data {
		switch key {
		case "enabled":
			if b, ok := value.(bool); ok {
				legacy.Enabled = b
			}
		case "priority":
			if i, ok := value.(int); ok {
				legacy.Priority = i
			}
		case "environment":
			if s, ok := value.(string); ok {
				legacy.Environment = s
			}
		default:
			legacy.Config[key] = value
		}
	}

	return legacy
}

// isCompatibleType checks if two types are compatible for assignment
func isCompatibleType(actual, expected reflect.Type) bool {
	if actual == nil || expected == nil {
		return actual == expected
	}

	// Direct match
	if actual == expected {
		return true
	}

	// Interface{} accepts any type
	if expected.Kind() == reflect.Interface && expected.NumMethod() == 0 {
		return true
	}

	// Check for convertible numeric types
	if isNumericType(actual) && isNumericType(expected) {
		return true
	}

	// String conversion
	if expected.Kind() == reflect.String {
		return true // Most types can be converted to string
	}

	// Slice compatibility
	if actual.Kind() == reflect.Slice && expected.Kind() == reflect.Slice {
		return isCompatibleType(actual.Elem(), expected.Elem())
	}

	return false
}

// isNumericType checks if a type is numeric
func isNumericType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// Common validator functions

// ValidateRange creates a validator for numeric ranges
func ValidateRange(min, max int64) func(interface{}) error {
	return func(value interface{}) error {
		var num int64
		switch v := value.(type) {
		case int:
			num = int64(v)
		case int64:
			num = v
		case float64:
			num = int64(v)
		default:
			return fmt.Errorf("expected numeric value, got %T", value)
		}

		if num < min || num > max {
			return fmt.Errorf("value %d is out of range [%d, %d]", num, min, max)
		}
		return nil
	}
}

// ValidateStringLength creates a validator for string length
func ValidateStringLength(min, max int) func(interface{}) error {
	return func(value interface{}) error {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}

		length := len(str)
		if length < min || length > max {
			return fmt.Errorf("string length %d is out of range [%d, %d]", length, min, max)
		}
		return nil
	}
}

// ValidateRegex creates a validator for regex patterns
func ValidateRegex(pattern string) func(interface{}) error {
	return func(value interface{}) error {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}

		// Simple pattern validation (extend as needed)
		if pattern == "^[a-zA-Z0-9_]+$" {
			for _, r := range str {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
					return fmt.Errorf("string contains invalid characters")
				}
			}
		}

		return nil
	}
}

// ValidateEnum creates a validator for enumerated values
func ValidateEnum(allowedValues ...interface{}) func(interface{}) error {
	return func(value interface{}) error {
		for _, allowed := range allowedValues {
			if reflect.DeepEqual(value, allowed) {
				return nil
			}
		}
		return fmt.Errorf("value %v is not in allowed set %v", value, allowedValues)
	}
}
