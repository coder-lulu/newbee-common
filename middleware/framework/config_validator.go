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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// ConfigValidator provides validation for middleware configurations
type ConfigValidator struct {
	rules map[string]ValidationRule
}

// ValidationRule defines a rule for validating configuration values
type ValidationRule struct {
	Required        bool
	Type            reflect.Type
	MinValue        interface{}
	MaxValue        interface{}
	AllowedValues   []interface{}
	CustomValidator func(interface{}) error
	Description     string
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Rule    string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		rules: make(map[string]ValidationRule),
	}
}

// AddRule adds a validation rule for a specific field
func (v *ConfigValidator) AddRule(fieldPath string, rule ValidationRule) {
	v.rules[fieldPath] = rule
}

// ValidateConfig validates a configuration struct against registered rules
func (v *ConfigValidator) ValidateConfig(config interface{}) []ValidationError {
	var errors []ValidationError

	// Use reflection to traverse the config struct
	errors = append(errors, v.validateStruct(config, "")...)

	return errors
}

// validateStruct recursively validates struct fields
func (v *ConfigValidator) validateStruct(obj interface{}, prefix string) []ValidationError {
	var errors []ValidationError

	if obj == nil {
		return errors
	}

	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return errors
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return errors
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Build field path
		fieldPath := fieldType.Name
		if prefix != "" {
			fieldPath = prefix + "." + fieldPath
		}

		// Check if there's a rule for this field
		if rule, exists := v.rules[fieldPath]; exists {
			if err := v.validateField(field.Interface(), rule, fieldPath); err != nil {
				errors = append(errors, *err)
			}
		}

		// Recursively validate nested structs
		if field.Kind() == reflect.Struct || (field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.Struct) {
			errors = append(errors, v.validateStruct(field.Interface(), fieldPath)...)
		}
	}

	return errors
}

// validateField validates a single field against its rule
func (v *ConfigValidator) validateField(value interface{}, rule ValidationRule, fieldPath string) *ValidationError {
	// Check if required
	if rule.Required && v.isZeroValue(value) {
		return &ValidationError{
			Field:   fieldPath,
			Value:   value,
			Rule:    "required",
			Message: "field is required but not provided",
		}
	}

	// Skip validation if value is zero and not required
	if !rule.Required && v.isZeroValue(value) {
		return nil
	}

	// Type validation
	if rule.Type != nil {
		if !reflect.TypeOf(value).AssignableTo(rule.Type) {
			return &ValidationError{
				Field:   fieldPath,
				Value:   value,
				Rule:    "type",
				Message: fmt.Sprintf("expected type %s, got %s", rule.Type, reflect.TypeOf(value)),
			}
		}
	}

	// Min/Max value validation
	if err := v.validateRange(value, rule, fieldPath); err != nil {
		return err
	}

	// Allowed values validation
	if len(rule.AllowedValues) > 0 {
		if err := v.validateAllowedValues(value, rule, fieldPath); err != nil {
			return err
		}
	}

	// Custom validation
	if rule.CustomValidator != nil {
		if err := rule.CustomValidator(value); err != nil {
			return &ValidationError{
				Field:   fieldPath,
				Value:   value,
				Rule:    "custom",
				Message: err.Error(),
			}
		}
	}

	return nil
}

// isZeroValue checks if a value is zero/empty
func (v *ConfigValidator) isZeroValue(value interface{}) bool {
	if value == nil {
		return true
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		return val.String() == ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return val.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return val.Float() == 0
	case reflect.Bool:
		return !val.Bool()
	case reflect.Slice, reflect.Map:
		return val.Len() == 0
	case reflect.Ptr:
		return val.IsNil()
	default:
		return false
	}
}

// validateRange validates min/max values
func (v *ConfigValidator) validateRange(value interface{}, rule ValidationRule, fieldPath string) *ValidationError {
	if rule.MinValue != nil {
		if !v.compareValues(value, rule.MinValue, ">=") {
			return &ValidationError{
				Field:   fieldPath,
				Value:   value,
				Rule:    "min",
				Message: fmt.Sprintf("value must be >= %v", rule.MinValue),
			}
		}
	}

	if rule.MaxValue != nil {
		if !v.compareValues(value, rule.MaxValue, "<=") {
			return &ValidationError{
				Field:   fieldPath,
				Value:   value,
				Rule:    "max",
				Message: fmt.Sprintf("value must be <= %v", rule.MaxValue),
			}
		}
	}

	return nil
}

// validateAllowedValues validates against allowed values
func (v *ConfigValidator) validateAllowedValues(value interface{}, rule ValidationRule, fieldPath string) *ValidationError {
	for _, allowedValue := range rule.AllowedValues {
		if reflect.DeepEqual(value, allowedValue) {
			return nil
		}
	}

	return &ValidationError{
		Field:   fieldPath,
		Value:   value,
		Rule:    "allowed_values",
		Message: fmt.Sprintf("value must be one of %v", rule.AllowedValues),
	}
}

// compareValues compares two values using the specified operator
func (v *ConfigValidator) compareValues(a, b interface{}, operator string) bool {
	switch operator {
	case ">=":
		return v.greaterThanOrEqual(a, b)
	case "<=":
		return v.lessThanOrEqual(a, b)
	case ">":
		return v.greaterThan(a, b)
	case "<":
		return v.lessThan(a, b)
	default:
		return false
	}
}

// Comparison helper functions
func (v *ConfigValidator) greaterThanOrEqual(a, b interface{}) bool {
	return v.compare(a, b) >= 0
}

func (v *ConfigValidator) lessThanOrEqual(a, b interface{}) bool {
	return v.compare(a, b) <= 0
}

func (v *ConfigValidator) greaterThan(a, b interface{}) bool {
	return v.compare(a, b) > 0
}

func (v *ConfigValidator) lessThan(a, b interface{}) bool {
	return v.compare(a, b) < 0
}

func (v *ConfigValidator) compare(a, b interface{}) int {
	aVal := reflect.ValueOf(a)
	bVal := reflect.ValueOf(b)

	if aVal.Type() != bVal.Type() {
		// Try to convert
		if bVal.Type().ConvertibleTo(aVal.Type()) {
			bVal = bVal.Convert(aVal.Type())
		} else {
			return 0 // Can't compare
		}
	}

	switch aVal.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		aInt := aVal.Int()
		bInt := bVal.Int()
		if aInt < bInt {
			return -1
		} else if aInt > bInt {
			return 1
		}
		return 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		aUint := aVal.Uint()
		bUint := bVal.Uint()
		if aUint < bUint {
			return -1
		} else if aUint > bUint {
			return 1
		}
		return 0
	case reflect.Float32, reflect.Float64:
		aFloat := aVal.Float()
		bFloat := bVal.Float()
		if aFloat < bFloat {
			return -1
		} else if aFloat > bFloat {
			return 1
		}
		return 0
	case reflect.String:
		return strings.Compare(aVal.String(), bVal.String())
	default:
		return 0
	}
}

// Standard Validation Rules Factory
func CreateStandardRules() *ConfigValidator {
	validator := NewConfigValidator()

	// Base configuration rules
	validator.AddRule("Enabled", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(true),
		Description: "Whether the middleware is enabled",
	})

	validator.AddRule("LogLevel", ValidationRule{
		Required:      false,
		Type:          reflect.TypeOf(""),
		AllowedValues: []interface{}{"debug", "info", "warn", "error"},
		Description:   "Log level for the middleware",
	})

	validator.AddRule("Timeout", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(time.Duration(0)),
		MinValue:    time.Millisecond,
		MaxValue:    time.Hour,
		Description: "Maximum processing timeout",
	})

	validator.AddRule("Priority", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(0),
		MinValue:    0,
		MaxValue:    100,
		Description: "Middleware execution priority",
	})

	// Performance configuration rules
	validator.AddRule("PerformanceConfig.MaxConcurrency", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(0),
		MinValue:    1,
		MaxValue:    10000,
		Description: "Maximum concurrent requests",
	})

	validator.AddRule("PerformanceConfig.MetricsInterval", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(time.Duration(0)),
		MinValue:    time.Second,
		MaxValue:    time.Hour,
		Description: "Metrics collection interval",
	})

	// Cache configuration rules
	validator.AddRule("L1CacheConfig.MaxSize", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(0),
		MinValue:    1,
		MaxValue:    1000000,
		Description: "Maximum L1 cache size",
	})

	validator.AddRule("L1CacheConfig.DefaultTTL", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(time.Duration(0)),
		MinValue:    time.Second,
		MaxValue:    24 * time.Hour,
		Description: "Default cache TTL",
	})

	// Circuit breaker validation rules are handled in parent middleware package

	// Rate limiting rules
	validator.AddRule("RateLimitConfig.RequestsPerSecond", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(0),
		MinValue:    1,
		MaxValue:    100000,
		Description: "Requests per second limit",
	})

	validator.AddRule("RateLimitConfig.BurstSize", ValidationRule{
		Required:    false,
		Type:        reflect.TypeOf(0),
		MinValue:    1,
		MaxValue:    10000,
		Description: "Rate limiter burst size",
	})

	return validator
}

// Validation helper functions for common patterns
func ValidateURL(url string) error {
	if url == "" {
		return errors.New("URL cannot be empty")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return errors.New("URL must start with http:// or https://")
	}
	return nil
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func ValidateIPAddress(ip string) error {
	if ip == "" {
		return errors.New("IP address cannot be empty")
	}
	// Simplified IP validation - in production, use net.ParseIP
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return errors.New("invalid IP address format")
	}
	return nil
}

func ValidateSecretKey(key string) error {
	if len(key) < 16 {
		return errors.New("secret key must be at least 16 characters long")
	}
	return nil
}
