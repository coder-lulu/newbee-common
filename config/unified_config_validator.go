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
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// UnifiedConfigValidator 配置验证器接口
type UnifiedConfigValidator interface {
	Validate(key string, value interface{}) error
}

// ValidationRule 验证规则
type ValidationRule struct {
	Key      string
	Required bool
	Type     string
	Min      interface{}
	Max      interface{}
	Pattern  string
	Options  []interface{}
	Custom   func(interface{}) error
}

// StandardUnifiedConfigValidator 标准配置验证器
type StandardUnifiedConfigValidator struct {
	rules []ValidationRule
}

// NewStandardUnifiedConfigValidator 创建标准配置验证器
func NewStandardUnifiedConfigValidator() *StandardUnifiedConfigValidator {
	return &StandardUnifiedConfigValidator{
		rules: make([]ValidationRule, 0),
	}
}

// AddRule 添加验证规则
func (v *StandardUnifiedConfigValidator) AddRule(rule ValidationRule) {
	v.rules = append(v.rules, rule)
}

// Validate 验证配置值
func (v *StandardUnifiedConfigValidator) Validate(key string, value interface{}) error {
	for _, rule := range v.rules {
		if v.matchKey(rule.Key, key) {
			if err := v.validateRule(rule, value); err != nil {
				return fmt.Errorf("validation failed for key %s: %w", key, err)
			}
		}
	}
	return nil
}

// matchKey 匹配配置键
func (v *StandardUnifiedConfigValidator) matchKey(pattern, key string) bool {
	// 支持通配符匹配
	if pattern == "*" {
		return true
	}

	// 支持前缀匹配
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(key, prefix)
	}

	// 精确匹配
	return pattern == key
}

// validateRule 验证规则
func (v *StandardUnifiedConfigValidator) validateRule(rule ValidationRule, value interface{}) error {
	// 检查必需性
	if rule.Required && value == nil {
		return fmt.Errorf("required value is missing")
	}

	if value == nil {
		return nil // 非必需字段可以为空
	}

	// 类型验证
	if rule.Type != "" {
		if err := v.validateType(rule.Type, value); err != nil {
			return err
		}
	}

	// 范围验证
	if rule.Min != nil || rule.Max != nil {
		if err := v.validateRange(rule.Min, rule.Max, value); err != nil {
			return err
		}
	}

	// 模式验证
	if rule.Pattern != "" {
		if err := v.validatePattern(rule.Pattern, value); err != nil {
			return err
		}
	}

	// 选项验证
	if len(rule.Options) > 0 {
		if err := v.validateOptions(rule.Options, value); err != nil {
			return err
		}
	}

	// 自定义验证
	if rule.Custom != nil {
		if err := rule.Custom(value); err != nil {
			return err
		}
	}

	return nil
}

// validateType 类型验证
func (v *StandardUnifiedConfigValidator) validateType(expectedType string, value interface{}) error {
	actualType := v.getTypeName(value)

	switch expectedType {
	case "string":
		if actualType != "string" {
			return fmt.Errorf("expected string, got %s", actualType)
		}
	case "int", "integer":
		if !v.isIntegerType(actualType) {
			return fmt.Errorf("expected integer, got %s", actualType)
		}
	case "float", "number":
		if !v.isNumericType(actualType) {
			return fmt.Errorf("expected number, got %s", actualType)
		}
	case "bool", "boolean":
		if actualType != "bool" {
			return fmt.Errorf("expected boolean, got %s", actualType)
		}
	case "duration":
		if actualType == "string" {
			// 尝试解析为 duration
			if _, err := time.ParseDuration(value.(string)); err != nil {
				return fmt.Errorf("invalid duration format: %w", err)
			}
		} else if actualType != "time.Duration" {
			return fmt.Errorf("expected duration, got %s", actualType)
		}
	default:
		return fmt.Errorf("unsupported type: %s", expectedType)
	}

	return nil
}

// validateRange 范围验证
func (v *StandardUnifiedConfigValidator) validateRange(min, max, value interface{}) error {
	typeName := v.getTypeName(value)

	if v.isNumericType(typeName) {
		numValue := v.toFloat64(value)

		if min != nil {
			minValue := v.toFloat64(min)
			if numValue < minValue {
				return fmt.Errorf("value %v is less than minimum %v", numValue, minValue)
			}
		}

		if max != nil {
			maxValue := v.toFloat64(max)
			if numValue > maxValue {
				return fmt.Errorf("value %v is greater than maximum %v", numValue, maxValue)
			}
		}
	} else if typeName == "string" {
		strValue := value.(string)

		if min != nil {
			minLen := int(v.toFloat64(min))
			if len(strValue) < minLen {
				return fmt.Errorf("string length %d is less than minimum %d", len(strValue), minLen)
			}
		}

		if max != nil {
			maxLen := int(v.toFloat64(max))
			if len(strValue) > maxLen {
				return fmt.Errorf("string length %d is greater than maximum %d", len(strValue), maxLen)
			}
		}
	} else if typeName == "time.Duration" || v.isDurationString(value) {
		// 处理 duration 类型的范围验证
		var duration time.Duration
		var err error

		if typeName == "time.Duration" {
			duration = value.(time.Duration)
		} else {
			duration, err = time.ParseDuration(value.(string))
			if err != nil {
				return fmt.Errorf("invalid duration format: %w", err)
			}
		}

		if min != nil {
			var minDuration time.Duration
			if minStr, ok := min.(string); ok {
				minDuration, err = time.ParseDuration(minStr)
				if err != nil {
					return fmt.Errorf("invalid minimum duration format: %w", err)
				}
			} else if minDur, ok := min.(time.Duration); ok {
				minDuration = minDur
			}

			if duration < minDuration {
				return fmt.Errorf("duration %v is less than minimum %v", duration, minDuration)
			}
		}

		if max != nil {
			var maxDuration time.Duration
			if maxStr, ok := max.(string); ok {
				maxDuration, err = time.ParseDuration(maxStr)
				if err != nil {
					return fmt.Errorf("invalid maximum duration format: %w", err)
				}
			} else if maxDur, ok := max.(time.Duration); ok {
				maxDuration = maxDur
			}

			if duration > maxDuration {
				return fmt.Errorf("duration %v is greater than maximum %v", duration, maxDuration)
			}
		}
	}

	return nil
}

// validatePattern 模式验证
func (v *StandardUnifiedConfigValidator) validatePattern(pattern string, value interface{}) error {
	if v.getTypeName(value) != "string" {
		return fmt.Errorf("pattern validation only supports string values")
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern %s: %w", pattern, err)
	}

	strValue := value.(string)
	if !regex.MatchString(strValue) {
		return fmt.Errorf("value %s does not match pattern %s", strValue, pattern)
	}

	return nil
}

// validateOptions 选项验证
func (v *StandardUnifiedConfigValidator) validateOptions(options []interface{}, value interface{}) error {
	for _, option := range options {
		if v.isEqual(option, value) {
			return nil
		}
	}

	return fmt.Errorf("value %v is not in allowed options %v", value, options)
}

// 辅助方法
func (v *StandardUnifiedConfigValidator) getTypeName(value interface{}) string {
	if value == nil {
		return "nil"
	}
	return reflect.TypeOf(value).String()
}

func (v *StandardUnifiedConfigValidator) isIntegerType(typeName string) bool {
	intTypes := []string{"int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64"}
	for _, t := range intTypes {
		if typeName == t {
			return true
		}
	}
	return false
}

func (v *StandardUnifiedConfigValidator) isNumericType(typeName string) bool {
	if v.isIntegerType(typeName) {
		return true
	}
	return typeName == "float32" || typeName == "float64"
}

func (v *StandardUnifiedConfigValidator) toFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case int:
		return float64(v)
	case int8:
		return float64(v)
	case int16:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func (v *StandardUnifiedConfigValidator) isEqual(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

func (v *StandardUnifiedConfigValidator) isDurationString(value interface{}) bool {
	if str, ok := value.(string); ok {
		_, err := time.ParseDuration(str)
		return err == nil
	}
	return false
}

// 预定义验证规则
func GetCommonValidationRules() []ValidationRule {
	return []ValidationRule{
		{
			Key:      "server.port",
			Required: true,
			Type:     "int",
			Min:      1,
			Max:      65535,
		},
		{
			Key:      "server.host",
			Required: true,
			Type:     "string",
			Min:      1,
			Max:      255,
		},
		{
			Key:     "log.level",
			Type:    "string",
			Options: []interface{}{"debug", "info", "warn", "error"},
		},
		{
			Key:  "cache.ttl",
			Type: "duration",
			Min:  "1s",
			Max:  "24h",
		},
		{
			Key:     "app.environment",
			Type:    "string",
			Options: []interface{}{"development", "testing", "staging", "production"},
		},
		{
			Key:     "database.host",
			Type:    "string",
			Pattern: `^[a-zA-Z0-9\-\.]+$`,
		},
		{
			Key:  "database.port",
			Type: "int",
			Min:  1,
			Max:  65535,
		},
		{
			Key:  "database.name",
			Type: "string",
			Min:  1,
			Max:  64,
		},
	}
}

// ValidatingUnifiedConfigManager 带验证的配置管理器
type ValidatingUnifiedConfigManager struct {
	*UnifiedConfigManager
	validator UnifiedConfigValidator
}

// NewValidatingUnifiedConfigManager 创建带验证的配置管理器
func NewValidatingUnifiedConfigManager(validator UnifiedConfigValidator, options ...ConfigOption) *ValidatingUnifiedConfigManager {
	return &ValidatingUnifiedConfigManager{
		UnifiedConfigManager: NewUnifiedConfigManager(options...),
		validator:            validator,
	}
}

// Set 设置配置值（带验证）
func (vcm *ValidatingUnifiedConfigManager) Set(key string, value interface{}) error {
	if vcm.validator != nil {
		if err := vcm.validator.Validate(key, value); err != nil {
			return err
		}
	}

	vcm.UnifiedConfigManager.Set(key, value)
	return nil
}

// ValidateAll 验证所有配置
func (vcm *ValidatingUnifiedConfigManager) ValidateAll() error {
	if vcm.validator == nil {
		return nil
	}

	configs := vcm.GetAllConfigs()
	for key, value := range configs {
		if err := vcm.validator.Validate(key, value); err != nil {
			return err
		}
	}

	return nil
}
