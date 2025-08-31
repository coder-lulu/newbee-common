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
	"strings"
	"testing"
)

func TestNewStandardUnifiedConfigValidator(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	if validator == nil {
		t.Error("NewStandardUnifiedConfigValidator should not return nil")
	}

	if validator.rules == nil {
		t.Error("Validator rules should be initialized")
	}
}

func TestStandardUnifiedConfigValidator_AddRule(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	rule := ValidationRule{
		Key:      "test.key",
		Required: true,
		Type:     "string",
	}

	validator.AddRule(rule)

	if len(validator.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(validator.rules))
	}

	if validator.rules[0].Key != "test.key" {
		t.Errorf("Expected key 'test.key', got %s", validator.rules[0].Key)
	}
}

func TestStandardUnifiedConfigValidator_Validate_Required(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Add required rule
	validator.AddRule(ValidationRule{
		Key:      "required.test",
		Required: true,
		Type:     "string",
	})

	// Test missing required value
	err := validator.Validate("required.test", nil)
	if err == nil {
		t.Error("Validation should fail for missing required value")
	}

	// Test present required value
	err = validator.Validate("required.test", "valid_value")
	if err != nil {
		t.Errorf("Validation should pass for present required value, got: %v", err)
	}
}

func TestStandardUnifiedConfigValidator_Validate_Types(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	testCases := []struct {
		name         string
		rule         ValidationRule
		validValue   interface{}
		invalidValue interface{}
	}{
		{
			name:         "string type",
			rule:         ValidationRule{Key: "string.test", Type: "string"},
			validValue:   "valid_string",
			invalidValue: 123,
		},
		{
			name:         "int type",
			rule:         ValidationRule{Key: "int.test", Type: "int"},
			validValue:   42,
			invalidValue: "not_a_number",
		},
		{
			name:         "float type",
			rule:         ValidationRule{Key: "float.test", Type: "float"},
			validValue:   3.14,
			invalidValue: "not_a_float",
		},
		{
			name:         "bool type",
			rule:         ValidationRule{Key: "bool.test", Type: "bool"},
			validValue:   true,
			invalidValue: "not_a_bool",
		},
		{
			name:         "duration type",
			rule:         ValidationRule{Key: "duration.test", Type: "duration"},
			validValue:   "5s",
			invalidValue: "invalid_duration",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator.AddRule(tc.rule)

			// Test valid value
			err := validator.Validate(tc.rule.Key, tc.validValue)
			if err != nil {
				t.Errorf("Validation should pass for valid %s value, got: %v", tc.rule.Type, err)
			}

			// Test invalid value
			err = validator.Validate(tc.rule.Key, tc.invalidValue)
			if err == nil {
				t.Errorf("Validation should fail for invalid %s value", tc.rule.Type)
			}
		})
	}
}

func TestStandardUnifiedConfigValidator_Validate_StringConstraints(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Test min/max length
	validator.AddRule(ValidationRule{
		Key:  "string.length",
		Type: "string",
		Min:  3,
		Max:  10,
	})

	// Valid length
	err := validator.Validate("string.length", "hello")
	if err != nil {
		t.Errorf("Validation should pass for valid string length, got: %v", err)
	}

	// Too short
	err = validator.Validate("string.length", "hi")
	if err == nil {
		t.Error("Validation should fail for string too short")
	}

	// Too long
	err = validator.Validate("string.length", "this_string_is_too_long")
	if err == nil {
		t.Error("Validation should fail for string too long")
	}
}

func TestStandardUnifiedConfigValidator_Validate_NumericConstraints(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Test int constraints
	validator.AddRule(ValidationRule{
		Key:  "int.range",
		Type: "int",
		Min:  10,
		Max:  100,
	})

	// Valid range
	err := validator.Validate("int.range", 50)
	if err != nil {
		t.Errorf("Validation should pass for valid int range, got: %v", err)
	}

	// Too small
	err = validator.Validate("int.range", 5)
	if err == nil {
		t.Error("Validation should fail for int too small")
	}

	// Too large
	err = validator.Validate("int.range", 150)
	if err == nil {
		t.Error("Validation should fail for int too large")
	}

	// Test float constraints
	validator.AddRule(ValidationRule{
		Key:  "float.range",
		Type: "float",
		Min:  1.5,
		Max:  10.5,
	})

	// Valid range
	err = validator.Validate("float.range", 5.5)
	if err != nil {
		t.Errorf("Validation should pass for valid float range, got: %v", err)
	}

	// Too small
	err = validator.Validate("float.range", 1.0)
	if err == nil {
		t.Error("Validation should fail for float too small")
	}

	// Too large
	err = validator.Validate("float.range", 11.0)
	if err == nil {
		t.Error("Validation should fail for float too large")
	}
}

func TestStandardUnifiedConfigValidator_Validate_Pattern(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Email pattern rule
	validator.AddRule(ValidationRule{
		Key:     "email.test",
		Type:    "string",
		Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
	})

	// Valid email
	err := validator.Validate("email.test", "test@example.com")
	if err != nil {
		t.Errorf("Validation should pass for valid email, got: %v", err)
	}

	// Invalid email
	err = validator.Validate("email.test", "invalid_email")
	if err == nil {
		t.Error("Validation should fail for invalid email pattern")
	}
}

func TestStandardUnifiedConfigValidator_Validate_Options(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Options rule
	validator.AddRule(ValidationRule{
		Key:     "options.test",
		Type:    "string",
		Options: []interface{}{"option1", "option2", "option3"},
	})

	// Valid option
	err := validator.Validate("options.test", "option2")
	if err != nil {
		t.Errorf("Validation should pass for valid option, got: %v", err)
	}

	// Invalid option
	err = validator.Validate("options.test", "invalid_option")
	if err == nil {
		t.Error("Validation should fail for invalid option")
	}
}

func TestStandardUnifiedConfigValidator_Validate_CustomRule(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Custom validation rule
	customRule := func(value interface{}) error {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("value must be string")
		}
		if len(str) < 5 {
			return fmt.Errorf("value must be at least 5 characters")
		}
		if !strings.Contains(str, "test") {
			return fmt.Errorf("value must contain 'test'")
		}
		return nil
	}

	validator.AddRule(ValidationRule{
		Key:    "custom.test",
		Type:   "string",
		Custom: customRule,
	})

	// Valid custom value
	err := validator.Validate("custom.test", "test_value")
	if err != nil {
		t.Errorf("Validation should pass for valid custom value, got: %v", err)
	}

	// Invalid custom value (too short)
	err = validator.Validate("custom.test", "test")
	if err == nil {
		t.Error("Validation should fail for custom rule violation (too short)")
	}

	// Invalid custom value (missing 'test')
	err = validator.Validate("custom.test", "invalid_value")
	if err == nil {
		t.Error("Validation should fail for custom rule violation (missing 'test')")
	}
}

func TestStandardUnifiedConfigValidator_Validate_NoMatchingRule(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Add a rule for a different key
	validator.AddRule(ValidationRule{
		Key:  "other.key",
		Type: "string",
	})

	// Validate key with no matching rule (should pass)
	err := validator.Validate("unmatched.key", "any_value")
	if err != nil {
		t.Errorf("Validation should pass for key with no matching rule, got: %v", err)
	}
}

func TestStandardUnifiedConfigValidator_ValidateConfig(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Add multiple rules
	validator.AddRule(ValidationRule{
		Key:      "required.string",
		Required: true,
		Type:     "string",
		Min:      3,
	})

	validator.AddRule(ValidationRule{
		Key:  "optional.int",
		Type: "int",
		Min:  0,
		Max:  100,
	})

	// Test valid configuration by validating individual keys
	err := validator.Validate("required.string", "valid_string")
	if err != nil {
		t.Errorf("Validate should pass for valid string, got: %v", err)
	}

	err = validator.Validate("optional.int", 50)
	if err != nil {
		t.Errorf("Validate should pass for valid int, got: %v", err)
	}

	// Test missing required field
	err = validator.Validate("required.string", nil)
	if err == nil {
		t.Error("Validate should fail for missing required field")
	}

	// Test invalid value
	err = validator.Validate("optional.int", 150) // exceeds max
	if err == nil {
		t.Error("Validate should fail for invalid value")
	}
}

func TestStandardUnifiedConfigValidator_MultipleRules(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Add multiple rules
	validator.AddRule(ValidationRule{Key: "rule1", Type: "string"})
	validator.AddRule(ValidationRule{Key: "rule2", Type: "int"})
	validator.AddRule(ValidationRule{Key: "rule3", Type: "bool"})

	// Test that all rules work
	err := validator.Validate("rule1", "test_string")
	if err != nil {
		t.Errorf("rule1 validation should pass, got: %v", err)
	}

	err = validator.Validate("rule2", 42)
	if err != nil {
		t.Errorf("rule2 validation should pass, got: %v", err)
	}

	err = validator.Validate("rule3", true)
	if err != nil {
		t.Errorf("rule3 validation should pass, got: %v", err)
	}

	// Test invalid types
	err = validator.Validate("rule1", 123) // should be string
	if err == nil {
		t.Error("rule1 should fail for non-string value")
	}
}

func TestStandardUnifiedConfigValidator_BasicValidation(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Test validation without any rules (should pass)
	err := validator.Validate("any.key", "any_value")
	if err != nil {
		t.Errorf("Validation without rules should pass, got: %v", err)
	}

	// Add some rules
	rule1 := ValidationRule{Key: "rule1", Type: "string"}
	rule2 := ValidationRule{Key: "rule2", Type: "int"}

	validator.AddRule(rule1)
	validator.AddRule(rule2)

	// Test validation with rules
	err = validator.Validate("rule1", "valid_string")
	if err != nil {
		t.Errorf("Valid string should pass validation, got: %v", err)
	}

	err = validator.Validate("rule2", 42)
	if err != nil {
		t.Errorf("Valid int should pass validation, got: %v", err)
	}

	// Test invalid validation
	err = validator.Validate("rule1", 123) // wrong type
	if err == nil {
		t.Error("Invalid type should fail validation")
	}
}

func TestStandardUnifiedConfigValidator_RuleManagement(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	// Add some rules
	validator.AddRule(ValidationRule{Key: "rule1", Type: "string"})
	validator.AddRule(ValidationRule{Key: "rule2", Type: "int"})

	// Test that rules work after adding
	err := validator.Validate("rule1", "test")
	if err != nil {
		t.Errorf("rule1 should validate successfully, got: %v", err)
	}

	err = validator.Validate("rule2", 42)
	if err != nil {
		t.Errorf("rule2 should validate successfully, got: %v", err)
	}

	// Note: ClearRules method doesn't exist, so we test basic functionality
}

func TestStandardUnifiedConfigValidator_EdgeCases(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	t.Run("NilValue", func(t *testing.T) {
		validator.AddRule(ValidationRule{
			Key:      "nil.test",
			Required: false,
			Type:     "string",
		})

		// Nil value for non-required field should pass
		err := validator.Validate("nil.test", nil)
		if err != nil {
			t.Errorf("Validation should pass for nil non-required value, got: %v", err)
		}
	})

	t.Run("EmptyStringType", func(t *testing.T) {
		validator.AddRule(ValidationRule{
			Key: "empty_type.test",
			// Type is empty - should skip type validation
		})

		err := validator.Validate("empty_type.test", "any_value")
		if err != nil {
			t.Errorf("Validation should pass when type is not specified, got: %v", err)
		}
	})

	t.Run("InvalidRegexPattern", func(t *testing.T) {
		validator.AddRule(ValidationRule{
			Key:     "invalid_regex.test",
			Type:    "string",
			Pattern: "[invalid_regex",
		})

		// Should handle invalid regex gracefully
		err := validator.Validate("invalid_regex.test", "test_value")
		if err == nil {
			t.Error("Validation should fail for invalid regex pattern")
		}
	})

	t.Run("TypeMismatchInConstraints", func(t *testing.T) {
		validator.AddRule(ValidationRule{
			Key:  "type_mismatch.test",
			Type: "string",
			Min:  "not_a_number", // Wrong type for min constraint
		})

		// Should handle type mismatch in constraints gracefully
		_ = validator.Validate("type_mismatch.test", "test_value")
		// Error handling depends on implementation
		// The test should not panic
	})

	t.Run("InterfaceSliceOptions", func(t *testing.T) {
		validator.AddRule(ValidationRule{
			Key:     "mixed_options.test",
			Options: []interface{}{"string", 42, true, 3.14},
		})

		// Test different types in options
		testValues := []interface{}{"string", 42, true, 3.14}
		for _, value := range testValues {
			err := validator.Validate("mixed_options.test", value)
			if err != nil {
				t.Errorf("Validation should pass for valid option %v, got: %v", value, err)
			}
		}

		// Test invalid option
		err := validator.Validate("mixed_options.test", "invalid")
		if err == nil {
			t.Error("Validation should fail for invalid option")
		}
	})
}

func TestValidationRule_ComplexScenarios(t *testing.T) {
	validator := NewStandardUnifiedConfigValidator()

	t.Run("CombinedConstraints", func(t *testing.T) {
		// Rule with multiple constraints
		validator.AddRule(ValidationRule{
			Key:     "complex.test",
			Type:    "string",
			Min:     5,
			Max:     20,
			Pattern: `^[a-zA-Z0-9_]+$`,
			Options: []interface{}{"valid_option_1", "valid_option_2"},
		})

		// Valid value
		err := validator.Validate("complex.test", "valid_option_1")
		if err != nil {
			t.Errorf("Validation should pass for valid complex value, got: %v", err)
		}

		// Invalid - not in options
		err = validator.Validate("complex.test", "invalid_option")
		if err == nil {
			t.Error("Validation should fail for value not in options")
		}

		// Invalid - doesn't match pattern (even if right length)
		err = validator.Validate("complex.test", "invalid!")
		if err == nil {
			t.Error("Validation should fail for value not matching pattern")
		}
	})

	t.Run("RequiredWithConstraints", func(t *testing.T) {
		validator.AddRule(ValidationRule{
			Key:      "required_constrained.test",
			Required: true,
			Type:     "int",
			Min:      1,
			Max:      10,
		})

		// Missing required value
		err := validator.Validate("required_constrained.test", nil)
		if err == nil {
			t.Error("Validation should fail for missing required value")
		}

		// Invalid constraint
		err = validator.Validate("required_constrained.test", 15)
		if err == nil {
			t.Error("Validation should fail for value exceeding max constraint")
		}

		// Valid value
		err = validator.Validate("required_constrained.test", 5)
		if err != nil {
			t.Errorf("Validation should pass for valid required constrained value, got: %v", err)
		}
	})
}
