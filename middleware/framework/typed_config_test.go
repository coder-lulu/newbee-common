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
	"reflect"
	"testing"
	"time"
)

func TestTypedPluginConfig_BasicTypes(t *testing.T) {
	config := NewTypedPluginConfig("test")

	// Test string
	config.Set("str_val", "hello")
	if got := config.GetString("str_val"); got != "hello" {
		t.Errorf("GetString() = %v, want %v", got, "hello")
	}

	// Test int
	config.Set("int_val", 42)
	if got := config.GetInt("int_val"); got != 42 {
		t.Errorf("GetInt() = %v, want %v", got, 42)
	}

	// Test bool
	config.Set("bool_val", true)
	if got := config.GetBool("bool_val"); got != true {
		t.Errorf("GetBool() = %v, want %v", got, true)
	}

	// Test duration
	dur := 5 * time.Minute
	config.Set("dur_val", dur)
	if got := config.GetDuration("dur_val"); got != dur {
		t.Errorf("GetDuration() = %v, want %v", got, dur)
	}
}

func TestTypedPluginConfig_DefaultValues(t *testing.T) {
	config := NewTypedPluginConfig("test")

	// Test defaults when key doesn't exist
	if got := config.GetString("missing", "default"); got != "default" {
		t.Errorf("GetString() with default = %v, want %v", got, "default")
	}

	if got := config.GetInt("missing", 100); got != 100 {
		t.Errorf("GetInt() with default = %v, want %v", got, 100)
	}

	if got := config.GetBool("missing", true); got != true {
		t.Errorf("GetBool() with default = %v, want %v", got, true)
	}
}

func TestTypedPluginConfig_SchemaValidation(t *testing.T) {
	config := NewTypedPluginConfig("test")

	// Define schema
	schema := map[string]*ConfigValue{
		"required_field": {
			Type:     reflect.TypeOf(""),
			Required: true,
		},
		"optional_field": {
			Type:     reflect.TypeOf(0),
			Required: false,
			Default:  42,
		},
		"validated_field": {
			Type:      reflect.TypeOf(0),
			Required:  false,
			Validator: ValidateRange(1, 100),
		},
	}

	config.DefineSchema(schema)

	// Test validation failure for missing required field
	if err := config.Validate(); err == nil {
		t.Error("Validate() should fail for missing required field")
	}

	// Set required field
	config.Set("required_field", "present")

	// Test validation failure for invalid range
	err := config.Set("validated_field", 200)
	if err == nil {
		t.Error("Set() should fail for value out of range")
	}

	// Test validation success
	config.Set("validated_field", 50)
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() should succeed, got error: %v", err)
	}

	// Test default value access
	if got := config.GetInt("optional_field"); got != 42 {
		t.Errorf("GetInt() for optional field = %v, want %v", got, 42)
	}
}

func TestTypedPluginConfig_SliceTypes(t *testing.T) {
	config := NewTypedPluginConfig("test")

	// Test string slice
	strSlice := []string{"a", "b", "c"}
	config.Set("str_slice", strSlice)
	if got := config.GetStringSlice("str_slice"); !reflect.DeepEqual(got, strSlice) {
		t.Errorf("GetStringSlice() = %v, want %v", got, strSlice)
	}

	// Test int slice
	intSlice := []int{1, 2, 3}
	config.Set("int_slice", intSlice)
	if got := config.GetIntSlice("int_slice"); !reflect.DeepEqual(got, intSlice) {
		t.Errorf("GetIntSlice() = %v, want %v", got, intSlice)
	}

	// Test conversion from interface{} slice
	interfaceSlice := []interface{}{"x", "y", "z"}
	config.Set("interface_slice", interfaceSlice)
	expected := []string{"x", "y", "z"}
	if got := config.GetStringSlice("interface_slice"); !reflect.DeepEqual(got, expected) {
		t.Errorf("GetStringSlice() from interface slice = %v, want %v", got, expected)
	}
}

func TestTypedPluginConfig_JSONMarshaling(t *testing.T) {
	config := NewTypedPluginConfig("test")

	config.Set("string_val", "hello")
	config.Set("int_val", 42)
	config.Set("bool_val", true)
	config.Set("slice_val", []string{"a", "b"})

	// Test marshaling
	data, err := config.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Test unmarshaling
	newConfig := NewTypedPluginConfig("test")
	if err := newConfig.FromJSON(data); err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}

	// Verify values
	if got := newConfig.GetString("string_val"); got != "hello" {
		t.Errorf("After JSON roundtrip, GetString() = %v, want %v", got, "hello")
	}

	if got := newConfig.GetInt("int_val"); got != 42 {
		t.Errorf("After JSON roundtrip, GetInt() = %v, want %v", got, 42)
	}

	if got := newConfig.GetBool("bool_val"); got != true {
		t.Errorf("After JSON roundtrip, GetBool() = %v, want %v", got, true)
	}
}

func TestTypedPluginConfig_LegacyConversion(t *testing.T) {
	// Create a legacy config
	legacy := PluginConfig{
		Enabled:     true,
		Priority:    50,
		Environment: "test",
		Config: map[string]interface{}{
			"custom_field": "value",
			"number_field": 123,
		},
	}

	// Convert to typed config
	typed := CreateFromPluginConfig("test", legacy)

	// Verify conversion
	if got := typed.GetBool("enabled"); got != true {
		t.Errorf("Legacy conversion: GetBool(enabled) = %v, want %v", got, true)
	}

	if got := typed.GetInt("priority"); got != 50 {
		t.Errorf("Legacy conversion: GetInt(priority) = %v, want %v", got, 50)
	}

	if got := typed.GetString("environment"); got != "test" {
		t.Errorf("Legacy conversion: GetString(environment) = %v, want %v", got, "test")
	}

	if got := typed.GetString("custom_field"); got != "value" {
		t.Errorf("Legacy conversion: GetString(custom_field) = %v, want %v", got, "value")
	}

	// Convert back to legacy
	converted := typed.ToLegacyPluginConfig()

	if converted.Enabled != true {
		t.Errorf("Back conversion: Enabled = %v, want %v", converted.Enabled, true)
	}

	if converted.Priority != 50 {
		t.Errorf("Back conversion: Priority = %v, want %v", converted.Priority, 50)
	}

	if converted.Environment != "test" {
		t.Errorf("Back conversion: Environment = %v, want %v", converted.Environment, "test")
	}
}

func TestAuditPluginConfig_Creation(t *testing.T) {
	config := CreateAuditPluginConfig()

	// Test default values
	if got := config.GetBool("capture_request"); got != true {
		t.Errorf("Default capture_request = %v, want %v", got, true)
	}

	if got := config.GetBool("capture_response"); got != false {
		t.Errorf("Default capture_response = %v, want %v", got, false)
	}

	if got := config.GetInt("max_body_size"); got != 64*1024 {
		t.Errorf("Default max_body_size = %v, want %v", got, 64*1024)
	}

	expected := []string{"/health", "/metrics"}
	if got := config.GetStringSlice("skip_paths"); !reflect.DeepEqual(got, expected) {
		t.Errorf("Default skip_paths = %v, want %v", got, expected)
	}

	// Test validation
	if err := config.Validate(); err != nil {
		t.Errorf("Validation failed: %v", err)
	}
}

func TestPluginConfigFactory(t *testing.T) {
	factory := NewPluginConfigFactory()

	// Test audit config creation
	auditConfig := factory.CreateTypedConfig("audit")
	if auditConfig == nil {
		t.Fatal("CreateTypedConfig(audit) returned nil")
	}

	// Test data permission config creation
	datapermConfig := factory.CreateTypedConfig("dataperm")
	if datapermConfig == nil {
		t.Fatal("CreateTypedConfig(dataperm) returned nil")
	}

	// Test tenant config creation
	tenantConfig := factory.CreateTypedConfig("tenant")
	if tenantConfig == nil {
		t.Fatal("CreateTypedConfig(tenant) returned nil")
	}

	// Test unknown plugin type
	unknownConfig := factory.CreateTypedConfig("unknown")
	if unknownConfig == nil {
		t.Fatal("CreateTypedConfig(unknown) returned nil")
	}
}

func TestValidatorFunctions(t *testing.T) {
	// Test range validator
	rangeValidator := ValidateRange(1, 10)

	if err := rangeValidator(5); err != nil {
		t.Errorf("Range validator should accept 5: %v", err)
	}

	if err := rangeValidator(15); err == nil {
		t.Error("Range validator should reject 15")
	}

	// Test string length validator
	lengthValidator := ValidateStringLength(3, 10)

	if err := lengthValidator("hello"); err != nil {
		t.Errorf("Length validator should accept 'hello': %v", err)
	}

	if err := lengthValidator("ab"); err == nil {
		t.Error("Length validator should reject 'ab'")
	}

	// Test enum validator
	enumValidator := ValidateEnum("red", "green", "blue")

	if err := enumValidator("green"); err != nil {
		t.Errorf("Enum validator should accept 'green': %v", err)
	}

	if err := enumValidator("yellow"); err == nil {
		t.Error("Enum validator should reject 'yellow'")
	}
}

func TestAuditPlugin_TypedConfiguration(t *testing.T) {
	plugin := NewAuditPlugin()

	// Create typed configuration
	config := CreateAuditPluginConfig()
	config.Set("capture_request", true)
	config.Set("max_body_size", 128*1024)
	config.Set("skip_paths", []string{"/test", "/debug"})
	config.Set("sensitive_fields", []string{"secret", "password"})

	// Initialize plugin with typed config
	if err := plugin.ReloadTypedConfig(config); err != nil {
		t.Fatalf("ReloadTypedConfig() error = %v", err)
	}

	// Test that plugin uses typed configuration
	captureRequest, _, maxBodySize, skipPaths, sensitiveFields := plugin.getTypedValues()

	if captureRequest != true {
		t.Errorf("captureRequest = %v, want %v", captureRequest, true)
	}

	if maxBodySize != 128*1024 {
		t.Errorf("maxBodySize = %v, want %v", maxBodySize, 128*1024)
	}

	expectedSkipPaths := []string{"/test", "/debug"}
	if !reflect.DeepEqual(skipPaths, expectedSkipPaths) {
		t.Errorf("skipPaths = %v, want %v", skipPaths, expectedSkipPaths)
	}

	expectedSensitiveFields := []string{"secret", "password"}
	if !reflect.DeepEqual(sensitiveFields, expectedSensitiveFields) {
		t.Errorf("sensitiveFields = %v, want %v", sensitiveFields, expectedSensitiveFields)
	}

	// Test schema access
	schema := plugin.GetConfigSchema()
	if schema == nil {
		t.Error("GetConfigSchema() returned nil")
	}

	if _, exists := schema["capture_request"]; !exists {
		t.Error("Schema should contain 'capture_request' field")
	}
}

func TestTypeCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		actual   reflect.Type
		expected reflect.Type
		want     bool
	}{
		{"exact match", reflect.TypeOf(42), reflect.TypeOf(42), true},
		{"int to int64", reflect.TypeOf(42), reflect.TypeOf(int64(42)), true},
		{"string conversion", reflect.TypeOf(42), reflect.TypeOf(""), true},
		{"slice compatibility", reflect.TypeOf([]string{}), reflect.TypeOf([]string{}), true},
		{"interface any", reflect.TypeOf(42), reflect.TypeOf((*interface{})(nil)).Elem(), true},
		{"incompatible", reflect.TypeOf(42), reflect.TypeOf(time.Time{}), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCompatibleType(tt.actual, tt.expected); got != tt.want {
				t.Errorf("isCompatibleType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkTypedConfig_GetString(b *testing.B) {
	config := NewTypedPluginConfig("test")
	config.Set("test_key", "test_value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.GetString("test_key")
	}
}

func BenchmarkTypedConfig_GetInt(b *testing.B) {
	config := NewTypedPluginConfig("test")
	config.Set("test_key", 42)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.GetInt("test_key")
	}
}

func BenchmarkTypedConfig_Validation(b *testing.B) {
	config := CreateAuditPluginConfig()
	config.Set("capture_request", true)
	config.Set("max_body_size", 64*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Validate()
	}
}
