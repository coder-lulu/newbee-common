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

package middleware

import (
	"strings"
	"testing"
	"time"
)

func TestDataDesensitizer_DesensitizeJSON(t *testing.T) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	tests := []struct {
		name     string
		input    string
		wantFunc func(string) bool
	}{
		{
			name:  "simple password field",
			input: `{"username":"user123","password":"secret123","email":"user@example.com"}`,
			wantFunc: func(result string) bool {
				return strings.Contains(result, `"password":"`) &&
					!strings.Contains(result, "secret123") &&
					strings.Contains(result, "user@example.com")
			},
		},
		{
			name:  "nested sensitive data",
			input: `{"user":{"id":123,"credentials":{"password":"mysecret","api_key":"abc123"},"profile":{"email":"test@test.com"}}}`,
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "mysecret") &&
					!strings.Contains(result, "abc123") &&
					strings.Contains(result, "test@test.com")
			},
		},
		{
			name:  "array with sensitive data",
			input: `{"users":[{"name":"john","password":"pass1"},{"name":"jane","password":"pass2"}]}`,
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "pass1") &&
					!strings.Contains(result, "pass2") &&
					strings.Contains(result, "john") &&
					strings.Contains(result, "jane")
			},
		},
		{
			name:  "empty JSON",
			input: `{}`,
			wantFunc: func(result string) bool {
				return result == `{}`
			},
		},
		{
			name:  "invalid JSON fallback to text",
			input: `invalid json with password=secret123`,
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "secret123")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := desensitizer.DesensitizeJSON(tt.input)
			if err != nil {
				t.Errorf("DesensitizeJSON() error = %v", err)
				return
			}
			if !tt.wantFunc(result) {
				t.Errorf("DesensitizeJSON() = %v, validation failed", result)
			}
		})
	}
}

func TestDataDesensitizer_DesensitizeFormData(t *testing.T) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	tests := []struct {
		name     string
		input    string
		wantFunc func(string) bool
	}{
		{
			name:  "simple form with password",
			input: "username=john&password=secret123&email=john@example.com",
			wantFunc: func(result string) bool {
				return strings.Contains(result, "username=john") &&
					!strings.Contains(result, "secret123") &&
					strings.Contains(result, "email=john@example.com")
			},
		},
		{
			name:  "multiple sensitive fields",
			input: "user=john&pass=secret&token=abc123&normal=value",
			wantFunc: func(result string) bool {
				return strings.Contains(result, "user=john") &&
					strings.Contains(result, "normal=value") &&
					!strings.Contains(result, "secret") &&
					!strings.Contains(result, "abc123")
			},
		},
		{
			name:  "empty form data",
			input: "",
			wantFunc: func(result string) bool {
				return result == ""
			},
		},
		{
			name:  "malformed form data",
			input: "key1=value1&key2&key3=value3",
			wantFunc: func(result string) bool {
				return strings.Contains(result, "key1=value1") &&
					strings.Contains(result, "key2") &&
					strings.Contains(result, "key3=value3")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := desensitizer.DesensitizeFormData(tt.input)
			if !tt.wantFunc(result) {
				t.Errorf("DesensitizeFormData() = %v, validation failed", result)
			}
		})
	}
}

func TestDataDesensitizer_DesensitizeText(t *testing.T) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	tests := []struct {
		name     string
		input    string
		wantFunc func(string) bool
	}{
		{
			name:  "email detection",
			input: "Contact us at support@company.com or admin@test.org",
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "support@company.com") &&
					!strings.Contains(result, "admin@test.org")
			},
		},
		{
			name:  "phone number detection",
			input: "Call us at 123-456-7890 or 555.123.4567",
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "123-456-7890") &&
					!strings.Contains(result, "555.123.4567")
			},
		},
		{
			name:  "credit card detection",
			input: "Payment with card 4532-1234-5678-9012 was successful",
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "4532-1234-5678-9012")
			},
		},
		{
			name:  "SSN detection",
			input: "SSN: 123-45-6789 is confidential",
			wantFunc: func(result string) bool {
				return !strings.Contains(result, "123-45-6789")
			},
		},
		{
			name:  "no sensitive data",
			input: "This is just normal text with numbers 123 and words",
			wantFunc: func(result string) bool {
				return result == "This is just normal text with numbers 123 and words"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := desensitizer.DesensitizeText(tt.input)
			if !tt.wantFunc(result) {
				t.Errorf("DesensitizeText() = %v, validation failed", result)
			}
		})
	}
}

func TestPatternMatcher_DetectPatterns(t *testing.T) {
	config := DefaultDesensitizationConfig()
	matcher := NewPatternMatcher(config)

	tests := []struct {
		name         string
		input        string
		expectedType string
		shouldFind   bool
	}{
		{
			name:         "detect email",
			input:        "Contact: user@example.com",
			expectedType: "email",
			shouldFind:   true,
		},
		{
			name:         "detect phone",
			input:        "Call: 123-456-7890",
			expectedType: "phone",
			shouldFind:   true,
		},
		{
			name:         "detect credit card",
			input:        "Card: 4532 1234 5678 9012",
			expectedType: "credit_card",
			shouldFind:   true,
		},
		{
			name:         "detect SSN",
			input:        "SSN: 123-45-6789",
			expectedType: "ssn",
			shouldFind:   true,
		},
		{
			name:         "detect IP address",
			input:        "Server: 192.168.1.1",
			expectedType: "ip_address",
			shouldFind:   true,
		},
		{
			name:         "detect URL",
			input:        "Visit: https://example.com/path",
			expectedType: "url",
			shouldFind:   true,
		},
		{
			name:       "no patterns",
			input:      "Just normal text here",
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := matcher.DetectPatterns(tt.input)

			if !tt.shouldFind {
				if len(matches) > 0 {
					t.Errorf("Expected no matches, but found %d", len(matches))
				}
				return
			}

			found := false
			for _, match := range matches {
				if match.Type == tt.expectedType {
					found = true
					if match.Confidence <= 0 || match.Confidence > 1 {
						t.Errorf("Invalid confidence score: %f", match.Confidence)
					}
					break
				}
			}

			if !found {
				t.Errorf("Expected to find pattern type %s, but didn't", tt.expectedType)
			}
		})
	}
}

func TestDesensitizationCache(t *testing.T) {
	config := DefaultDesensitizationConfig()
	config.CacheSize = 3
	config.CacheTTL = 100 * time.Millisecond

	cache := NewDesensitizationCache(config)

	// Test basic set/get
	cache.Set("key1", "value1", LevelPartial)
	value, level, found := cache.Get("key1")
	if !found || value != "value1" || level != LevelPartial {
		t.Errorf("Cache get failed: found=%v, value=%s, level=%v", found, value, level)
	}

	// Test cache expiration
	time.Sleep(150 * time.Millisecond)
	_, _, found = cache.Get("key1")
	if found {
		t.Errorf("Expected cache entry to be expired")
	}

	// Test cache size limit
	cache.Set("key1", "value1", LevelPartial)
	cache.Set("key2", "value2", LevelPartial)
	cache.Set("key3", "value3", LevelPartial)
	cache.Set("key4", "value4", LevelPartial) // Should evict oldest

	// Key1 might be evicted
	_, _, _ = cache.Get("key1") // found1 not used
	_, _, found4 := cache.Get("key4")

	if !found4 {
		t.Errorf("Expected key4 to be in cache")
	}

	// Test cache disabled
	config.CacheEnabled = false
	disabledCache := NewDesensitizationCache(config)
	disabledCache.Set("test", "value", LevelPartial)
	_, _, found = disabledCache.Get("test")
	if found {
		t.Errorf("Expected cache to be disabled")
	}
}

func TestDesensitizationRuleEngine(t *testing.T) {
	config := DefaultDesensitizationConfig()
	config.CustomRules = []DesensitizationRule{
		{
			ID:       "rule1",
			Name:     "High Priority Password",
			Field:    "password",
			Level:    LevelComplete,
			Priority: 10,
			Enabled:  true,
		},
		{
			ID:       "rule2",
			Name:     "Context Sensitive",
			Pattern:  `\d{3}-\d{2}-\d{4}`,
			Context:  []string{"ssn", "social"},
			Level:    LevelHashed,
			Priority: 5,
			Enabled:  true,
		},
		{
			ID:       "rule3",
			Name:     "Disabled Rule",
			Field:    "secret",
			Level:    LevelRemoved,
			Priority: 15,
			Enabled:  false,
		},
	}

	engine := NewDesensitizationRuleEngine(config)

	tests := []struct {
		name          string
		fieldName     string
		value         string
		context       []string
		expectedLevel DesensitizationLevel
	}{
		{
			name:          "field match",
			fieldName:     "password",
			value:         "secret123",
			context:       []string{},
			expectedLevel: LevelComplete,
		},
		{
			name:          "pattern match with context",
			fieldName:     "user_ssn",
			value:         "123-45-6789",
			context:       []string{"user", "ssn"},
			expectedLevel: LevelHashed,
		},
		{
			name:          "disabled rule ignored",
			fieldName:     "secret",
			value:         "topsecret",
			context:       []string{},
			expectedLevel: LevelNone,
		},
		{
			name:          "no rules match",
			fieldName:     "username",
			value:         "john",
			context:       []string{},
			expectedLevel: LevelNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, level := engine.ApplyRules(tt.fieldName, tt.value, tt.context)
			if level != tt.expectedLevel {
				t.Errorf("ApplyRules() level = %v, want %v", level, tt.expectedLevel)
			}
		})
	}
}

func TestDesensitizationLevels(t *testing.T) {
	config := DefaultDesensitizationConfig()
	config.PreserveLength = true
	config.PreserveFormat = true
	config.HashSalt = "testsalt"

	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	tests := []struct {
		name     string
		level    DesensitizationLevel
		value    string
		wantFunc func(string, string) bool
	}{
		{
			name:  "level none",
			level: LevelNone,
			value: "unchanged",
			wantFunc: func(original, result string) bool {
				return original == result
			},
		},
		{
			name:  "level partial preserves length",
			level: LevelPartial,
			value: "password123",
			wantFunc: func(original, result string) bool {
				return len(original) == len(result) && result != original
			},
		},
		{
			name:  "level complete masks all",
			level: LevelComplete,
			value: "secret",
			wantFunc: func(original, result string) bool {
				return !strings.Contains(result, original) && len(result) == len(original)
			},
		},
		{
			name:  "level hashed creates hash",
			level: LevelHashed,
			value: "sensitive",
			wantFunc: func(original, result string) bool {
				return strings.HasPrefix(result, "[HASH:") && strings.HasSuffix(result, "]")
			},
		},
		{
			name:  "level removed",
			level: LevelRemoved,
			value: "remove_me",
			wantFunc: func(original, result string) bool {
				return result == "[REMOVED]"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := desensitizer.applyDesensitization("testfield", tt.value, tt.level)
			if !tt.wantFunc(tt.value, result) {
				t.Errorf("applyDesensitization() = %v, validation failed for level %v", result, tt.level)
			}
		})
	}
}

func TestDataDesensitizer_Performance(t *testing.T) {
	config := DefaultDesensitizationConfig()
	config.PerformanceMode = true
	config.CacheEnabled = true

	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	// Test data
	jsonData := `{
		"user": {
			"id": 123,
			"email": "user@example.com",
			"password": "secret123",
			"profile": {
				"phone": "123-456-7890",
				"ssn": "123-45-6789"
			}
		},
		"metadata": {
			"created_at": "2024-01-01T00:00:00Z",
			"api_key": "sk_test_abc123def456"
		}
	}`

	// Benchmark processing
	iterations := 100
	start := time.Now()

	for i := 0; i < iterations; i++ {
		_, err := desensitizer.DesensitizeJSON(jsonData)
		if err != nil {
			t.Fatalf("DesensitizeJSON failed: %v", err)
		}
	}

	duration := time.Since(start)
	avgDuration := duration / time.Duration(iterations)

	t.Logf("Performance test: %d iterations in %v, avg: %v per operation",
		iterations, duration, avgDuration)

	// Should complete reasonably fast (under 10ms per operation)
	if avgDuration > 10*time.Millisecond {
		t.Errorf("Performance too slow: %v per operation", avgDuration)
	}

	// Check statistics
	stats := desensitizer.GetStats()
	if stats.ProcessedFields == 0 {
		t.Errorf("Expected processed fields > 0")
	}

	if stats.CacheHits+stats.CacheMisses == 0 {
		t.Errorf("Expected cache operations > 0")
	}

	t.Logf("Stats: processed=%d, sensitive=%d, cache_hits=%d, cache_misses=%d, processing_time=%dms",
		stats.ProcessedFields, stats.DetectedSensitive, stats.CacheHits, stats.CacheMisses, stats.ProcessingTimeMs)
}

func TestDataDesensitizer_ConfigUpdate(t *testing.T) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	// Test initial state
	result, err := desensitizer.DesensitizeJSON(`{"password":"test"}`)
	if err != nil {
		t.Fatalf("Initial desensitization failed: %v", err)
	}
	if strings.Contains(result, "test") {
		t.Errorf("Expected password to be masked")
	}

	// Update config to disable
	newConfig := DefaultDesensitizationConfig()
	newConfig.Enabled = false

	err = desensitizer.UpdateConfig(newConfig)
	if err != nil {
		t.Fatalf("Config update failed: %v", err)
	}

	// Test disabled state
	result, err = desensitizer.DesensitizeJSON(`{"password":"test"}`)
	if err != nil {
		t.Fatalf("Desensitization after config update failed: %v", err)
	}
	if !strings.Contains(result, "test") {
		t.Errorf("Expected password to NOT be masked when disabled")
	}
}

func TestDataDesensitizer_EdgeCases(t *testing.T) {
	config := DefaultDesensitizationConfig()
	config.MaxDataSize = 100 // Small limit for testing

	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "very large data",
			input:    strings.Repeat("a", 200),
			expected: "[DATA_TOO_LARGE]",
		},
		{
			name:     "null JSON",
			input:    "null",
			expected: "null",
		},
		{
			name:     "empty JSON object",
			input:    "{}",
			expected: "{}",
		},
		{
			name:     "empty JSON array",
			input:    "[]",
			expected: "[]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := desensitizer.DesensitizeJSON(tt.input)
			if err != nil {
				t.Errorf("DesensitizeJSON() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("DesensitizeJSON() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDataDesensitizer_StatsTracking(t *testing.T) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	// Initial stats should be zero
	stats := desensitizer.GetStats()
	if stats.ProcessedFields != 0 || stats.DetectedSensitive != 0 {
		t.Errorf("Initial stats should be zero")
	}

	// Process some data
	jsonData := `{"password":"secret","email":"user@test.com","normal":"value"}`
	_, err := desensitizer.DesensitizeJSON(jsonData)
	if err != nil {
		t.Fatalf("DesensitizeJSON failed: %v", err)
	}

	// Check stats updated
	stats = desensitizer.GetStats()
	if stats.ProcessedFields == 0 {
		t.Errorf("Expected processed fields > 0")
	}

	// Reset stats
	desensitizer.ResetStats()
	stats = desensitizer.GetStats()
	if stats.ProcessedFields != 0 {
		t.Errorf("Expected stats to be reset")
	}
}

// Benchmark tests
func BenchmarkDataDesensitizer_JSON(b *testing.B) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	jsonData := `{
		"user": {
			"email": "user@example.com",
			"password": "secret123",
			"profile": {
				"phone": "123-456-7890",
				"address": "123 Main St"
			}
		}
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := desensitizer.DesensitizeJSON(jsonData)
		if err != nil {
			b.Fatalf("DesensitizeJSON failed: %v", err)
		}
	}
}

func BenchmarkDataDesensitizer_FormData(b *testing.B) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	formData := "username=john&password=secret123&email=john@example.com&phone=123-456-7890"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		desensitizer.DesensitizeFormData(formData)
	}
}

func BenchmarkDataDesensitizer_Text(b *testing.B) {
	config := DefaultDesensitizationConfig()
	desensitizer := NewDataDesensitizer(config)
	defer desensitizer.Close()

	text := "Contact support@company.com or call 123-456-7890. SSN: 123-45-6789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		desensitizer.DesensitizeText(text)
	}
}

func BenchmarkPatternMatcher_Detection(b *testing.B) {
	config := DefaultDesensitizationConfig()
	matcher := NewPatternMatcher(config)

	text := "Email: user@example.com, Phone: 123-456-7890, Card: 4532-1234-5678-9012"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.DetectPatterns(text)
	}
}
