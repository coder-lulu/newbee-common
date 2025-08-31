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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zeromicro/go-zero/core/logx"
)

// DataDesensitizer provides intelligent sensitive data identification and multi-layer desensitization
type DataDesensitizer struct {
	config         *DesensitizationConfig
	patternMatcher *PatternMatcher
	ruleEngine     *DesensitizationRuleEngine
	cache          *DesensitizationCache
	stats          *DesensitizationStatsCollector
	mu             sync.RWMutex
}

// DesensitizationConfig defines configuration for data desensitization
type DesensitizationConfig struct {
	// Basic settings
	Enabled         bool `json:"enabled"`
	MaxDataSize     int  `json:"max_data_size"`    // Maximum data size to process
	PerformanceMode bool `json:"performance_mode"` // Enable performance optimizations

	// Detection settings
	EnablePatternDetection bool `json:"enable_pattern_detection"`
	EnableMLDetection      bool `json:"enable_ml_detection"`
	EnableContextAnalysis  bool `json:"enable_context_analysis"`

	// Desensitization levels
	DefaultLevel       DesensitizationLevel            `json:"default_level"`
	LevelByContentType map[string]DesensitizationLevel `json:"level_by_content_type"`
	LevelByField       map[string]DesensitizationLevel `json:"level_by_field"`

	// Performance settings
	CacheEnabled bool          `json:"cache_enabled"`
	CacheSize    int           `json:"cache_size"`
	CacheTTL     time.Duration `json:"cache_ttl"`
	BatchSize    int           `json:"batch_size"`

	// Hash settings
	HashSalt       string `json:"hash_salt,omitempty"`
	PreserveLength bool   `json:"preserve_length"`
	PreserveFormat bool   `json:"preserve_format"`

	// Custom settings
	CustomPatterns []CustomPattern       `json:"custom_patterns"`
	CustomRules    []DesensitizationRule `json:"custom_rules"`
	FieldMappings  map[string]string     `json:"field_mappings"` // field -> desensitization type
}

// DefaultDesensitizationConfig returns default desensitization configuration
func DefaultDesensitizationConfig() *DesensitizationConfig {
	return &DesensitizationConfig{
		Enabled:                true,
		MaxDataSize:            1024 * 1024, // 1MB
		PerformanceMode:        true,
		EnablePatternDetection: true,
		EnableMLDetection:      false, // CPU intensive
		EnableContextAnalysis:  true,
		DefaultLevel:           LevelPartial,
		LevelByContentType: map[string]DesensitizationLevel{
			"application/json":                  LevelPartial,
			"application/x-www-form-urlencoded": LevelComplete,
			"multipart/form-data":               LevelComplete,
		},
		LevelByField: map[string]DesensitizationLevel{
			"password": LevelComplete,
			"ssn":      LevelComplete,
			"email":    LevelPartial,
			"phone":    LevelPartial,
		},
		CacheEnabled:   true,
		CacheSize:      1000,
		CacheTTL:       5 * time.Minute,
		BatchSize:      100,
		PreserveLength: true,
		PreserveFormat: true,
		CustomPatterns: []CustomPattern{
			{
				Name:        "credit_card",
				Pattern:     `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
				Replacement: "****-****-****-****",
				Level:       LevelComplete,
			},
			{
				Name:        "phone_number",
				Pattern:     `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`,
				Replacement: "***-***-****",
				Level:       LevelPartial,
			},
		},
		FieldMappings: map[string]string{
			"password":      "password",
			"passwd":        "password",
			"pwd":           "password",
			"token":         "token",
			"access_token":  "token",
			"refresh_token": "token",
			"secret":        "secret",
			"api_key":       "secret",
			"apikey":        "secret",
			"email":         "email",
			"phone":         "phone",
			"mobile":        "phone",
			"ssn":           "ssn",
			"social":        "ssn",
			"credit":        "credit_card",
			"card":          "credit_card",
		},
	}
}

// DesensitizationLevel defines the level of desensitization
type DesensitizationLevel int

const (
	LevelNone     DesensitizationLevel = iota // No desensitization
	LevelPartial                              // Partial masking (show some characters)
	LevelComplete                             // Complete masking or hashing
	LevelHashed                               // Hash the value
	LevelRemoved                              // Remove the field entirely
)

func (l DesensitizationLevel) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelPartial:
		return "partial"
	case LevelComplete:
		return "complete"
	case LevelHashed:
		return "hashed"
	case LevelRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

// CustomPattern represents a custom pattern for detection
type CustomPattern struct {
	Name        string               `json:"name"`
	Pattern     string               `json:"pattern"`
	Replacement string               `json:"replacement"`
	Level       DesensitizationLevel `json:"level"`
	Enabled     bool                 `json:"enabled"`
}

// DesensitizationRule represents a rule for desensitization
type DesensitizationRule struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Field       string               `json:"field"`
	Pattern     string               `json:"pattern"`
	Level       DesensitizationLevel `json:"level"`
	Context     []string             `json:"context"`  // Context keywords
	Priority    int                  `json:"priority"` // Higher priority rules apply first
	Enabled     bool                 `json:"enabled"`
}

// PatternMatcher handles pattern-based sensitive data detection
type PatternMatcher struct {
	patterns map[string]*regexp.Regexp
	config   *DesensitizationConfig
	mu       sync.RWMutex
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher(config *DesensitizationConfig) *PatternMatcher {
	matcher := &PatternMatcher{
		patterns: make(map[string]*regexp.Regexp),
		config:   config,
	}

	// Compile built-in patterns
	builtinPatterns := map[string]string{
		"email":       `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		"phone":       `\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b`,
		"ssn":         `\b\d{3}-?\d{2}-?\d{4}\b`,
		"credit_card": `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
		"ip_address":  `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
		"url":         `https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`,
		"jwt_token":   `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`,
		"api_key":     `[A-Za-z0-9]{32,}`,
	}

	for name, pattern := range builtinPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			matcher.patterns[name] = regex
		} else {
			logx.Errorw("Failed to compile built-in pattern",
				logx.Field("pattern", name),
				logx.Field("error", err))
		}
	}

	// Compile custom patterns
	for _, customPattern := range config.CustomPatterns {
		if customPattern.Enabled {
			if regex, err := regexp.Compile(customPattern.Pattern); err == nil {
				matcher.patterns[customPattern.Name] = regex
			} else {
				logx.Errorw("Failed to compile custom pattern",
					logx.Field("pattern", customPattern.Name),
					logx.Field("error", err))
			}
		}
	}

	return matcher
}

// DetectPatterns detects sensitive patterns in the given text
func (pm *PatternMatcher) DetectPatterns(text string) []PatternMatch {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var matches []PatternMatch

	for name, pattern := range pm.patterns {
		if found := pattern.FindAllStringSubmatch(text, -1); len(found) > 0 {
			for _, match := range found {
				matches = append(matches, PatternMatch{
					Type:       name,
					Value:      match[0],
					Start:      strings.Index(text, match[0]),
					End:        strings.Index(text, match[0]) + len(match[0]),
					Pattern:    pattern.String(),
					Confidence: pm.calculateConfidence(name, match[0]),
				})
			}
		}
	}

	return matches
}

// PatternMatch represents a detected pattern match
type PatternMatch struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Pattern    string  `json:"pattern"`
	Confidence float64 `json:"confidence"`
}

// calculateConfidence calculates confidence score for a pattern match
func (pm *PatternMatcher) calculateConfidence(patternType, value string) float64 {
	// Simple confidence calculation based on pattern type and value characteristics
	switch patternType {
	case "email":
		if strings.Contains(value, "@") && strings.Contains(value, ".") {
			return 0.9
		}
		return 0.5
	case "credit_card":
		// Luhn algorithm check could be added here
		if len(strings.ReplaceAll(strings.ReplaceAll(value, "-", ""), " ", "")) == 16 {
			return 0.8
		}
		return 0.6
	case "phone":
		if len(strings.ReplaceAll(strings.ReplaceAll(value, "-", ""), " ", "")) >= 10 {
			return 0.8
		}
		return 0.6
	case "ssn":
		if len(strings.ReplaceAll(value, "-", "")) == 9 {
			return 0.9
		}
		return 0.7
	default:
		return 0.5
	}
}

// DesensitizationRuleEngine handles rule-based desensitization
type DesensitizationRuleEngine struct {
	rules  []DesensitizationRule
	config *DesensitizationConfig
	mu     sync.RWMutex
}

// NewDesensitizationRuleEngine creates a new rule engine
func NewDesensitizationRuleEngine(config *DesensitizationConfig) *DesensitizationRuleEngine {
	engine := &DesensitizationRuleEngine{
		rules:  config.CustomRules,
		config: config,
	}
	return engine
}

// ApplyRules applies desensitization rules to the given data
func (re *DesensitizationRuleEngine) ApplyRules(fieldName, value string, context []string) (string, DesensitizationLevel) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// Find matching rules
	var applicableRules []DesensitizationRule

	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}

		// Check field name match
		if rule.Field != "" && !strings.EqualFold(rule.Field, fieldName) {
			continue
		}

		// Check pattern match
		if rule.Pattern != "" {
			if matched, _ := regexp.MatchString(rule.Pattern, value); !matched {
				continue
			}
		}

		// Check context match
		if len(rule.Context) > 0 {
			contextMatch := false
			for _, ctx := range rule.Context {
				for _, provided := range context {
					if strings.Contains(strings.ToLower(provided), strings.ToLower(ctx)) {
						contextMatch = true
						break
					}
				}
				if contextMatch {
					break
				}
			}
			if !contextMatch {
				continue
			}
		}

		applicableRules = append(applicableRules, rule)
	}

	// If no rules match, return original value
	if len(applicableRules) == 0 {
		return value, LevelNone
	}

	// Apply the highest priority rule
	var bestRule *DesensitizationRule
	for i, rule := range applicableRules {
		if bestRule == nil || rule.Priority > bestRule.Priority {
			bestRule = &applicableRules[i]
		}
	}

	return value, bestRule.Level
}

// DesensitizationCache provides caching for desensitization results
type DesensitizationCache struct {
	cache  map[string]CacheEntry
	config *DesensitizationConfig
	mu     sync.RWMutex
}

// CacheEntry represents a cached desensitization result
type CacheEntry struct {
	Value     string               `json:"value"`
	Level     DesensitizationLevel `json:"level"`
	ExpiresAt time.Time            `json:"expires_at"`
	HitCount  int64                `json:"hit_count"`
}

// NewDesensitizationCache creates a new desensitization cache
func NewDesensitizationCache(config *DesensitizationConfig) *DesensitizationCache {
	return &DesensitizationCache{
		cache:  make(map[string]CacheEntry),
		config: config,
	}
}

// Get retrieves a value from cache
func (c *DesensitizationCache) Get(key string) (string, DesensitizationLevel, bool) {
	if !c.config.CacheEnabled {
		return "", LevelNone, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.cache[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		if exists {
			delete(c.cache, key)
		}
		return "", LevelNone, false
	}

	// Update hit count
	entry.HitCount++
	c.cache[key] = entry

	return entry.Value, entry.Level, true
}

// Set stores a value in cache
func (c *DesensitizationCache) Set(key, value string, level DesensitizationLevel) {
	if !c.config.CacheEnabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check cache size limit
	if len(c.cache) >= c.config.CacheSize {
		c.evictOldest()
	}

	c.cache[key] = CacheEntry{
		Value:     value,
		Level:     level,
		ExpiresAt: time.Now().Add(c.config.CacheTTL),
		HitCount:  0,
	}
}

// evictOldest evicts the oldest cache entry
func (c *DesensitizationCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.cache {
		if oldestKey == "" || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// DesensitizationStats tracks desensitization statistics
type DesensitizationStats struct {
	ProcessedFields   int64            `json:"processed_fields"`
	DetectedSensitive int64            `json:"detected_sensitive"`
	CacheHits         int64            `json:"cache_hits"`
	CacheMisses       int64            `json:"cache_misses"`
	ProcessingTimeMs  int64            `json:"processing_time_ms"`
	LastReset         time.Time        `json:"last_reset"`
	DetectionsByType  map[string]int64 `json:"detections_by_type"`
	LevelDistribution map[string]int64 `json:"level_distribution"`
}

// DesensitizationStatsCollector wraps stats with mutex
type DesensitizationStatsCollector struct {
	stats DesensitizationStats
	mu    sync.RWMutex
}

// NewDesensitizationStats creates new desensitization statistics
func NewDesensitizationStats() *DesensitizationStatsCollector {
	return &DesensitizationStatsCollector{
		stats: DesensitizationStats{
			LastReset:         time.Now(),
			DetectionsByType:  make(map[string]int64),
			LevelDistribution: make(map[string]int64),
		},
	}
}

// RecordProcessing records processing statistics
func (s *DesensitizationStatsCollector) RecordProcessing(fieldsCount int64, sensitiveCount int64, processingTime time.Duration, detectionType string, level DesensitizationLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.ProcessedFields += fieldsCount
	s.stats.DetectedSensitive += sensitiveCount
	s.stats.ProcessingTimeMs += processingTime.Milliseconds()

	if detectionType != "" {
		s.stats.DetectionsByType[detectionType]++
	}

	s.stats.LevelDistribution[level.String()]++
}

// RecordCacheHit records a cache hit
func (s *DesensitizationStatsCollector) RecordCacheHit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.CacheHits++
}

// RecordCacheMiss records a cache miss
func (s *DesensitizationStatsCollector) RecordCacheMiss() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.CacheMisses++
}

// GetStats returns current statistics
func (s *DesensitizationStatsCollector) GetStats() DesensitizationStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a new struct copy
	statsCopy := DesensitizationStats{
		ProcessedFields:   s.stats.ProcessedFields,
		DetectedSensitive: s.stats.DetectedSensitive,
		CacheHits:         s.stats.CacheHits,
		CacheMisses:       s.stats.CacheMisses,
		ProcessingTimeMs:  s.stats.ProcessingTimeMs,
		LastReset:         s.stats.LastReset,
		DetectionsByType:  make(map[string]int64),
		LevelDistribution: make(map[string]int64),
	}

	for k, v := range s.stats.DetectionsByType {
		statsCopy.DetectionsByType[k] = v
	}
	for k, v := range s.stats.LevelDistribution {
		statsCopy.LevelDistribution[k] = v
	}

	return statsCopy
}

// Reset resets statistics
func (s *DesensitizationStatsCollector) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.ProcessedFields = 0
	s.stats.DetectedSensitive = 0
	s.stats.CacheHits = 0
	s.stats.CacheMisses = 0
	s.stats.ProcessingTimeMs = 0
	s.stats.LastReset = time.Now()
	s.stats.DetectionsByType = make(map[string]int64)
	s.stats.LevelDistribution = make(map[string]int64)
}

// NewDataDesensitizer creates a new data desensitizer
func NewDataDesensitizer(config *DesensitizationConfig) *DataDesensitizer {
	if config == nil {
		config = DefaultDesensitizationConfig()
	}

	desensitizer := &DataDesensitizer{
		config:         config,
		patternMatcher: NewPatternMatcher(config),
		ruleEngine:     NewDesensitizationRuleEngine(config),
		cache:          NewDesensitizationCache(config),
		stats:          NewDesensitizationStats(),
	}

	logx.Infow("Data desensitizer initialized",
		logx.Field("enabled", config.Enabled),
		logx.Field("performanceMode", config.PerformanceMode),
		logx.Field("patternDetection", config.EnablePatternDetection),
		logx.Field("cacheEnabled", config.CacheEnabled))

	return desensitizer
}

// DesensitizeJSON desensitizes JSON data
func (d *DataDesensitizer) DesensitizeJSON(jsonData string) (string, error) {
	if !d.config.Enabled {
		return jsonData, nil
	}

	if len(jsonData) > d.config.MaxDataSize {
		return "[DATA_TOO_LARGE]", nil
	}

	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		d.stats.RecordProcessing(1, 0, processingTime, "json", LevelPartial)
	}()

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		// If not valid JSON, treat as plain text
		return d.DesensitizeText(jsonData), nil
	}

	desensitized := d.desensitizeMap(data, []string{"json"})

	result, err := json.Marshal(desensitized)
	if err != nil {
		logx.Errorw("Failed to marshal desensitized JSON",
			logx.Field("error", err))
		return "[JSON_MARSHAL_ERROR]", err
	}

	return string(result), nil
}

// DesensitizeFormData desensitizes form data
func (d *DataDesensitizer) DesensitizeFormData(formData string) string {
	if !d.config.Enabled {
		return formData
	}

	if len(formData) > d.config.MaxDataSize {
		return "[DATA_TOO_LARGE]"
	}

	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		d.stats.RecordProcessing(1, 0, processingTime, "form", LevelComplete)
	}()

	// Parse form data
	pairs := strings.Split(formData, "&")
	var desensitizedPairs []string

	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			desensitizedPairs = append(desensitizedPairs, pair)
			continue
		}

		key := parts[0]
		value := parts[1]

		// Desensitize value
		desensitizedValue := d.desensitizeValue(key, value, []string{"form"})
		desensitizedPairs = append(desensitizedPairs, key+"="+desensitizedValue)
	}

	return strings.Join(desensitizedPairs, "&")
}

// DesensitizeText desensitizes plain text
func (d *DataDesensitizer) DesensitizeText(text string) string {
	if !d.config.Enabled {
		return text
	}

	if len(text) > d.config.MaxDataSize {
		return "[DATA_TOO_LARGE]"
	}

	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		d.stats.RecordProcessing(1, 0, processingTime, "text", LevelPartial)
	}()

	if !d.config.EnablePatternDetection {
		return text
	}

	// Detect patterns
	matches := d.patternMatcher.DetectPatterns(text)

	result := text
	for _, match := range matches {
		replacement := d.generateReplacement(match.Type, match.Value)
		result = strings.ReplaceAll(result, match.Value, replacement)

		d.stats.RecordProcessing(0, 1, 0, match.Type, LevelPartial)
	}

	return result
}

// desensitizeMap desensitizes a map of data
func (d *DataDesensitizer) desensitizeMap(data map[string]interface{}, context []string) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		switch v := value.(type) {
		case string:
			result[key] = d.desensitizeValue(key, v, context)
		case map[string]interface{}:
			result[key] = d.desensitizeMap(v, append(context, key))
		case []interface{}:
			result[key] = d.desensitizeSlice(v, append(context, key))
		default:
			result[key] = value
		}
	}

	return result
}

// desensitizeSlice desensitizes a slice of data
func (d *DataDesensitizer) desensitizeSlice(data []interface{}, context []string) []interface{} {
	result := make([]interface{}, len(data))

	for i, item := range data {
		switch v := item.(type) {
		case string:
			result[i] = d.desensitizeValue("", v, context)
		case map[string]interface{}:
			result[i] = d.desensitizeMap(v, context)
		case []interface{}:
			result[i] = d.desensitizeSlice(v, context)
		default:
			result[i] = item
		}
	}

	return result
}

// desensitizeValue desensitizes a single value
func (d *DataDesensitizer) desensitizeValue(fieldName, value string, context []string) string {
	if value == "" {
		return value
	}

	// Check cache first
	cacheKey := d.generateCacheKey(fieldName, value, context)
	if cached, level, found := d.cache.Get(cacheKey); found {
		d.stats.RecordCacheHit()
		d.stats.RecordProcessing(0, 1, 0, "cached", level)
		return cached
	}
	d.stats.RecordCacheMiss()

	// Determine desensitization level
	level := d.determineDesensitizationLevel(fieldName, value, context)

	// Apply desensitization
	result := d.applyDesensitization(fieldName, value, level)

	// Cache the result
	d.cache.Set(cacheKey, result, level)

	return result
}

// determineDesensitizationLevel determines the appropriate desensitization level
func (d *DataDesensitizer) determineDesensitizationLevel(fieldName, value string, context []string) DesensitizationLevel {
	// Check field-specific configuration
	if level, exists := d.config.LevelByField[strings.ToLower(fieldName)]; exists {
		return level
	}

	// Check field mapping
	if mappedType, exists := d.config.FieldMappings[strings.ToLower(fieldName)]; exists {
		if level, exists := d.config.LevelByField[mappedType]; exists {
			return level
		}
	}

	// Apply rule engine
	if _, level := d.ruleEngine.ApplyRules(fieldName, value, context); level != LevelNone {
		return level
	}

	// Pattern-based detection
	if d.config.EnablePatternDetection {
		matches := d.patternMatcher.DetectPatterns(value)
		if len(matches) > 0 {
			// Use the highest confidence match
			var bestMatch PatternMatch
			for _, match := range matches {
				if bestMatch.Type == "" || match.Confidence > bestMatch.Confidence {
					bestMatch = match
				}
			}

			// Determine level based on pattern type
			switch bestMatch.Type {
			case "password", "ssn", "credit_card":
				return LevelComplete
			case "email", "phone":
				return LevelPartial
			default:
				return LevelPartial
			}
		}
	}

	// Check for common sensitive patterns in field name
	sensitivePatterns := []string{
		"password", "passwd", "pwd", "pass",
		"secret", "key", "token",
		"ssn", "social", "credit", "card",
		"phone", "mobile", "email",
	}

	fieldLower := strings.ToLower(fieldName)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(fieldLower, pattern) {
			switch pattern {
			case "password", "passwd", "pwd", "pass", "secret", "key", "token":
				return LevelComplete
			default:
				return LevelPartial
			}
		}
	}

	return d.config.DefaultLevel
}

// applyDesensitization applies the specified desensitization level to a value
func (d *DataDesensitizer) applyDesensitization(fieldName, value string, level DesensitizationLevel) string {
	switch level {
	case LevelNone:
		return value

	case LevelPartial:
		return d.partialMask(value)

	case LevelComplete:
		return d.completeMask(value)

	case LevelHashed:
		return d.hashValue(value)

	case LevelRemoved:
		return "[REMOVED]"

	default:
		return d.partialMask(value)
	}
}

// partialMask applies partial masking to a value
func (d *DataDesensitizer) partialMask(value string) string {
	if len(value) <= 3 {
		return "***"
	}

	// For preserving format, try to detect the value type
	if d.config.PreserveFormat {
		// Email: show first char and domain
		if strings.Contains(value, "@") {
			parts := strings.Split(value, "@")
			if len(parts) == 2 && len(parts[0]) > 0 {
				return string(parts[0][0]) + "****@" + parts[1]
			}
		}

		// Phone: show last 4 digits
		if matched, _ := regexp.MatchString(`\d`, value); matched {
			if len(value) >= 4 {
				return "***-***-" + value[len(value)-4:]
			}
		}
	}

	// Default partial masking: show first and last character
	if d.config.PreserveLength {
		length := utf8.RuneCountInString(value)
		if length <= 2 {
			return strings.Repeat("*", length)
		}

		runes := []rune(value)
		masked := make([]rune, length)
		masked[0] = runes[0]
		masked[length-1] = runes[length-1]

		for i := 1; i < length-1; i++ {
			masked[i] = '*'
		}

		return string(masked)
	}

	return string(value[0]) + "***" + string(value[len(value)-1])
}

// completeMask applies complete masking to a value
func (d *DataDesensitizer) completeMask(value string) string {
	if d.config.PreserveLength {
		return strings.Repeat("*", utf8.RuneCountInString(value))
	}
	return "[MASKED]"
}

// hashValue creates a hash of the value
func (d *DataDesensitizer) hashValue(value string) string {
	hasher := sha256.New()
	hasher.Write([]byte(d.config.HashSalt + value))
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Return first 8 characters of hash
	if len(hash) >= 8 {
		return "[HASH:" + hash[:8] + "]"
	}
	return "[HASH:" + hash + "]"
}

// generateReplacement generates a replacement string for a detected pattern
func (d *DataDesensitizer) generateReplacement(patternType, value string) string {
	// Check for custom pattern replacement
	for _, customPattern := range d.config.CustomPatterns {
		if customPattern.Name == patternType && customPattern.Replacement != "" {
			return customPattern.Replacement
		}
	}

	// Default replacements
	switch patternType {
	case "email":
		return "****@****.com"
	case "phone":
		return "***-***-****"
	case "ssn":
		return "***-**-****"
	case "credit_card":
		return "****-****-****-****"
	case "ip_address":
		return "***.***.***.***"
	case "url":
		return "https://***.***/***"
	case "jwt_token":
		return "[JWT_TOKEN]"
	case "api_key":
		return "[API_KEY]"
	default:
		return "[DETECTED:" + strings.ToUpper(patternType) + "]"
	}
}

// generateCacheKey generates a cache key for the given parameters
func (d *DataDesensitizer) generateCacheKey(fieldName, value string, context []string) string {
	hasher := sha256.New()
	hasher.Write([]byte(fieldName + "|" + value + "|" + strings.Join(context, ",")))
	return hex.EncodeToString(hasher.Sum(nil))[:16] // Use first 16 characters
}

// GetStats returns desensitization statistics
func (d *DataDesensitizer) GetStats() DesensitizationStats {
	return d.stats.GetStats()
}

// ResetStats resets desensitization statistics
func (d *DataDesensitizer) ResetStats() {
	d.stats.Reset()
}

// UpdateConfig updates the desensitizer configuration
func (d *DataDesensitizer) UpdateConfig(config *DesensitizationConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.config = config
	d.patternMatcher = NewPatternMatcher(config)
	d.ruleEngine = NewDesensitizationRuleEngine(config)

	logx.Infow("Desensitizer configuration updated",
		logx.Field("enabled", config.Enabled),
		logx.Field("performanceMode", config.PerformanceMode))

	return nil
}

// Close gracefully shuts down the desensitizer
func (d *DataDesensitizer) Close() error {
	logx.Info("Data desensitizer shutting down")
	return nil
}
