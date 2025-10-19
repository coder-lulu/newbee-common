// Copyright 2024 The NewBee Authors. All Rights Reserved.

package audit

import (
	"crypto/sha256"
	"encoding/hex"
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
	EnableContextAnalysis  bool `json:"enable_context_analysis"`

	// Desensitization levels
	DefaultLevel       DesensitizationLevel            `json:"default_level"`
	LevelByContentType map[string]DesensitizationLevel `json:"level_by_content_type"`
	LevelByField       map[string]DesensitizationLevel `json:"level_by_field"`

	// Performance settings
	CacheEnabled bool          `json:"cache_enabled"`
	CacheSize    int           `json:"cache_size"`
	CacheTTL     time.Duration `json:"cache_ttl"`

	// Hash settings
	HashSalt       string `json:"hash_salt,omitempty"`
	PreserveLength bool   `json:"preserve_length"`
	PreserveFormat bool   `json:"preserve_format"`

	// Custom settings
	CustomPatterns []CustomPattern       `json:"custom_patterns"`
	FieldMappings  map[string]string     `json:"field_mappings"` // field -> desensitization type
}

// DefaultDesensitizationConfig returns default desensitization configuration
func DefaultDesensitizationConfig() *DesensitizationConfig {
	return &DesensitizationConfig{
		Enabled:                true,
		MaxDataSize:            1024 * 1024, // 1MB
		PerformanceMode:        true,
		EnablePatternDetection: true,
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

	// Compile patterns
	for _, pattern := range config.CustomPatterns {
		if pattern.Enabled && pattern.Pattern != "" {
			if regex, err := regexp.Compile(pattern.Pattern); err == nil {
				matcher.patterns[pattern.Name] = regex
			} else {
				logx.Errorw("Failed to compile pattern", 
					logx.Field("name", pattern.Name),
					logx.Field("pattern", pattern.Pattern),
					logx.Field("error", err))
			}
		}
	}

	return matcher
}

// DesensitizationCache provides caching for desensitized data
type DesensitizationCache struct {
	cache map[string]CacheEntry
	mu    sync.RWMutex
	size  int
	ttl   time.Duration
}

type CacheEntry struct {
	Value     string
	Timestamp time.Time
}

// NewDesensitizationCache creates a new desensitization cache
func NewDesensitizationCache(size int, ttl time.Duration) *DesensitizationCache {
	cache := &DesensitizationCache{
		cache: make(map[string]CacheEntry),
		size:  size,
		ttl:   ttl,
	}
	
	// Start cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// Get retrieves a cached desensitized value
func (c *DesensitizationCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.cache[key]
	if !exists || time.Since(entry.Timestamp) > c.ttl {
		return "", false
	}
	
	return entry.Value, true
}

// Put stores a desensitized value in cache
func (c *DesensitizationCache) Put(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Check size limit
	if len(c.cache) >= c.size {
		// Remove oldest entry (simple implementation)
		var oldestKey string
		var oldestTime time.Time = time.Now()
		for k, v := range c.cache {
			if v.Timestamp.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.Timestamp
			}
		}
		if oldestKey != "" {
			delete(c.cache, oldestKey)
		}
	}
	
	c.cache[key] = CacheEntry{
		Value:     value,
		Timestamp: time.Now(),
	}
}

// cleanup removes expired entries
func (c *DesensitizationCache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.cache {
			if now.Sub(entry.Timestamp) > c.ttl {
				delete(c.cache, key)
			}
		}
		c.mu.Unlock()
	}
}

// DesensitizationStatsCollector collects desensitization statistics
type DesensitizationStatsCollector struct {
	TotalRequests     int64 `json:"total_requests"`
	ProcessedRequests int64 `json:"processed_requests"`
	CacheHits         int64 `json:"cache_hits"`
	CacheMisses       int64 `json:"cache_misses"`
	DetectedPatterns  int64 `json:"detected_patterns"`
	ProcessingTimeMs  int64 `json:"processing_time_ms"`
	mu                sync.RWMutex
}

// NewDataDesensitizer creates a new data desensitizer
func NewDataDesensitizer(config *DesensitizationConfig) *DataDesensitizer {
	if config == nil {
		config = DefaultDesensitizationConfig()
	}

	var cache *DesensitizationCache
	if config.CacheEnabled {
		cache = NewDesensitizationCache(config.CacheSize, config.CacheTTL)
	}

	desensitizer := &DataDesensitizer{
		config:         config,
		patternMatcher: NewPatternMatcher(config),
		cache:          cache,
		stats:          &DesensitizationStatsCollector{},
	}

	logx.Infow("Data desensitizer initialized",
		logx.Field("enabled", config.Enabled),
		logx.Field("patterns", len(config.CustomPatterns)),
		logx.Field("fieldMappings", len(config.FieldMappings)))

	return desensitizer
}

// DesensitizeData desensitizes sensitive data in the given input
func (d *DataDesensitizer) DesensitizeData(data interface{}) interface{} {
	if !d.config.Enabled {
		return data
	}

	d.stats.mu.Lock()
	d.stats.TotalRequests++
	d.stats.mu.Unlock()

	start := time.Now()
	defer func() {
		d.stats.mu.Lock()
		d.stats.ProcessingTimeMs += time.Since(start).Milliseconds()
		d.stats.mu.Unlock()
	}()

	switch v := data.(type) {
	case string:
		return d.desensitizeString(v)
	case map[string]interface{}:
		return d.desensitizeMap(v)
	case []interface{}:
		return d.desensitizeSlice(v)
	default:
		return data
	}
}

// desensitizeString desensitizes a string value
func (d *DataDesensitizer) desensitizeString(value string) string {
	if value == "" {
		return value
	}

	// Check cache first
	if d.cache != nil {
		cacheKey := d.generateCacheKey(value)
		if cached, found := d.cache.Get(cacheKey); found {
			d.stats.mu.Lock()
			d.stats.CacheHits++
			d.stats.mu.Unlock()
			return cached
		}
		d.stats.mu.Lock()
		d.stats.CacheMisses++
		d.stats.mu.Unlock()
	}

	result := d.applyPatterns(value)

	// Cache result
	if d.cache != nil {
		cacheKey := d.generateCacheKey(value)
		d.cache.Put(cacheKey, result)
	}

	return result
}

// desensitizeMap desensitizes a map
func (d *DataDesensitizer) desensitizeMap(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		level := d.getLevelForField(key)
		
		switch level {
		case LevelRemoved:
			// Skip this field
			continue
		case LevelNone:
			result[key] = value
		default:
			result[key] = d.DesensitizeData(value)
		}
	}

	return result
}

// desensitizeSlice desensitizes a slice
func (d *DataDesensitizer) desensitizeSlice(data []interface{}) []interface{} {
	result := make([]interface{}, len(data))
	for i, item := range data {
		result[i] = d.DesensitizeData(item)
	}
	return result
}

// getLevelForField gets desensitization level for a field
func (d *DataDesensitizer) getLevelForField(field string) DesensitizationLevel {
	field = strings.ToLower(field)
	
	if level, exists := d.config.LevelByField[field]; exists {
		return level
	}
	
	// Check field mappings
	if mappingType, exists := d.config.FieldMappings[field]; exists {
		if level, exists := d.config.LevelByField[mappingType]; exists {
			return level
		}
	}
	
	return d.config.DefaultLevel
}

// applyPatterns applies desensitization patterns to a string
func (d *DataDesensitizer) applyPatterns(value string) string {
	d.patternMatcher.mu.RLock()
	defer d.patternMatcher.mu.RUnlock()

	result := value
	for name, pattern := range d.patternMatcher.patterns {
		if pattern.MatchString(result) {
			d.stats.mu.Lock()
			d.stats.DetectedPatterns++
			d.stats.mu.Unlock()

			// Find corresponding custom pattern
			for _, cp := range d.config.CustomPatterns {
				if cp.Name == name && cp.Enabled {
					switch cp.Level {
					case LevelPartial:
						result = d.partialMask(result, pattern)
					case LevelComplete:
						result = pattern.ReplaceAllString(result, cp.Replacement)
					case LevelHashed:
						result = d.hashValue(result)
					}
					break
				}
			}
		}
	}

	return result
}

// partialMask partially masks sensitive data
func (d *DataDesensitizer) partialMask(value string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(value, func(match string) string {
		if utf8.RuneCountInString(match) <= 4 {
			return strings.Repeat("*", utf8.RuneCountInString(match))
		}
		
		runes := []rune(match)
		length := len(runes)
		showCount := length / 4 // Show 25% of characters
		
		if showCount < 1 {
			showCount = 1
		}
		if showCount > 3 {
			showCount = 3
		}
		
		masked := make([]rune, length)
		copy(masked, runes)
		
		// Mask middle characters
		for i := showCount; i < length-showCount; i++ {
			masked[i] = '*'
		}
		
		return string(masked)
	})
}

// hashValue hashes a value using SHA256
func (d *DataDesensitizer) hashValue(value string) string {
	hasher := sha256.New()
	hasher.Write([]byte(value + d.config.HashSalt))
	return hex.EncodeToString(hasher.Sum(nil))[:16] // Return first 16 chars
}

// generateCacheKey generates a cache key for a value
func (d *DataDesensitizer) generateCacheKey(value string) string {
	hasher := sha256.New()
	hasher.Write([]byte(value))
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

// UpdateConfig updates the desensitizer configuration
func (d *DataDesensitizer) UpdateConfig(config *DesensitizationConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.config = config
	d.patternMatcher = NewPatternMatcher(config)

	logx.Infow("Data desensitizer configuration updated",
		logx.Field("patterns", len(config.CustomPatterns)),
		logx.Field("fieldMappings", len(config.FieldMappings)))

	return nil
}

// GetStats returns desensitization statistics
func (d *DataDesensitizer) GetStats() *DesensitizationStatsCollector {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	stats := *d.stats
	return &stats
}

// Close gracefully shuts down the desensitizer
func (d *DataDesensitizer) Close() error {
	logx.Info("Data desensitizer shutting down")
	return nil
}