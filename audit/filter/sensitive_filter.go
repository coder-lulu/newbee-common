package filter

import (
	"encoding/json"
	"regexp"
	"strings"
)

// SensitiveFilter provides sensitive data filtering functionality
type SensitiveFilter struct {
	config *FilterConfig
}

// FilterConfig defines configuration for sensitive data filtering
type FilterConfig struct {
	SensitiveFields []string `json:"sensitive_fields"`
	MaskCharacter   string   `json:"mask_character"`
}

// DefaultFilterConfig returns default filter configuration
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		SensitiveFields: []string{"password", "passwd", "token", "secret", "key", "credential"},
		MaskCharacter:   "***",
	}
}

// NewSensitiveFilter creates a new sensitive filter
func NewSensitiveFilter(config *FilterConfig) (*SensitiveFilter, error) {
	if config == nil {
		config = DefaultFilterConfig()
	}
	return &SensitiveFilter{config: config}, nil
}

// FilterJSON filters sensitive data from JSON string
func (f *SensitiveFilter) FilterJSON(data string) (string, error) {
	if data == "" {
		return data, nil
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &jsonData); err != nil {
		// If not valid JSON, treat as plain text
		return f.filterText(data), nil
	}

	f.filterJSONObject(jsonData)
	
	filtered, err := json.Marshal(jsonData)
	if err != nil {
		return data, err
	}
	
	return string(filtered), nil
}

// FilterFormData filters sensitive data from form data string
func (f *SensitiveFilter) FilterFormData(data string) string {
	return f.filterText(data)
}

// filterJSONObject recursively filters JSON object
func (f *SensitiveFilter) filterJSONObject(obj map[string]interface{}) {
	for key, value := range obj {
		if f.isSensitiveField(key) {
			obj[key] = f.config.MaskCharacter
		} else if subObj, ok := value.(map[string]interface{}); ok {
			f.filterJSONObject(subObj)
		} else if arr, ok := value.([]interface{}); ok {
			for _, item := range arr {
				if subObj, ok := item.(map[string]interface{}); ok {
					f.filterJSONObject(subObj)
				}
			}
		}
	}
}

// filterText filters sensitive data from plain text
func (f *SensitiveFilter) filterText(data string) string {
	result := data
	for _, field := range f.config.SensitiveFields {
		// Match patterns like field=value or field:value
		pattern := regexp.MustCompile(`(?i)(` + regexp.QuoteMeta(field) + `[=:])[^&\s]+`)
		result = pattern.ReplaceAllString(result, `${1}`+f.config.MaskCharacter)
	}
	return result
}

// isSensitiveField checks if a field name is considered sensitive
func (f *SensitiveFilter) isSensitiveField(fieldName string) bool {
	fieldLower := strings.ToLower(fieldName)
	for _, sensitive := range f.config.SensitiveFields {
		if strings.Contains(fieldLower, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}