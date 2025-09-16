package validator

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationRule 验证规则结构
type ValidationRule struct {
	// 规则类型
	Type string `json:"type"` // required, string, number, email, url, pattern, min, max, range, custom等

	// 规则参数
	Params map[string]interface{} `json:"params,omitempty"` // 不同类型规则的具体参数

	// 错误提示信息
	Message string `json:"message"`

	// 是否启用
	Enabled bool `json:"enabled"`

	// 自定义验证函数名（当type为custom时使用）
	CustomValidator string `json:"customValidator,omitempty"`
}

// ValidationResult 验证结果
type ValidationResult struct {
	// 是否通过验证
	Valid bool `json:"valid"`

	// 错误信息列表
	Errors []string `json:"errors,omitempty"`

	// 验证失败的规则
	FailedRules []ValidationRule `json:"failedRules,omitempty"`
}

// Validator 验证引擎
type Validator struct {
	// 自定义验证函数映射
	customValidators map[string]func(interface{}, map[string]interface{}) error

	// 预编译的正则表达式缓存
	patternCache map[string]*regexp.Regexp
}

// NewValidator 创建新的验证引擎
func NewValidator() *Validator {
	return &Validator{
		customValidators: make(map[string]func(interface{}, map[string]interface{}) error),
		patternCache:     make(map[string]*regexp.Regexp),
	}
}

// RegisterCustomValidator 注册自定义验证函数
func (v *Validator) RegisterCustomValidator(name string, fn func(interface{}, map[string]interface{}) error) {
	v.customValidators[name] = fn
}

// Validate 执行验证
func (v *Validator) Validate(value interface{}, rules []ValidationRule) ValidationResult {
	result := ValidationResult{
		Valid: true,
	}

	if len(rules) == 0 {
		return result
	}

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		err := v.validateRule(value, rule)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, rule.Message)
			result.FailedRules = append(result.FailedRules, rule)
		}
	}

	return result
}

// validateRule 验证单个规则
func (v *Validator) validateRule(value interface{}, rule ValidationRule) error {
	switch rule.Type {
	case "required":
		return v.validateRequired(value)
	case "string":
		return v.validateString(value, rule.Params)
	case "number":
		return v.validateNumber(value, rule.Params)
	case "email":
		return v.validateEmail(value)
	case "url":
		return v.validateURL(value)
	case "pattern":
		return v.validatePattern(value, rule.Params)
	case "min":
		return v.validateMin(value, rule.Params)
	case "max":
		return v.validateMax(value, rule.Params)
	case "range":
		return v.validateRange(value, rule.Params)
	case "date":
		return v.validateDate(value, rule.Params)
	case "datetime":
		return v.validateDateTime(value, rule.Params)
	case "enum":
		return v.validateEnum(value, rule.Params)
	case "custom":
		return v.validateCustom(value, rule)
	default:
		return fmt.Errorf("未知的验证规则类型: %s", rule.Type)
	}
}

// validateRequired 验证必填
func (v *Validator) validateRequired(value interface{}) error {
	if value == nil {
		return fmt.Errorf("字段不能为空")
	}

	switch reflect.TypeOf(value).Kind() {
	case reflect.String:
		if value.(string) == "" {
			return fmt.Errorf("字段不能为空")
		}
	case reflect.Slice, reflect.Map:
		if reflect.ValueOf(value).Len() == 0 {
			return fmt.Errorf("字段不能为空")
		}
	case reflect.Ptr:
		if reflect.ValueOf(value).IsNil() {
			return fmt.Errorf("字段不能为空")
		}
	}
	return nil
}

// validateString 验证字符串
func (v *Validator) validateString(value interface{}, params map[string]interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("值必须是字符串类型")
	}

	if minLen, ok := params["minLength"].(float64); ok {
		if len(str) < int(minLen) {
			return fmt.Errorf("字符串长度不能小于%d", int(minLen))
		}
	}

	if maxLen, ok := params["maxLength"].(float64); ok {
		if len(str) > int(maxLen) {
			return fmt.Errorf("字符串长度不能大于%d", int(maxLen))
		}
	}

	return nil
}

// validateNumber 验证数字
func (v *Validator) validateNumber(value interface{}, params map[string]interface{}) error {
	var num float64
	switch v := value.(type) {
	case float64:
		num = v
	case int:
		num = float64(v)
	case int64:
		num = float64(v)
	case string:
		var err error
		num, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("值必须是数字类型")
		}
	default:
		return fmt.Errorf("值必须是数字类型")
	}

	if min, ok := params["min"].(float64); ok {
		if num < min {
			return fmt.Errorf("数值不能小于%v", min)
		}
	}

	if max, ok := params["max"].(float64); ok {
		if num > max {
			return fmt.Errorf("数值不能大于%v", max)
		}
	}

	return nil
}

// validateEmail 验证邮箱
func (v *Validator) validateEmail(value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("值必须是字符串类型")
	}

	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(pattern, str)
	if err != nil || !matched {
		return fmt.Errorf("邮箱格式不正确")
	}

	return nil
}

// validateURL 验证URL
func (v *Validator) validateURL(value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("值必须是字符串类型")
	}

	if !strings.HasPrefix(str, "http://") && !strings.HasPrefix(str, "https://") {
		return fmt.Errorf("URL必须以http://或https://开头")
	}

	return nil
}

// validatePattern 验证正则表达式
func (v *Validator) validatePattern(value interface{}, params map[string]interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("值必须是字符串类型")
	}

	pattern, ok := params["pattern"].(string)
	if !ok {
		return fmt.Errorf("缺少pattern参数")
	}

	// 使用缓存的编译后的正则表达式
	re, ok := v.patternCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("无效的正则表达式: %v", err)
		}
		v.patternCache[pattern] = re
	}

	if !re.MatchString(str) {
		return fmt.Errorf("格式不匹配")
	}

	return nil
}

// validateMin 验证最小值
func (v *Validator) validateMin(value interface{}, params map[string]interface{}) error {
	min, ok := params["min"].(float64)
	if !ok {
		return fmt.Errorf("缺少min参数")
	}

	switch v := value.(type) {
	case float64:
		if v < min {
			return fmt.Errorf("值不能小于%v", min)
		}
	case int:
		if float64(v) < min {
			return fmt.Errorf("值不能小于%v", min)
		}
	case string:
		if len(v) < int(min) {
			return fmt.Errorf("长度不能小于%v", min)
		}
	default:
		return fmt.Errorf("不支持的类型")
	}

	return nil
}

// validateMax 验证最大值
func (v *Validator) validateMax(value interface{}, params map[string]interface{}) error {
	max, ok := params["max"].(float64)
	if !ok {
		return fmt.Errorf("缺少max参数")
	}

	switch v := value.(type) {
	case float64:
		if v > max {
			return fmt.Errorf("值不能大于%v", max)
		}
	case int:
		if float64(v) > max {
			return fmt.Errorf("值不能大于%v", max)
		}
	case string:
		if len(v) > int(max) {
			return fmt.Errorf("长度不能大于%v", max)
		}
	default:
		return fmt.Errorf("不支持的类型")
	}

	return nil
}

// validateRange 验证范围
func (v *Validator) validateRange(value interface{}, params map[string]interface{}) error {
	min, ok := params["min"].(float64)
	if !ok {
		return fmt.Errorf("缺少min参数")
	}

	max, ok := params["max"].(float64)
	if !ok {
		return fmt.Errorf("缺少max参数")
	}

	switch v := value.(type) {
	case float64:
		if v < min || v > max {
			return fmt.Errorf("值必须在%v到%v之间", min, max)
		}
	case int:
		if float64(v) < min || float64(v) > max {
			return fmt.Errorf("值必须在%v到%v之间", min, max)
		}
	case string:
		if len(v) < int(min) || len(v) > int(max) {
			return fmt.Errorf("长度必须在%v到%v之间", min, max)
		}
	default:
		return fmt.Errorf("不支持的类型")
	}

	return nil
}

// validateDate 验证日期
func (v *Validator) validateDate(value interface{}, params map[string]interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("值必须是字符串类型")
	}

	layout := "2006-01-02"
	if customLayout, ok := params["layout"].(string); ok {
		layout = customLayout
	}

	_, err := time.Parse(layout, str)
	if err != nil {
		return fmt.Errorf("日期格式不正确，应为: %s", layout)
	}

	return nil
}

// validateDateTime 验证日期时间
func (v *Validator) validateDateTime(value interface{}, params map[string]interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("值必须是字符串类型")
	}

	layout := "2006-01-02 15:04:05"
	if customLayout, ok := params["layout"].(string); ok {
		layout = customLayout
	}

	_, err := time.Parse(layout, str)
	if err != nil {
		return fmt.Errorf("日期时间格式不正确，应为: %s", layout)
	}

	return nil
}

// validateEnum 验证枚举值
func (v *Validator) validateEnum(value interface{}, params map[string]interface{}) error {
	enumValues, ok := params["values"].([]interface{})
	if !ok {
		return fmt.Errorf("缺少values参数")
	}

	for _, enumValue := range enumValues {
		if reflect.DeepEqual(value, enumValue) {
			return nil
		}
	}

	return fmt.Errorf("值必须是以下之一: %v", enumValues)
}

// validateCustom 验证自定义规则
func (v *Validator) validateCustom(value interface{}, rule ValidationRule) error {
	if rule.CustomValidator == "" {
		return fmt.Errorf("缺少customValidator参数")
	}

	validator, ok := v.customValidators[rule.CustomValidator]
	if !ok {
		return fmt.Errorf("未找到自定义验证函数: %s", rule.CustomValidator)
	}

	return validator(value, rule.Params)
}
