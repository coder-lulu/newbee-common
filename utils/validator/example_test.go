package validator

import (
	"fmt"
	"regexp"
	"testing"
)

func ExampleValidator() {
	// 创建验证引擎
	validator := NewValidator()

	// 注册自定义验证函数
	validator.RegisterCustomValidator("ipv4", func(value interface{}, params map[string]interface{}) error {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("值必须是字符串类型")
		}
		pattern := `^(\d{1,3}\.){3}\d{1,3}$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil || !matched {
			return fmt.Errorf("IP地址格式不正确")
		}
		return nil
	})

	// 定义验证规则
	rules := []ValidationRule{
		{
			Type:    "required",
			Message: "字段不能为空",
			Enabled: true,
		},
		{
			Type:    "string",
			Message: "必须是字符串类型",
			Enabled: true,
			Params: map[string]interface{}{
				"minLength": 3.0,
				"maxLength": 50.0,
			},
		},
		{
			Type:    "pattern",
			Message: "只能包含字母和数字",
			Enabled: true,
			Params: map[string]interface{}{
				"pattern": "^[a-zA-Z0-9]+$",
			},
		},
	}

	// 测试用例
	testCases := []struct {
		name  string
		value interface{}
		want  bool
	}{
		{
			name:  "有效值",
			value: "abc123",
			want:  true,
		},
		{
			name:  "空值",
			value: "",
			want:  false,
		},
		{
			name:  "太短",
			value: "ab",
			want:  false,
		},
		{
			name:  "包含特殊字符",
			value: "abc@123",
			want:  false,
		},
	}

	// 执行测试
	for _, tc := range testCases {
		result := validator.Validate(tc.value, rules)
		fmt.Printf("测试 %s: 值=%v, 期望=%v, 实际=%v\n",
			tc.name, tc.value, tc.want, result.Valid)
		if !result.Valid {
			fmt.Printf("错误信息: %v\n", result.Errors)
		}
	}
}

func TestValidator(t *testing.T) {
	validator := NewValidator()

	// 测试必填规则
	t.Run("required", func(t *testing.T) {
		rules := []ValidationRule{
			{
				Type:    "required",
				Message: "字段不能为空",
				Enabled: true,
			},
		}

		result := validator.Validate("", rules)
		if result.Valid {
			t.Error("空字符串应该验证失败")
		}
	})

	// 测试数字范围规则
	t.Run("number range", func(t *testing.T) {
		rules := []ValidationRule{
			{
				Type:    "range",
				Message: "数值必须在1-100之间",
				Enabled: true,
				Params: map[string]interface{}{
					"min": 1.0,
					"max": 100.0,
				},
			},
		}

		result := validator.Validate(50, rules)
		if !result.Valid {
			t.Error("50应该在有效范围内")
		}

		result = validator.Validate(150, rules)
		if result.Valid {
			t.Error("150应该超出范围")
		}
	})

	// 测试日期验证
	t.Run("date validation", func(t *testing.T) {
		rules := []ValidationRule{
			{
				Type:    "date",
				Message: "日期格式不正确",
				Enabled: true,
				Params: map[string]interface{}{
					"layout": "2006-01-02",
				},
			},
		}

		result := validator.Validate("2024-03-20", rules)
		if !result.Valid {
			t.Error("有效日期应该通过验证")
		}

		result = validator.Validate("2024/03/20", rules)
		if result.Valid {
			t.Error("无效日期格式应该验证失败")
		}
	})

	// 测试枚举值验证
	t.Run("enum validation", func(t *testing.T) {
		rules := []ValidationRule{
			{
				Type:    "enum",
				Message: "值必须是预定义的选项之一",
				Enabled: true,
				Params: map[string]interface{}{
					"values": []interface{}{"A", "B", "C"},
				},
			},
		}

		result := validator.Validate("A", rules)
		if !result.Valid {
			t.Error("有效枚举值应该通过验证")
		}

		result = validator.Validate("D", rules)
		if result.Valid {
			t.Error("无效枚举值应该验证失败")
		}
	})

	// 测试自定义规则
	t.Run("custom validator", func(t *testing.T) {
		validator.RegisterCustomValidator("even", func(value interface{}, params map[string]interface{}) error {
			num, ok := value.(int)
			if !ok {
				return fmt.Errorf("值必须是整数类型")
			}
			if num%2 != 0 {
				return fmt.Errorf("必须是偶数")
			}
			return nil
		})

		rules := []ValidationRule{
			{
				Type:            "custom",
				Message:         "必须是偶数",
				Enabled:         true,
				CustomValidator: "even",
			},
		}

		result := validator.Validate(4, rules)
		if !result.Valid {
			t.Error("4应该是有效的偶数")
		}

		result = validator.Validate(5, rules)
		if result.Valid {
			t.Error("5应该是无效的奇数")
		}
	})
}
