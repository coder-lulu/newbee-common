// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/coder-lulu/newbee-common/middleware/logging"
)

// FieldMaskProcessor 字段掩码处理器 - 负责字段级权限控制和数据掩码
type FieldMaskProcessor struct {
	logger *logging.MiddlewareLogger
	
	// 掩码策略配置
	maskStrategies map[string]MaskStrategy
	
	// 敏感字段配置
	sensitiveFields map[string]SensitivityLevel
}

// MaskStrategy 掩码策略
type MaskStrategy interface {
	Apply(value interface{}) interface{}
	GetType() string
}

// SensitivityLevel 敏感度级别
type SensitivityLevel int

const (
	SensitivityNone SensitivityLevel = iota // 无敏感性
	SensitivityLow                          // 低敏感度
	SensitivityMedium                       // 中等敏感度
	SensitivityHigh                         // 高敏感度
	SensitivityCritical                     // 关键敏感度
)

// 内置掩码策略实现

// NoneMaskStrategy 无掩码策略
type NoneMaskStrategy struct{}

func (s *NoneMaskStrategy) Apply(value interface{}) interface{} {
	return value
}

func (s *NoneMaskStrategy) GetType() string {
	return "none"
}

// PartialMaskStrategy 部分掩码策略
type PartialMaskStrategy struct {
	keepStart int // 保留开头字符数
	keepEnd   int // 保留结尾字符数
}

func (s *PartialMaskStrategy) Apply(value interface{}) interface{} {
	str := fmt.Sprintf("%v", value)
	if len(str) <= s.keepStart+s.keepEnd {
		return strings.Repeat("*", len(str))
	}
	
	start := str[:s.keepStart]
	end := str[len(str)-s.keepEnd:]
	middle := strings.Repeat("*", len(str)-s.keepStart-s.keepEnd)
	
	return start + middle + end
}

func (s *PartialMaskStrategy) GetType() string {
	return "partial"
}

// FullMaskStrategy 完全掩码策略
type FullMaskStrategy struct {
	replacement string
}

func (s *FullMaskStrategy) Apply(value interface{}) interface{} {
	if s.replacement != "" {
		return s.replacement
	}
	return "***"
}

func (s *FullMaskStrategy) GetType() string {
	return "full"
}

// HashMaskStrategy 哈希掩码策略
type HashMaskStrategy struct {
	algorithm string
}

func (s *HashMaskStrategy) Apply(value interface{}) interface{} {
	str := fmt.Sprintf("%v", value)
	switch s.algorithm {
	case "md5":
		return fmt.Sprintf("%x", md5.Sum([]byte(str)))
	default:
		// 简单哈希
		return fmt.Sprintf("HASH_%d", len(str))
	}
}

func (s *HashMaskStrategy) GetType() string {
	return "hash"
}

// EncryptMaskStrategy 加密掩码策略
type EncryptMaskStrategy struct {
	keyHint string
}

func (s *EncryptMaskStrategy) Apply(value interface{}) interface{} {
	// 简化的加密标识，实际应用中应使用真正的加密
	return fmt.Sprintf("[ENCRYPTED:%s]", s.keyHint)
}

func (s *EncryptMaskStrategy) GetType() string {
	return "encrypt"
}

// NewFieldMaskProcessor 创建字段掩码处理器
func NewFieldMaskProcessor(logger *logging.MiddlewareLogger) *FieldMaskProcessor {
	processor := &FieldMaskProcessor{
		logger:          logger,
		maskStrategies:  make(map[string]MaskStrategy),
		sensitiveFields: make(map[string]SensitivityLevel),
	}
	
	// 初始化内置掩码策略
	processor.initBuiltinStrategies()
	
	// 初始化默认敏感字段配置
	processor.initDefaultSensitiveFields()
	
	logger.Info("field mask processor initialized")
	return processor
}

// initBuiltinStrategies 初始化内置掩码策略
func (p *FieldMaskProcessor) initBuiltinStrategies() {
	p.maskStrategies["none"] = &NoneMaskStrategy{}
	p.maskStrategies["partial"] = &PartialMaskStrategy{keepStart: 1, keepEnd: 1}
	p.maskStrategies["partial_phone"] = &PartialMaskStrategy{keepStart: 3, keepEnd: 4}
	p.maskStrategies["partial_email"] = &PartialMaskStrategy{keepStart: 2, keepEnd: 0}
	p.maskStrategies["full"] = &FullMaskStrategy{replacement: "***"}
	p.maskStrategies["hash"] = &HashMaskStrategy{algorithm: "md5"}
	p.maskStrategies["encrypt"] = &EncryptMaskStrategy{keyHint: "AES256"}
}

// initDefaultSensitiveFields 初始化默认敏感字段配置
func (p *FieldMaskProcessor) initDefaultSensitiveFields() {
	// 关键敏感字段
	criticalFields := []string{
		"password", "passwd", "pwd", "secret", "private_key", "access_token", "refresh_token",
		"api_key", "secret_key", "private", "confidential",
	}
	for _, field := range criticalFields {
		p.sensitiveFields[field] = SensitivityCritical
	}
	
	// 高敏感字段
	highFields := []string{
		"id_card", "ssn", "social_security", "credit_card", "bank_account", "account_number",
		"passport", "driver_license", "medical_record",
	}
	for _, field := range highFields {
		p.sensitiveFields[field] = SensitivityHigh
	}
	
	// 中等敏感字段
	mediumFields := []string{
		"phone", "mobile", "telephone", "email", "address", "home_address", "work_address",
		"birth_date", "birthday", "age", "salary", "income",
	}
	for _, field := range mediumFields {
		p.sensitiveFields[field] = SensitivityMedium
	}
	
	// 低敏感字段
	lowFields := []string{
		"nickname", "real_name", "full_name", "gender", "department", "position", "title",
	}
	for _, field := range lowFields {
		p.sensitiveFields[field] = SensitivityLow
	}
}

// ProcessFieldMasks 处理字段掩码
func (p *FieldMaskProcessor) ProcessFieldMasks(ctx context.Context, data interface{}, fieldMasks map[string]string) interface{} {
	if len(fieldMasks) == 0 {
		return data
	}
	
	return p.applyMasksToValue(ctx, data, fieldMasks, "")
}

// applyMasksToValue 对值应用掩码
func (p *FieldMaskProcessor) applyMasksToValue(ctx context.Context, value interface{}, fieldMasks map[string]string, fieldPath string) interface{} {
	if value == nil {
		return value
	}
	
	v := reflect.ValueOf(value)
	
	// 处理指针
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return value
		}
		elem := v.Elem()
		maskedElem := p.applyMasksToValue(ctx, elem.Interface(), fieldMasks, fieldPath)
		
		// 创建新的指针
		newPtr := reflect.New(elem.Type())
		newPtr.Elem().Set(reflect.ValueOf(maskedElem))
		return newPtr.Interface()
	}
	
	switch v.Kind() {
	case reflect.Struct:
		return p.applyMasksToStruct(ctx, value, fieldMasks, fieldPath)
	case reflect.Slice, reflect.Array:
		return p.applyMasksToSlice(ctx, value, fieldMasks, fieldPath)
	case reflect.Map:
		return p.applyMasksToMap(ctx, value, fieldMasks, fieldPath)
	default:
		// 对于基本类型，检查是否有对应的掩码
		if maskType, exists := fieldMasks[fieldPath]; exists {
			return p.applyMask(ctx, value, maskType)
		}
		return value
	}
}

// applyMasksToStruct 对结构体应用掩码
func (p *FieldMaskProcessor) applyMasksToStruct(ctx context.Context, value interface{}, fieldMasks map[string]string, basePath string) interface{} {
	v := reflect.ValueOf(value)
	t := reflect.TypeOf(value)
	
	// 创建新的结构体实例
	newStruct := reflect.New(t).Elem()
	
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		
		// 跳过未导出的字段
		if !field.CanInterface() {
			continue
		}
		
		// 构建字段路径
		fieldName := fieldType.Name
		if jsonTag := fieldType.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			// 使用JSON标签作为字段名
			if commaIdx := strings.Index(jsonTag, ","); commaIdx > 0 {
				fieldName = jsonTag[:commaIdx]
			} else {
				fieldName = jsonTag
			}
		}
		
		var fieldPath string
		if basePath == "" {
			fieldPath = strings.ToLower(fieldName)
		} else {
			fieldPath = basePath + "." + strings.ToLower(fieldName)
		}
		
		// 递归处理字段值
		maskedValue := p.applyMasksToValue(ctx, field.Interface(), fieldMasks, fieldPath)
		
		// 设置新值
		if newStruct.Field(i).CanSet() {
			newStruct.Field(i).Set(reflect.ValueOf(maskedValue))
		}
	}
	
	return newStruct.Interface()
}

// applyMasksToSlice 对切片应用掩码
func (p *FieldMaskProcessor) applyMasksToSlice(ctx context.Context, value interface{}, fieldMasks map[string]string, fieldPath string) interface{} {
	v := reflect.ValueOf(value)
	
	// 创建新的切片
	newSlice := reflect.MakeSlice(v.Type(), v.Len(), v.Cap())
	
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		maskedElem := p.applyMasksToValue(ctx, elem.Interface(), fieldMasks, fieldPath)
		newSlice.Index(i).Set(reflect.ValueOf(maskedElem))
	}
	
	return newSlice.Interface()
}

// applyMasksToMap 对映射应用掩码
func (p *FieldMaskProcessor) applyMasksToMap(ctx context.Context, value interface{}, fieldMasks map[string]string, basePath string) interface{} {
	v := reflect.ValueOf(value)
	
	// 创建新的映射
	newMap := reflect.MakeMap(v.Type())
	
	for _, key := range v.MapKeys() {
		mapValue := v.MapIndex(key)
		
		// 构建字段路径
		keyStr := fmt.Sprintf("%v", key.Interface())
		var fieldPath string
		if basePath == "" {
			fieldPath = strings.ToLower(keyStr)
		} else {
			fieldPath = basePath + "." + strings.ToLower(keyStr)
		}
		
		maskedValue := p.applyMasksToValue(ctx, mapValue.Interface(), fieldMasks, fieldPath)
		newMap.SetMapIndex(key, reflect.ValueOf(maskedValue))
	}
	
	return newMap.Interface()
}

// applyMask 应用具体的掩码
func (p *FieldMaskProcessor) applyMask(ctx context.Context, value interface{}, maskType string) interface{} {
	strategy, exists := p.maskStrategies[maskType]
	if !exists {
		p.logger.WithContext(ctx).WithField("mask_type", maskType).Warn("unknown mask type, using full mask")
		strategy = p.maskStrategies["full"]
	}
	
	return strategy.Apply(value)
}

// CheckFieldAccess 检查字段访问权限
func (p *FieldMaskProcessor) CheckFieldAccess(ctx context.Context, fieldName string, userRoles []string) bool {
	// 获取字段敏感度
	sensitivity := p.getFieldSensitivity(fieldName)
	
	// 根据用户角色和字段敏感度判断访问权限
	return p.hasAccessToSensitivityLevel(userRoles, sensitivity)
}

// getFieldSensitivity 获取字段敏感度
func (p *FieldMaskProcessor) getFieldSensitivity(fieldName string) SensitivityLevel {
	fieldName = strings.ToLower(fieldName)
	
	// 精确匹配
	if sensitivity, exists := p.sensitiveFields[fieldName]; exists {
		return sensitivity
	}
	
	// 模糊匹配
	for pattern, sensitivity := range p.sensitiveFields {
		if strings.Contains(fieldName, pattern) {
			return sensitivity
		}
	}
	
	return SensitivityNone
}

// hasAccessToSensitivityLevel 检查角色是否有访问指定敏感度的权限
func (p *FieldMaskProcessor) hasAccessToSensitivityLevel(userRoles []string, sensitivity SensitivityLevel) bool {
	// 角色权限等级映射
	roleAccessLevels := map[string]SensitivityLevel{
		"super_admin": SensitivityCritical,
		"admin":       SensitivityHigh,
		"manager":     SensitivityMedium,
		"user":        SensitivityLow,
		"readonly":    SensitivityNone,
	}
	
	// 获取用户的最高权限等级
	maxAccessLevel := SensitivityNone
	for _, role := range userRoles {
		if accessLevel, exists := roleAccessLevels[role]; exists {
			if accessLevel > maxAccessLevel {
				maxAccessLevel = accessLevel
			}
		}
	}
	
	return maxAccessLevel >= sensitivity
}

// GetRecommendedMaskType 获取推荐的掩码类型
func (p *FieldMaskProcessor) GetRecommendedMaskType(fieldName string, userRoles []string) string {
	sensitivity := p.getFieldSensitivity(fieldName)
	hasAccess := p.hasAccessToSensitivityLevel(userRoles, sensitivity)
	
	if hasAccess {
		return "none"
	}
	
	// 根据敏感度推荐掩码类型
	switch sensitivity {
	case SensitivityCritical:
		return "full"
	case SensitivityHigh:
		return "encrypt"
	case SensitivityMedium:
		if strings.Contains(strings.ToLower(fieldName), "phone") {
			return "partial_phone"
		}
		if strings.Contains(strings.ToLower(fieldName), "email") {
			return "partial_email"
		}
		return "partial"
	case SensitivityLow:
		return "partial"
	default:
		return "none"
	}
}

// RegisterCustomMaskStrategy 注册自定义掩码策略
func (p *FieldMaskProcessor) RegisterCustomMaskStrategy(name string, strategy MaskStrategy) {
	p.maskStrategies[name] = strategy
	p.logger.WithField("strategy_name", name).Info("custom mask strategy registered")
}

// SetFieldSensitivity 设置字段敏感度
func (p *FieldMaskProcessor) SetFieldSensitivity(fieldName string, sensitivity SensitivityLevel) {
	p.sensitiveFields[strings.ToLower(fieldName)] = sensitivity
}

// GetStats 获取字段掩码处理器统计信息
func (p *FieldMaskProcessor) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"mask_strategies_count":  len(p.maskStrategies),
		"sensitive_fields_count": len(p.sensitiveFields),
	}
	
	// 统计各敏感度级别的字段数量
	sensitivityCounts := make(map[string]int)
	for _, sensitivity := range p.sensitiveFields {
		switch sensitivity {
		case SensitivityNone:
			sensitivityCounts["none"]++
		case SensitivityLow:
			sensitivityCounts["low"]++
		case SensitivityMedium:
			sensitivityCounts["medium"]++
		case SensitivityHigh:
			sensitivityCounts["high"]++
		case SensitivityCritical:
			sensitivityCounts["critical"]++
		}
	}
	stats["sensitivity_distribution"] = sensitivityCounts
	
	return stats
}

// ProcessJSONResponse 处理JSON响应中的字段掩码
func (p *FieldMaskProcessor) ProcessJSONResponse(ctx context.Context, jsonData []byte, fieldMasks map[string]string) ([]byte, error) {
	if len(fieldMasks) == 0 {
		return jsonData, nil
	}
	
	var data interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	
	maskedData := p.ProcessFieldMasks(ctx, data, fieldMasks)
	
	maskedJSON, err := json.Marshal(maskedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal masked data: %w", err)
	}
	
	return maskedJSON, nil
}