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
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// UnifiedConfigManager 统一配置管理器
type UnifiedConfigManager struct {
	configs map[string]interface{}
	mu      sync.RWMutex

	// 观察者模式
	observers []UnifiedConfigObserver

	// 配置来源
	sources []UnifiedConfigSource

	// 缓存配置
	cache UnifiedConfigCache

	// 默认值
	defaults map[string]interface{}
}

// UnifiedConfigObserver 配置观察者接口
type UnifiedConfigObserver interface {
	OnConfigChanged(key string, oldValue, newValue interface{})
}

// UnifiedConfigSource 配置来源接口
type UnifiedConfigSource interface {
	Load(ctx context.Context) (map[string]interface{}, error)
	Watch(ctx context.Context, callback func(map[string]interface{})) error
	Priority() int
}

// UnifiedConfigCache 配置缓存接口
type UnifiedConfigCache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
}

// NewUnifiedConfigManager 创建新的配置管理器
func NewUnifiedConfigManager(options ...ConfigOption) *UnifiedConfigManager {
	cm := &UnifiedConfigManager{
		configs:   make(map[string]interface{}),
		observers: make([]UnifiedConfigObserver, 0),
		sources:   make([]UnifiedConfigSource, 0),
		defaults:  make(map[string]interface{}),
	}

	// 应用配置选项
	for _, opt := range options {
		opt(cm)
	}

	// 初始化默认缓存
	if cm.cache == nil {
		cm.cache = NewMemoryUnifiedConfigCache()
	}

	return cm
}

// ConfigOption 配置选项
type ConfigOption func(*UnifiedConfigManager)

// WithUnifiedConfigSource 添加配置源
func WithUnifiedConfigSource(source UnifiedConfigSource) ConfigOption {
	return func(cm *UnifiedConfigManager) {
		cm.sources = append(cm.sources, source)
	}
}

// WithCache 设置缓存
func WithCache(cache UnifiedConfigCache) ConfigOption {
	return func(cm *UnifiedConfigManager) {
		cm.cache = cache
	}
}

// WithDefaults 设置默认值
func WithDefaults(defaults map[string]interface{}) ConfigOption {
	return func(cm *UnifiedConfigManager) {
		for k, v := range defaults {
			cm.defaults[k] = v
		}
	}
}

// LoadConfigs 加载所有配置源的配置
func (cm *UnifiedConfigManager) LoadConfigs(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 按优先级排序配置源
	sources := make([]UnifiedConfigSource, len(cm.sources))
	copy(sources, cm.sources)

	// 简单排序（高优先级在后，覆盖低优先级）
	for i := 0; i < len(sources)-1; i++ {
		for j := i + 1; j < len(sources); j++ {
			if sources[i].Priority() > sources[j].Priority() {
				sources[i], sources[j] = sources[j], sources[i]
			}
		}
	}

	// 加载所有配置源
	for _, source := range sources {
		configs, err := source.Load(ctx)
		if err != nil {
			logx.Errorw("Failed to load config from source", logx.Field("error", err))
			continue
		}

		// 合并配置
		for key, value := range configs {
			oldValue := cm.configs[key]
			cm.configs[key] = value

			// 通知观察者
			cm.notifyObservers(key, oldValue, value)
		}
	}

	return nil
}

// Get 获取配置值
func (cm *UnifiedConfigManager) Get(key string) interface{} {
	// 先检查缓存
	if cm.cache != nil {
		if value, exists := cm.cache.Get(key); exists {
			return value
		}
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 检查配置
	if value, exists := cm.configs[key]; exists {
		// 更新缓存
		if cm.cache != nil {
			cm.cache.Set(key, value, 5*time.Minute)
		}
		return value
	}

	// 检查默认值
	if value, exists := cm.defaults[key]; exists {
		return value
	}

	return nil
}

// GetString 获取字符串配置
func (cm *UnifiedConfigManager) GetString(key string) string {
	value := cm.Get(key)
	if value == nil {
		return ""
	}

	if str, ok := value.(string); ok {
		return str
	}

	return fmt.Sprintf("%v", value)
}

// GetInt 获取整数配置
func (cm *UnifiedConfigManager) GetInt(key string) int {
	value := cm.Get(key)
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		// 尝试解析字符串
		if strings.Contains(v, ".") {
			return 0
		}
		var result int
		fmt.Sscanf(v, "%d", &result)
		return result
	default:
		return 0
	}
}

// GetBool 获取布尔配置
func (cm *UnifiedConfigManager) GetBool(key string) bool {
	value := cm.Get(key)
	if value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.ToLower(v) == "true" || v == "1"
	case int:
		return v != 0
	default:
		return false
	}
}

// GetDuration 获取时间段配置
func (cm *UnifiedConfigManager) GetDuration(key string) time.Duration {
	value := cm.Get(key)
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case time.Duration:
		return v
	case string:
		if duration, err := time.ParseDuration(v); err == nil {
			return duration
		}
		return 0
	case int64:
		return time.Duration(v) * time.Nanosecond
	default:
		return 0
	}
}

// Set 设置配置值
func (cm *UnifiedConfigManager) Set(key string, value interface{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	oldValue := cm.configs[key]
	cm.configs[key] = value

	// 更新缓存
	if cm.cache != nil {
		cm.cache.Set(key, value, 5*time.Minute)
	}

	// 通知观察者
	cm.notifyObservers(key, oldValue, value)
}

// Delete 删除配置
func (cm *UnifiedConfigManager) Delete(key string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	oldValue := cm.configs[key]
	delete(cm.configs, key)

	// 删除缓存
	if cm.cache != nil {
		cm.cache.Delete(key)
	}

	// 通知观察者
	cm.notifyObservers(key, oldValue, nil)
}

// AddObserver 添加观察者
func (cm *UnifiedConfigManager) AddObserver(observer UnifiedConfigObserver) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.observers = append(cm.observers, observer)
}

// RemoveObserver 移除观察者
func (cm *UnifiedConfigManager) RemoveObserver(observer UnifiedConfigObserver) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, obs := range cm.observers {
		if obs == observer {
			cm.observers = append(cm.observers[:i], cm.observers[i+1:]...)
			break
		}
	}
}

// notifyObservers 通知所有观察者
func (cm *UnifiedConfigManager) notifyObservers(key string, oldValue, newValue interface{}) {
	for _, observer := range cm.observers {
		observer.OnConfigChanged(key, oldValue, newValue)
	}
}

// GetAllConfigs 获取所有配置
func (cm *UnifiedConfigManager) GetAllConfigs() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range cm.configs {
		result[k] = v
	}

	return result
}

// LoadFromStruct 从结构体加载配置
func (cm *UnifiedConfigManager) LoadFromStruct(prefix string, config interface{}) error {
	return cm.loadFromStructRecursive(prefix, reflect.ValueOf(config))
}

// loadFromStructRecursive 递归加载结构体配置
func (cm *UnifiedConfigManager) loadFromStructRecursive(prefix string, v reflect.Value) error {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fmt.Errorf("expected struct, got %v", v.Kind())
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// 跳过非导出字段
		if !fieldType.IsExported() {
			continue
		}

		// 构建配置键
		key := strings.ToLower(fieldType.Name)
		if prefix != "" {
			key = prefix + "." + key
		}

		// 检查 json tag
		if jsonTag := fieldType.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				key = parts[0]
				if prefix != "" {
					key = prefix + "." + key
				}
			}
		}

		// 递归处理嵌套结构体
		if field.Kind() == reflect.Struct || (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct) {
			if err := cm.loadFromStructRecursive(key, field); err != nil {
				return err
			}
		} else {
			cm.Set(key, field.Interface())
		}
	}

	return nil
}

// ToStruct 将配置映射到结构体
func (cm *UnifiedConfigManager) ToStruct(prefix string, config interface{}) error {
	return cm.toStructRecursive(prefix, reflect.ValueOf(config))
}

// toStructRecursive 递归映射配置到结构体
func (cm *UnifiedConfigManager) toStructRecursive(prefix string, v reflect.Value) error {
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("expected pointer to struct, got %v", v.Kind())
	}

	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("expected struct, got %v", v.Kind())
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// 跳过非导出字段
		if !fieldType.IsExported() || !field.CanSet() {
			continue
		}

		// 构建配置键
		key := strings.ToLower(fieldType.Name)
		if prefix != "" {
			key = prefix + "." + key
		}

		// 检查 json tag
		if jsonTag := fieldType.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				key = parts[0]
				if prefix != "" {
					key = prefix + "." + key
				}
			}
		}

		// 获取配置值
		configValue := cm.Get(key)
		if configValue == nil {
			continue
		}

		// 设置字段值
		if err := cm.setFieldValue(field, configValue); err != nil {
			logx.Errorw("Failed to set field value",
				logx.Field("field", fieldType.Name),
				logx.Field("key", key),
				logx.Field("error", err))
		}
	}

	return nil
}

// setFieldValue 设置字段值
func (cm *UnifiedConfigManager) setFieldValue(field reflect.Value, value interface{}) error {
	valueReflect := reflect.ValueOf(value)

	// 类型转换
	if valueReflect.Type().ConvertibleTo(field.Type()) {
		field.Set(valueReflect.Convert(field.Type()))
		return nil
	}

	// 特殊处理
	switch field.Kind() {
	case reflect.String:
		field.SetString(fmt.Sprintf("%v", value))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if intVal := cm.convertToInt64(value); intVal != 0 || value == 0 {
			field.SetInt(intVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if intVal := cm.convertToInt64(value); intVal >= 0 {
			field.SetUint(uint64(intVal))
		}
	case reflect.Float32, reflect.Float64:
		if floatVal := cm.convertToFloat64(value); !isNaN(floatVal) {
			field.SetFloat(floatVal)
		}
	case reflect.Bool:
		field.SetBool(cm.convertToBool(value))
	}

	return nil
}

// 辅助转换函数
func (cm *UnifiedConfigManager) convertToInt64(value interface{}) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		return int64(v)
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		var result int64
		fmt.Sscanf(v, "%d", &result)
		return result
	default:
		return 0
	}
}

func (cm *UnifiedConfigManager) convertToFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case float32:
		return float64(v)
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		var result float64
		fmt.Sscanf(v, "%f", &result)
		return result
	default:
		return 0.0
	}
}

func (cm *UnifiedConfigManager) convertToBool(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.ToLower(v) == "true" || v == "1"
	case int:
		return v != 0
	default:
		return false
	}
}

func isNaN(f float64) bool {
	return f != f
}

// JSON 序列化支持
func (cm *UnifiedConfigManager) MarshalJSON() ([]byte, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return json.Marshal(cm.configs)
}

func (cm *UnifiedConfigManager) UnmarshalJSON(data []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var configs map[string]interface{}
	if err := json.Unmarshal(data, &configs); err != nil {
		return err
	}

	for key, value := range configs {
		oldValue := cm.configs[key]
		cm.configs[key] = value
		cm.notifyObservers(key, oldValue, value)
	}

	return nil
}

// 全局配置管理器实例
var defaultUnifiedConfigManager = NewUnifiedConfigManager()

// 全局函数
func Get(key string) interface{} {
	return defaultUnifiedConfigManager.Get(key)
}

func GetString(key string) string {
	return defaultUnifiedConfigManager.GetString(key)
}

func GetInt(key string) int {
	return defaultUnifiedConfigManager.GetInt(key)
}

func GetBool(key string) bool {
	return defaultUnifiedConfigManager.GetBool(key)
}

func GetDuration(key string) time.Duration {
	return defaultUnifiedConfigManager.GetDuration(key)
}

func Set(key string, value interface{}) {
	defaultUnifiedConfigManager.Set(key, value)
}

func LoadConfigs(ctx context.Context) error {
	return defaultUnifiedConfigManager.LoadConfigs(ctx)
}

func LoadUnifiedConfigs(ctx context.Context) error {
	return LoadConfigs(ctx)
}

func GetUnifiedString(key string) string {
	return GetString(key)
}

func GetUnifiedInt(key string) int {
	return GetInt(key)
}

func GetUnifiedBool(key string) bool {
	return GetBool(key)
}

func AddUnifiedConfigSource(source UnifiedConfigSource) {
	defaultUnifiedConfigManager.sources = append(defaultUnifiedConfigManager.sources, source)
}

func GetDefaultUnifiedConfigManager() *UnifiedConfigManager {
	return defaultUnifiedConfigManager
}

// 初始化默认配置源
func init() {
	// 添加环境变量配置源
	AddUnifiedConfigSource(NewEnvUnifiedConfigSource())
}
