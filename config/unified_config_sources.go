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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
	"gopkg.in/yaml.v3"
)

// EnvUnifiedConfigSource 环境变量配置源
type EnvUnifiedConfigSource struct {
	prefix   string
	priority int
}

// NewEnvUnifiedConfigSource 创建环境变量配置源
func NewEnvUnifiedConfigSource(options ...EnvOption) *EnvUnifiedConfigSource {
	source := &EnvUnifiedConfigSource{
		prefix:   "NEWBEE_",
		priority: 100,
	}

	for _, opt := range options {
		opt(source)
	}

	return source
}

type EnvOption func(*EnvUnifiedConfigSource)

func WithEnvPrefix(prefix string) EnvOption {
	return func(source *EnvUnifiedConfigSource) {
		source.prefix = prefix
	}
}

func WithEnvPriority(priority int) EnvOption {
	return func(source *EnvUnifiedConfigSource) {
		source.priority = priority
	}
}

func (e *EnvUnifiedConfigSource) Load(ctx context.Context) (map[string]interface{}, error) {
	configs := make(map[string]interface{})

	environ := os.Environ()
	for _, env := range environ {
		if strings.HasPrefix(env, e.prefix) {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimPrefix(parts[0], e.prefix))
				key = strings.ReplaceAll(key, "_", ".")
				configs[key] = parts[1]
			}
		}
	}

	return configs, nil
}

func (e *EnvUnifiedConfigSource) Watch(ctx context.Context, callback func(map[string]interface{})) error {
	// 环境变量通常不需要监听变化
	return nil
}

func (e *EnvUnifiedConfigSource) Priority() int {
	return e.priority
}

// FileUnifiedConfigSource 文件配置源
type FileUnifiedConfigSource struct {
	filePath string
	format   string
	priority int
}

// NewFileUnifiedConfigSource 创建文件配置源
func NewFileUnifiedConfigSource(filePath string, options ...FileOption) *FileUnifiedConfigSource {
	ext := strings.ToLower(filepath.Ext(filePath))
	format := "json"

	switch ext {
	case ".yaml", ".yml":
		format = "yaml"
	case ".json":
		format = "json"
	}

	source := &FileUnifiedConfigSource{
		filePath: filePath,
		format:   format,
		priority: 50,
	}

	for _, opt := range options {
		opt(source)
	}

	return source
}

type FileOption func(*FileUnifiedConfigSource)

func WithFileFormat(format string) FileOption {
	return func(source *FileUnifiedConfigSource) {
		source.format = format
	}
}

func WithFilePriority(priority int) FileOption {
	return func(source *FileUnifiedConfigSource) {
		source.priority = priority
	}
}

func (f *FileUnifiedConfigSource) Load(ctx context.Context) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(f.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", f.filePath, err)
	}

	var configs map[string]interface{}

	switch f.format {
	case "json":
		err = json.Unmarshal(data, &configs)
	case "yaml":
		err = yaml.Unmarshal(data, &configs)
	default:
		err = fmt.Errorf("unsupported config format: %s", f.format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", f.filePath, err)
	}

	// 扁平化嵌套配置
	return f.flattenMap("", configs), nil
}

func (f *FileUnifiedConfigSource) Watch(ctx context.Context, callback func(map[string]interface{})) error {
	// 实现文件监听逻辑
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		var lastModTime time.Time
		if stat, err := os.Stat(f.filePath); err == nil {
			lastModTime = stat.ModTime()
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if stat, err := os.Stat(f.filePath); err == nil {
					if stat.ModTime().After(lastModTime) {
						lastModTime = stat.ModTime()
						if configs, err := f.Load(ctx); err == nil {
							callback(configs)
						} else {
							logx.Errorw("Failed to reload config file",
								logx.Field("file", f.filePath),
								logx.Field("error", err))
						}
					}
				}
			}
		}
	}()

	return nil
}

func (f *FileUnifiedConfigSource) Priority() int {
	return f.priority
}

// flattenMap 扁平化嵌套 map
func (f *FileUnifiedConfigSource) flattenMap(prefix string, m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range m {
		newKey := key
		if prefix != "" {
			newKey = prefix + "." + key
		}

		if subMap, ok := value.(map[string]interface{}); ok {
			// 递归处理嵌套 map
			for k, v := range f.flattenMap(newKey, subMap) {
				result[k] = v
			}
		} else {
			result[newKey] = value
		}
	}

	return result
}

// MemoryUnifiedConfigSource 内存配置源
type MemoryUnifiedConfigSource struct {
	configs  map[string]interface{}
	priority int
}

// NewMemoryUnifiedConfigSource 创建内存配置源
func NewMemoryUnifiedConfigSource(configs map[string]interface{}, priority int) *MemoryUnifiedConfigSource {
	return &MemoryUnifiedConfigSource{
		configs:  configs,
		priority: priority,
	}
}

func (m *MemoryUnifiedConfigSource) Load(ctx context.Context) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for k, v := range m.configs {
		result[k] = v
	}
	return result, nil
}

func (m *MemoryUnifiedConfigSource) Watch(ctx context.Context, callback func(map[string]interface{})) error {
	// 内存配置源通常不需要监听
	return nil
}

func (m *MemoryUnifiedConfigSource) Priority() int {
	return m.priority
}

// RemoteUnifiedConfigSource 远程配置源接口
type RemoteUnifiedConfigSource interface {
	UnifiedConfigSource
	SetEndpoint(endpoint string)
	SetAuth(token string)
}

// HTTPUnifiedConfigSource HTTP 远程配置源
type HTTPUnifiedConfigSource struct {
	endpoint string
	token    string
	priority int
	format   string
}

// NewHTTPUnifiedConfigSource 创建 HTTP 配置源
func NewHTTPUnifiedConfigSource(endpoint string, options ...HTTPOption) *HTTPUnifiedConfigSource {
	source := &HTTPUnifiedConfigSource{
		endpoint: endpoint,
		priority: 75,
		format:   "json",
	}

	for _, opt := range options {
		opt(source)
	}

	return source
}

type HTTPOption func(*HTTPUnifiedConfigSource)

func WithHTTPToken(token string) HTTPOption {
	return func(source *HTTPUnifiedConfigSource) {
		source.token = token
	}
}

func WithHTTPPriority(priority int) HTTPOption {
	return func(source *HTTPUnifiedConfigSource) {
		source.priority = priority
	}
}

func WithHTTPFormat(format string) HTTPOption {
	return func(source *HTTPUnifiedConfigSource) {
		source.format = format
	}
}

func (h *HTTPUnifiedConfigSource) SetEndpoint(endpoint string) {
	h.endpoint = endpoint
}

func (h *HTTPUnifiedConfigSource) SetAuth(token string) {
	h.token = token
}

func (h *HTTPUnifiedConfigSource) Load(ctx context.Context) (map[string]interface{}, error) {
	// TODO: 实现 HTTP 请求逻辑
	// 这里只是示例，实际实现需要添加 HTTP 客户端
	logx.Infow("Loading config from HTTP endpoint", logx.Field("endpoint", h.endpoint))
	return make(map[string]interface{}), nil
}

func (h *HTTPUnifiedConfigSource) Watch(ctx context.Context, callback func(map[string]interface{})) error {
	// TODO: 实现 HTTP 长连接或轮询监听
	return nil
}

func (h *HTTPUnifiedConfigSource) Priority() int {
	return h.priority
}

// DefaultUnifiedConfigSources 默认配置源
func GetDefaultUnifiedConfigSources() []UnifiedConfigSource {
	sources := make([]UnifiedConfigSource, 0)

	// 1. 默认值（最低优先级）
	defaults := map[string]interface{}{
		"app.name":        "newbee",
		"app.version":     "1.0.0",
		"app.environment": "development",
		"server.port":     8080,
		"server.host":     "0.0.0.0",
		"log.level":       "info",
		"cache.enabled":   true,
		"cache.ttl":       "5m",
	}
	sources = append(sources, NewMemoryUnifiedConfigSource(defaults, 10))

	// 2. 配置文件
	configFiles := []string{
		"config.yaml",
		"config.yml",
		"config.json",
		"app.yaml",
		"app.yml",
		"app.json",
	}

	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			sources = append(sources, NewFileUnifiedConfigSource(file, WithFilePriority(50)))
			break
		}
	}

	// 3. 环境变量（最高优先级）
	sources = append(sources, NewEnvUnifiedConfigSource(WithEnvPriority(100)))

	return sources
}
