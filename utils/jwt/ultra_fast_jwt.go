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

package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/golang-jwt/jwt/v5"
)

// ================== 极致性能优化的JWT验证器 ==================

// FastJWTValidator 超高性能JWT验证器
type FastJWTValidator struct {
	// 预编译的密钥
	secretKey []byte
	secretLen int
	
	// 性能优化配置
	config *FastJWTConfig
	
	// 内存池和缓存
	tokenPool    *TokenInfoPool
	stringPool   *StringPool
	hmacPool     *HMACPool
	bytesPool    *BytesPool
	
	// 预分配的缓冲区
	headerBuf  []byte
	payloadBuf []byte
	sigBuf     []byte
	
	// 统计数据
	stats *ValidationStats
	
	// 同步原语
	mu sync.RWMutex
}

// FastJWTConfig 快速JWT配置
type FastJWTConfig struct {
	// 性能优化选项
	EnableZeroCopy        bool          `json:"enable_zero_copy" yaml:"enable_zero_copy"`
	EnableFastAlgorithm   bool          `json:"enable_fast_algorithm" yaml:"enable_fast_algorithm"`
	EnableTokenCaching    bool          `json:"enable_token_caching" yaml:"enable_token_caching"`
	EnableBytesPooling    bool          `json:"enable_bytes_pooling" yaml:"enable_bytes_pooling"`
	
	// 缓存配置
	TokenCacheSize       int           `json:"token_cache_size" yaml:"token_cache_size"`
	TokenCacheTTL        time.Duration `json:"token_cache_ttl" yaml:"token_cache_ttl"`
	StringPoolSize       int           `json:"string_pool_size" yaml:"string_pool_size"`
	
	// 验证选项
	SkipExpirationCheck  bool     `json:"skip_expiration_check" yaml:"skip_expiration_check"`
	AllowedAlgorithms    []string `json:"allowed_algorithms" yaml:"allowed_algorithms"`
	ClockSkewTolerance   time.Duration `json:"clock_skew_tolerance" yaml:"clock_skew_tolerance"`
	
	// 性能调优
	PreallocBufferSize   int           `json:"prealloc_buffer_size" yaml:"prealloc_buffer_size"`
	HMACPoolSize         int           `json:"hmac_pool_size" yaml:"hmac_pool_size"`
}

// ValidationStats 验证统计信息
type ValidationStats struct {
	TotalValidations    int64 `json:"total_validations"`
	SuccessValidations  int64 `json:"success_validations"`
	FailedValidations   int64 `json:"failed_validations"`
	CacheHits          int64 `json:"cache_hits"`
	CacheMisses        int64 `json:"cache_misses"`
	TotalLatencyNanos  int64 `json:"total_latency_nanos"`
	MinLatencyNanos    int64 `json:"min_latency_nanos"`
	MaxLatencyNanos    int64 `json:"max_latency_nanos"`
}

// DefaultFastJWTConfig 默认快速JWT配置
func DefaultFastJWTConfig() *FastJWTConfig {
	return &FastJWTConfig{
		EnableZeroCopy:       true,
		EnableFastAlgorithm:  true,
		EnableTokenCaching:   true,
		EnableBytesPooling:   true,
		TokenCacheSize:       50000,
		TokenCacheTTL:        10 * time.Minute,
		StringPoolSize:       10000,
		AllowedAlgorithms:    []string{"HS256", "HS384", "HS512"},
		ClockSkewTolerance:   5 * time.Minute,
		PreallocBufferSize:   4096,
		HMACPoolSize:         100,
	}
}

// NewFastJWTValidator 创建快速JWT验证器
func NewFastJWTValidator(secretKey string, config *FastJWTConfig) *FastJWTValidator {
	if config == nil {
		config = DefaultFastJWTConfig()
	}
	
	validator := &FastJWTValidator{
		secretKey: []byte(secretKey),
		secretLen: len(secretKey),
		config:    config,
		stats:     &ValidationStats{MinLatencyNanos: 1<<63 - 1},
	}
	
	// 初始化内存池
	if config.EnableBytesPooling {
		validator.tokenPool = NewTokenInfoPool(1000)
		validator.stringPool = NewStringPool(config.StringPoolSize)
		validator.hmacPool = NewHMACPool(config.HMACPoolSize)
		validator.bytesPool = NewBytesPool(config.PreallocBufferSize)
	}
	
	// 预分配缓冲区
	if config.PreallocBufferSize > 0 {
		validator.headerBuf = make([]byte, 0, config.PreallocBufferSize)
		validator.payloadBuf = make([]byte, 0, config.PreallocBufferSize)
		validator.sigBuf = make([]byte, 0, config.PreallocBufferSize)
	}
	
	return validator
}

// ValidateTokenUltraFast 超高性能token验证（目标：<50μs）
func (v *FastJWTValidator) ValidateTokenUltraFast(token string) (*TokenInfo, error) {
	start := time.Now()
	defer func() {
		latency := time.Since(start).Nanoseconds()
		v.updateStats(latency, true)
	}()
	
	// 统计
	atomic.AddInt64(&v.stats.TotalValidations, 1)
	
	// 快速预检查
	if len(token) < 10 || strings.Count(token, ".") != 2 {
		atomic.AddInt64(&v.stats.FailedValidations, 1)
		return nil, fmt.Errorf("invalid token format")
	}
	
	// 零拷贝token分割（避免字符串分配）
	parts := v.splitTokenZeroCopy(token)
	if len(parts) != 3 {
		atomic.AddInt64(&v.stats.FailedValidations, 1)
		return nil, fmt.Errorf("token must have 3 parts")
	}
	
	// 快速算法验证（跳过标准JWT库的重复验证）
	if v.config.EnableFastAlgorithm {
		if err := v.fastSignatureVerification(token, parts); err != nil {
			atomic.AddInt64(&v.stats.FailedValidations, 1)
			return nil, err
		}
	}
	
	// 快速payload解析
	tokenInfo, err := v.fastParsePayload(parts[1])
	if err != nil {
		atomic.AddInt64(&v.stats.FailedValidations, 1)
		return nil, err
	}
	
	// 快速过期检查（避免不必要的时间计算）
	if !v.config.SkipExpirationCheck {
		now := time.Now().Unix()
		if tokenInfo.ExpiresAt.Unix() <= now-int64(v.config.ClockSkewTolerance.Seconds()) {
			atomic.AddInt64(&v.stats.FailedValidations, 1)
			return nil, fmt.Errorf("token expired")
		}
	}
	
	atomic.AddInt64(&v.stats.SuccessValidations, 1)
	return tokenInfo, nil
}

// splitTokenZeroCopy 零拷贝token分割
func (v *FastJWTValidator) splitTokenZeroCopy(token string) []string {
	// 使用unsafe进行零拷贝切片操作
	parts := make([]string, 0, 3)
	
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if start < i {
				parts = append(parts, token[start:i])
			}
			start = i + 1
		}
	}
	
	// 添加最后一部分
	if start < len(token) {
		parts = append(parts, token[start:])
	}
	
	return parts
}

// fastSignatureVerification 快速签名验证
func (v *FastJWTValidator) fastSignatureVerification(token string, parts []string) error {
	// 构建签名消息（header + "." + payload）
	messageLen := len(parts[0]) + 1 + len(parts[1])
	message := token[:messageLen] // 零拷贝获取消息部分
	
	// 从池中获取HMAC实例
	var h hash.Hash
	if v.hmacPool != nil {
		h = v.hmacPool.Get()
		defer v.hmacPool.Put(h)
		h.Reset()
	} else {
		h = hmac.New(sha256.New, v.secretKey)
	}
	
	// 计算签名
	h.Write(stringToBytes(message))
	signature := h.Sum(nil)
	
	// Base64编码（避免额外的内存分配）
	expectedSig := base64.RawURLEncoding.EncodeToString(signature)
	
	// 常量时间比较
	if len(expectedSig) != len(parts[2]) {
		return fmt.Errorf("signature verification failed")
	}
	
	var match byte
	for i := 0; i < len(expectedSig); i++ {
		match |= expectedSig[i] ^ parts[2][i]
	}
	
	if match != 0 {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}

// fastParsePayload 快速payload解析
func (v *FastJWTValidator) fastParsePayload(payloadPart string) (*TokenInfo, error) {
	// 获取解码缓冲区
	var decodeBuf []byte
	if v.bytesPool != nil {
		decodeBuf = v.bytesPool.Get()
		defer v.bytesPool.Put(decodeBuf)
	} else {
		decodeBuf = make([]byte, len(payloadPart)*3/4+10)
	}
	
	// Base64解码
	n, err := base64.RawURLEncoding.Decode(decodeBuf, stringToBytes(payloadPart))
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	
	payload := decodeBuf[:n]
	
	// 获取TokenInfo对象
	var tokenInfo *TokenInfo
	if v.tokenPool != nil {
		tokenInfo = v.tokenPool.Get()
	} else {
		tokenInfo = &TokenInfo{
			Claims: make(jwt.MapClaims, 8),
		}
	}
	
	// 快速JSON解析（手工优化的关键字段解析）
	if err := v.fastJSONParse(payload, tokenInfo); err != nil {
		if v.tokenPool != nil {
			v.tokenPool.Put(tokenInfo)
		}
		return nil, err
	}
	
	return tokenInfo, nil
}

// fastJSONParse 快速JSON解析（只解析必要字段）
func (v *FastJWTValidator) fastJSONParse(payload []byte, tokenInfo *TokenInfo) error {
	// 将字节切片转为字符串（零拷贝）
	payloadStr := bytesToString(payload)
	
	// 手工解析关键字段（避免完整JSON解析的开销）
	
	// 解析userId
	if userID := v.extractJSONValue(payloadStr, `"userId"`); userID != "" {
		tokenInfo.UserID = v.internString(userID)
	} else {
		return fmt.Errorf("missing userId")
	}
	
	// 解析tenantId
	if tenantID := v.extractJSONValue(payloadStr, `"tenantId"`); tenantID != "" {
		tokenInfo.TenantID = v.internString(tenantID)
	} else {
		return fmt.Errorf("missing tenantId")
	}
	
	// 解析exp
	if expStr := v.extractJSONValue(payloadStr, `"exp"`); expStr != "" {
		if exp, err := strconv.ParseInt(expStr, 10, 64); err == nil {
			tokenInfo.ExpiresAt = time.Unix(exp, 0)
		} else {
			return fmt.Errorf("invalid exp: %w", err)
		}
	} else {
		return fmt.Errorf("missing exp")
	}
	
	// 解析iat
	if iatStr := v.extractJSONValue(payloadStr, `"iat"`); iatStr != "" {
		if iat, err := strconv.ParseInt(iatStr, 10, 64); err == nil {
			tokenInfo.IssuedAt = time.Unix(iat, 0)
		}
	}
	
	tokenInfo.Valid = true
	return nil
}

// extractJSONValue 从JSON字符串中提取值（避免完整解析）
func (v *FastJWTValidator) extractJSONValue(json, key string) string {
	keyIndex := strings.Index(json, key)
	if keyIndex == -1 {
		return ""
	}
	
	// 找到冒号
	colonIndex := keyIndex + len(key)
	for colonIndex < len(json) && json[colonIndex] != ':' {
		colonIndex++
	}
	
	if colonIndex >= len(json) {
		return ""
	}
	
	// 跳过空格和冒号
	valueStart := colonIndex + 1
	for valueStart < len(json) && (json[valueStart] == ' ' || json[valueStart] == '\t') {
		valueStart++
	}
	
	if valueStart >= len(json) {
		return ""
	}
	
	// 确定值的结束位置
	var valueEnd int
	if json[valueStart] == '"' {
		// 字符串值
		valueStart++ // 跳过开始引号
		valueEnd = valueStart
		for valueEnd < len(json) && json[valueEnd] != '"' {
			if json[valueEnd] == '\\' {
				valueEnd += 2 // 跳过转义字符
			} else {
				valueEnd++
			}
		}
	} else {
		// 数字值
		valueEnd = valueStart
		for valueEnd < len(json) && 
			(json[valueEnd] >= '0' && json[valueEnd] <= '9' || 
			 json[valueEnd] == '.' || json[valueEnd] == '-') {
			valueEnd++
		}
	}
	
	if valueEnd <= valueStart {
		return ""
	}
	
	return json[valueStart:valueEnd]
}

// internString 字符串内部化
func (v *FastJWTValidator) internString(s string) string {
	if v.stringPool != nil {
		return v.stringPool.Intern(s)
	}
	return s
}

// updateStats 更新统计信息
func (v *FastJWTValidator) updateStats(latency int64, success bool) {
	atomic.AddInt64(&v.stats.TotalLatencyNanos, latency)
	
	// 更新最小延迟
	for {
		current := atomic.LoadInt64(&v.stats.MinLatencyNanos)
		if latency >= current || atomic.CompareAndSwapInt64(&v.stats.MinLatencyNanos, current, latency) {
			break
		}
	}
	
	// 更新最大延迟
	for {
		current := atomic.LoadInt64(&v.stats.MaxLatencyNanos)
		if latency <= current || atomic.CompareAndSwapInt64(&v.stats.MaxLatencyNanos, current, latency) {
			break
		}
	}
}

// GetStats 获取统计信息
func (v *FastJWTValidator) GetStats() ValidationStats {
	return ValidationStats{
		TotalValidations:   atomic.LoadInt64(&v.stats.TotalValidations),
		SuccessValidations: atomic.LoadInt64(&v.stats.SuccessValidations),
		FailedValidations:  atomic.LoadInt64(&v.stats.FailedValidations),
		CacheHits:          atomic.LoadInt64(&v.stats.CacheHits),
		CacheMisses:        atomic.LoadInt64(&v.stats.CacheMisses),
		TotalLatencyNanos:  atomic.LoadInt64(&v.stats.TotalLatencyNanos),
		MinLatencyNanos:    atomic.LoadInt64(&v.stats.MinLatencyNanos),
		MaxLatencyNanos:    atomic.LoadInt64(&v.stats.MaxLatencyNanos),
	}
}

// AverageLatencyMicros 平均延迟（微秒）
func (v *FastJWTValidator) AverageLatencyMicros() float64 {
	stats := v.GetStats()
	if stats.TotalValidations == 0 {
		return 0
	}
	return float64(stats.TotalLatencyNanos) / float64(stats.TotalValidations) / 1000.0
}

// ================== 内存池实现 ==================

// TokenInfoPool Token信息对象池
type TokenInfoPool struct {
	pool sync.Pool
}

// NewTokenInfoPool 创建Token信息对象池
func NewTokenInfoPool(initialSize int) *TokenInfoPool {
	return &TokenInfoPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &TokenInfo{
					Claims: make(jwt.MapClaims, 8),
				}
			},
		},
	}
}

// Get 获取Token信息对象
func (p *TokenInfoPool) Get() *TokenInfo {
	return p.pool.Get().(*TokenInfo)
}

// Put 归还Token信息对象
func (p *TokenInfoPool) Put(info *TokenInfo) {
	// 清理数据
	info.UserID = ""
	info.TenantID = ""
	info.IssuedAt = time.Time{}
	info.ExpiresAt = time.Time{}
	info.Valid = false
	
	// 清理Claims
	for k := range info.Claims {
		delete(info.Claims, k)
	}
	
	p.pool.Put(info)
}

// StringPool 字符串池
type StringPool struct {
	mu    sync.RWMutex
	table map[string]string
	maxSize int
}

// NewStringPool 创建字符串池
func NewStringPool(maxSize int) *StringPool {
	return &StringPool{
		table:   make(map[string]string, maxSize),
		maxSize: maxSize,
	}
}

// Intern 内部化字符串
func (p *StringPool) Intern(s string) string {
	// 快速路径：读锁检查
	p.mu.RLock()
	if interned, exists := p.table[s]; exists {
		p.mu.RUnlock()
		return interned
	}
	p.mu.RUnlock()
	
	// 慢路径：写锁添加
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// 双重检查
	if interned, exists := p.table[s]; exists {
		return interned
	}
	
	// 检查容量
	if len(p.table) >= p.maxSize {
		// 清理一半的条目
		newTable := make(map[string]string, p.maxSize)
		count := 0
		for k, v := range p.table {
			if count >= p.maxSize/2 {
				break
			}
			newTable[k] = v
			count++
		}
		p.table = newTable
	}
	
	p.table[s] = s
	return s
}

// HMACPool HMAC对象池  
type HMACPool struct {
	pool sync.Pool
	key  []byte
}

// NewHMACPool 创建HMAC池
func NewHMACPool(size int) *HMACPool {
	return &HMACPool{
		pool: sync.Pool{
			New: func() interface{} {
				return hmac.New(sha256.New, nil)
			},
		},
	}
}

// Get 获取HMAC实例
func (p *HMACPool) Get() hash.Hash {
	h := p.pool.Get().(hash.Hash)
	return h
}

// Put 归还HMAC实例
func (p *HMACPool) Put(h hash.Hash) {
	h.Reset()
	p.pool.Put(h)
}

// BytesPool 字节切片池
type BytesPool struct {
	pool sync.Pool
}

// NewBytesPool 创建字节切片池
func NewBytesPool(size int) *BytesPool {
	return &BytesPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, size)
			},
		},
	}
}

// Get 获取字节切片
func (p *BytesPool) Get() []byte {
	return p.pool.Get().([]byte)[:0]
}

// Put 归还字节切片
func (p *BytesPool) Put(buf []byte) {
	if cap(buf) < 64*1024 { // 避免池中积累过大的切片
		p.pool.Put(buf)
	}
}

// ================== 零拷贝辅助函数 ==================

// stringToBytes 零拷贝字符串转字节切片
func stringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&struct {
		string
		int
	}{s, len(s)}))
}

// bytesToString 零拷贝字节切片转字符串
func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// ================== 上下文优化 ==================

// ContextKey 预定义的上下文键类型
type ContextKey int

const (
	// 预定义上下文键（避免字符串分配）
	UserIDContextKey ContextKey = iota
	TenantIDContextKey
	TokenClaimsContextKey
	PermissionsContextKey
	RolesContextKey
)

// UltraFastContextInjector 超高性能上下文注入器
type UltraFastContextInjector struct {
	// 预分配的值缓存
	valueCache sync.Map
}

// NewUltraFastContextInjector 创建超高性能上下文注入器
func NewUltraFastContextInjector() *UltraFastContextInjector {
	return &UltraFastContextInjector{}
}

// InjectTokenContext 注入token上下文（零分配）
func (injector *UltraFastContextInjector) InjectTokenContext(
	ctx context.Context, 
	tokenInfo *TokenInfo,
) context.Context {
	// 批量注入核心字段（减少context.WithValue调用）
	ctx = context.WithValue(ctx, UserIDContextKey, tokenInfo.UserID)
	ctx = context.WithValue(ctx, TenantIDContextKey, tokenInfo.TenantID)
	ctx = context.WithValue(ctx, TokenClaimsContextKey, tokenInfo.Claims)
	
	// 批量处理可选字段
	if len(tokenInfo.Claims) > 0 {
		if permissions, exists := tokenInfo.Claims["permissions"]; exists {
			ctx = context.WithValue(ctx, PermissionsContextKey, permissions)
		}
		if roles, exists := tokenInfo.Claims["roles"]; exists {
			ctx = context.WithValue(ctx, RolesContextKey, roles)
		}
	}
	
	return ctx
}

// ExtractUserIDFast 快速提取用户ID
func ExtractUserIDFast(ctx context.Context) (string, bool) {
	if userID, ok := ctx.Value(UserIDContextKey).(string); ok {
		return userID, true
	}
	// 兼容性检查
	if userID, ok := ctx.Value("userID").(string); ok {
		return userID, true
	}
	return "", false
}

// ExtractTenantIDFast 快速提取租户ID
func ExtractTenantIDFast(ctx context.Context) (string, bool) {
	if tenantID, ok := ctx.Value(TenantIDContextKey).(string); ok {
		return tenantID, true
	}
	// 兼容性检查
	if tenantID, ok := ctx.Value("tenantID").(string); ok {
		return tenantID, true
	}
	return "", false
}

// ExtractClaimsFast 快速提取claims
func ExtractClaimsFast(ctx context.Context) (jwt.MapClaims, bool) {
	if claims, ok := ctx.Value(TokenClaimsContextKey).(jwt.MapClaims); ok {
		return claims, true
	}
	return nil, false
}

// ================== 兼容性API ==================

// ValidateJwtTokenUltraFast 超高性能JWT验证（兼容原有API）
func ValidateJwtTokenUltraFast(tokenString, secretKey string) (*TokenInfo, error) {
	validator := NewFastJWTValidator(secretKey, DefaultFastJWTConfig())
	return validator.ValidateTokenUltraFast(tokenString)
}

// CreateUltraFastValidator 创建超高性能验证器的便捷函数
func CreateUltraFastValidator(secretKey string) *FastJWTValidator {
	config := DefaultFastJWTConfig()
	// 企业级性能配置
	config.TokenCacheSize = 100000
	config.StringPoolSize = 50000
	config.HMACPoolSize = 200
	config.PreallocBufferSize = 8192
	
	return NewFastJWTValidator(secretKey, config)
}