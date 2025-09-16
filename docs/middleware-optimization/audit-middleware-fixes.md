# 审计中间件优化修复方案

## 📍 位置
`/opt/code/newbee/common/middleware/audit/plugin.go`

## 🎯 修复目标
解决审计中间件的严重内存泄漏风险和性能问题，保持现有审计功能完整性不变。

## 🔍 问题分析

### P0级别问题（紧急修复）

#### 1. 内存泄漏和OOM风险
**位置**: `audit/plugin.go:81-91` 和 `audit/plugin.go:94-99`
**问题**: 无限制缓存请求/响应体到内存，大文件上传导致OOM
**影响**: 高并发或大文件场景下服务崩溃

#### 2. 同步数据库写入阻塞
**位置**: `audit/plugin.go:147-153`
**问题**: 同步写入审计日志阻塞HTTP请求处理
**影响**: 响应时间显著增长，用户体验差

#### 3. 敏感数据过滤不完善
**位置**: `audit/plugin.go:300-337`
**问题**: 简单字符串检查易绕过，无JSON结构化过滤
**风险**: 敏感信息泄露到审计日志

#### 4. 缺少资源名称缓存
**位置**: `audit/plugin.go:174-189`
**问题**: 每次请求都进行RPC调用获取资源名称
**影响**: 额外的RPC开销影响性能

## 🛠️ 修复方案

### 1. 流式请求体处理（解决内存泄漏）

```go
import (
    "crypto/md5"
    "encoding/hex"
    "io"
    "github.com/klauspost/compress/gzip"
)

// 流式请求体读取器
type StreamingBodyReader struct {
    reader     io.Reader
    maxSize    int64
    readSize   int64
    hash       hash.Hash
    sample     []byte
    sampleSize int
}

func NewStreamingBodyReader(reader io.Reader, maxSize int64) *StreamingBodyReader {
    return &StreamingBodyReader{
        reader:     reader,
        maxSize:    maxSize,
        hash:       md5.New(),
        sampleSize: 512, // 只采样前512字节
    }
}

func (s *StreamingBodyReader) Read(p []byte) (int, error) {
    n, err := s.reader.Read(p)
    if n > 0 {
        s.readSize += int64(n)
        
        // 检查大小限制
        if s.readSize > s.maxSize {
            return 0, fmt.Errorf("request body too large: %d bytes", s.readSize)
        }
        
        // 计算hash用于完整性检查
        s.hash.Write(p[:n])
        
        // 采样数据用于审计（只保存前面部分）
        if len(s.sample) < s.sampleSize {
            remaining := s.sampleSize - len(s.sample)
            if n > remaining {
                s.sample = append(s.sample, p[:remaining]...)
            } else {
                s.sample = append(s.sample, p[:n]...)
            }
        }
    }
    return n, err
}

func (s *StreamingBodyReader) GetSummary() AuditBodySummary {
    return AuditBodySummary{
        TotalSize: s.readSize,
        Hash:      hex.EncodeToString(s.hash.Sum(nil)),
        Sample:    string(s.sample),
        Truncated: s.readSize > int64(s.sampleSize),
    }
}

type AuditBodySummary struct {
    TotalSize int64  `json:"total_size"`
    Hash      string `json:"hash"`
    Sample    string `json:"sample"`
    Truncated bool   `json:"truncated"`
}

// 修改审计中间件的请求体处理
func (p *AuditPlugin) captureRequestBody(r *http.Request) (string, error) {
    if r.Body == nil || !p.shouldCaptureRequestBody(r) {
        return "", nil
    }
    
    // 获取Content-Length，设置合理的最大限制
    maxSize := int64(10 << 20) // 10MB默认限制
    if p.config.MaxBodySize > 0 {
        maxSize = p.config.MaxBodySize
    }
    
    contentLength := r.ContentLength
    if contentLength > maxSize {
        return fmt.Sprintf(`{"error":"body_too_large","size":%d,"limit":%d}`, contentLength, maxSize), nil
    }
    
    // 创建流式读取器
    streamReader := NewStreamingBodyReader(r.Body, maxSize)
    
    // 创建TeeReader，同时读取数据和恢复body
    var bodyBuffer bytes.Buffer
    teeReader := io.TeeReader(streamReader, &bodyBuffer)
    
    // 读取并处理
    _, err := io.Copy(io.Discard, teeReader)
    if err != nil {
        return fmt.Sprintf(`{"error":"read_failed","message":"%s"}`, err.Error()), nil
    }
    
    // 恢复request body供后续处理使用
    r.Body = io.NopCloser(&bodyBuffer)
    
    // 获取摘要信息而不是完整内容
    summary := streamReader.GetSummary()
    summaryJSON, _ := json.Marshal(summary)
    return p.filterSensitiveData(string(summaryJSON)), nil
}
```

### 2. 异步审计日志写入

```go
// 异步审计队列
type AsyncAuditQueue struct {
    queue       chan framework.AuditLogData
    workers     int
    auditWriter framework.AuditWriter
    ctx         context.Context
    cancel      context.CancelFunc
    wg          sync.WaitGroup
}

func NewAsyncAuditQueue(auditWriter framework.AuditWriter, workers int, bufferSize int) *AsyncAuditQueue {
    ctx, cancel := context.WithCancel(context.Background())
    
    queue := &AsyncAuditQueue{
        queue:       make(chan framework.AuditLogData, bufferSize),
        workers:     workers,
        auditWriter: auditWriter,
        ctx:         ctx,
        cancel:      cancel,
    }
    
    // 启动工作协程
    for i := 0; i < workers; i++ {
        go queue.worker(i)
    }
    
    return queue
}

func (q *AsyncAuditQueue) worker(id int) {
    q.wg.Add(1)
    defer q.wg.Done()
    
    logx.Infof("Audit worker %d started", id)
    
    for {
        select {
        case auditData := <-q.queue:
            // 重试机制
            var err error
            for retry := 0; retry < 3; retry++ {
                err = q.auditWriter.WriteAuditLog(q.ctx, auditData)
                if err == nil {
                    break
                }
                
                logx.Errorw("Audit write failed, retrying", 
                    logx.Field("retry", retry), 
                    logx.Field("error", err),
                    logx.Field("worker", id))
                
                // 指数退避
                time.Sleep(time.Duration(1<<retry) * time.Second)
            }
            
            if err != nil {
                // 最终失败，记录到文件或死信队列
                logx.Errorw("Audit write permanently failed", 
                    logx.Field("error", err),
                    logx.Field("auditData", auditData))
                    
                // 可选：写入死信文件
                q.writeToDeadLetter(auditData, err)
            }
            
        case <-q.ctx.Done():
            logx.Infof("Audit worker %d stopping", id)
            return
        }
    }
}

func (q *AsyncAuditQueue) Enqueue(auditData framework.AuditLogData) error {
    select {
    case q.queue <- auditData:
        return nil
    case <-time.After(100 * time.Millisecond):
        return fmt.Errorf("audit queue is full, dropping audit log")
    }
}

func (q *AsyncAuditQueue) Shutdown() {
    close(q.queue)
    q.cancel()
    q.wg.Wait()
}

// 在 AuditPlugin 中集成异步队列
type AuditPlugin struct {
    core         *framework.CoreServices
    config       *framework.AuditConfig
    asyncQueue   *AsyncAuditQueue  // 新增异步队列
    resourceCache *sync.Map        // 新增资源名称缓存
}

func (p *AuditPlugin) Init(core *framework.CoreServices) error {
    p.core = core
    p.config = core.Config.Audit
    p.resourceCache = &sync.Map{}
    
    if p.config == nil || !p.config.Enabled {
        return fmt.Errorf("audit config is missing or disabled")
    }
    
    // 初始化异步审计队列
    if core.AuditWriter != nil {
        workers := 3
        bufferSize := 1000
        if p.config.AsyncWorkers > 0 {
            workers = p.config.AsyncWorkers
        }
        if p.config.AsyncBufferSize > 0 {
            bufferSize = p.config.AsyncBufferSize
        }
        
        p.asyncQueue = NewAsyncAuditQueue(core.AuditWriter, workers, bufferSize)
    }
    
    return nil
}

// 修改审计写入逻辑
func (p *AuditPlugin) writeAuditLog(ctx context.Context, auditData framework.AuditLogData) {
    if p.asyncQueue != nil {
        // 异步写入
        if err := p.asyncQueue.Enqueue(auditData); err != nil {
            logx.Errorw("Failed to enqueue audit log", logx.Field("error", err))
        }
    } else if p.core.AuditWriter != nil {
        // 同步写入（降级）
        if err := p.core.AuditWriter.WriteAuditLog(ctx, auditData); err != nil {
            logx.Errorw("Failed to write audit log", logx.Field("error", err))
        }
    }
}
```

### 3. 增强敏感数据过滤

```go
import (
    "encoding/json"
    "regexp"
)

// 敏感数据过滤器
type SensitiveDataFilter struct {
    jsonFields   map[string]*regexp.Regexp // JSON字段级过滤
    patterns     []*regexp.Regexp          // 正则模式
    replacements map[string]string         // 替换规则
}

func NewSensitiveDataFilter() *SensitiveDataFilter {
    filter := &SensitiveDataFilter{
        jsonFields:   make(map[string]*regexp.Regexp),
        patterns:     make([]*regexp.Regexp, 0),
        replacements: make(map[string]string),
    }
    
    // 初始化敏感字段正则
    sensitiveFields := []string{
        "password", "pwd", "passwd", "secret", "token", "key", "authorization",
        "auth", "credential", "private", "ssn", "social_security_number",
        "credit_card", "card_number", "phone", "mobile", "email", "address",
        "id_card", "身份证", "手机号", "电话", "邮箱", "密码", "口令",
    }
    
    for _, field := range sensitiveFields {
        // 匹配JSON字段：\"field\":\"value\"
        pattern := fmt.Sprintf(`"%s"\s*:\s*"[^"]*"`, regexp.QuoteMeta(field))
        if regex, err := regexp.Compile(`(?i)`+pattern); err == nil {
            filter.jsonFields[field] = regex
        }
        
        // 匹配form格式：field=value
        pattern = fmt.Sprintf(`%s\s*=\s*[^\s&]*`, regexp.QuoteMeta(field))
        if regex, err := regexp.Compile(`(?i)`+pattern); err == nil {
            filter.patterns = append(filter.patterns, regex)
        }
    }
    
    // 身份证号正则
    if regex, err := regexp.Compile(`\b\d{17}[\dxX]\b`); err == nil {
        filter.patterns = append(filter.patterns, regex)
    }
    
    // 手机号正则  
    if regex, err := regexp.Compile(`\b1[3-9]\d{9}\b`); err == nil {
        filter.patterns = append(filter.patterns, regex)
    }
    
    // 邮箱正则
    if regex, err := regexp.Compile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`); err == nil {
        filter.patterns = append(filter.patterns, regex)
    }
    
    return filter
}

func (f *SensitiveDataFilter) Filter(data string) string {
    if len(data) == 0 {
        return data
    }
    
    result := data
    
    // 先尝试JSON结构化过滤
    if strings.HasPrefix(strings.TrimSpace(data), "{") {
        if filtered := f.filterJSON(data); filtered != "" {
            return filtered
        }
    }
    
    // JSON字段过滤
    for field, regex := range f.jsonFields {
        replacement := fmt.Sprintf(`"%s":"***FILTERED***"`, field)
        result = regex.ReplaceAllString(result, replacement)
    }
    
    // 通用模式过滤
    for _, regex := range f.patterns {
        result = regex.ReplaceAllStringFunc(result, func(match string) string {
            if strings.Contains(match, "=") {
                parts := strings.SplitN(match, "=", 2)
                return parts[0] + "=***FILTERED***"
            }
            return "***FILTERED***"
        })
    }
    
    return result
}

func (f *SensitiveDataFilter) filterJSON(jsonStr string) string {
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
        return "" // 不是有效JSON，让通用过滤器处理
    }
    
    // 递归过滤JSON对象
    filtered := f.filterJSONObject(data)
    
    result, _ := json.Marshal(filtered)
    return string(result)
}

func (f *SensitiveDataFilter) filterJSONObject(obj interface{}) interface{} {
    switch v := obj.(type) {
    case map[string]interface{}:
        result := make(map[string]interface{})
        for key, value := range v {
            lowerKey := strings.ToLower(key)
            
            // 检查是否是敏感字段
            isSensitive := false
            for sensitiveField := range f.jsonFields {
                if strings.Contains(lowerKey, strings.ToLower(sensitiveField)) {
                    isSensitive = true
                    break
                }
            }
            
            if isSensitive {
                result[key] = "***FILTERED***"
            } else {
                result[key] = f.filterJSONObject(value)
            }
        }
        return result
        
    case []interface{}:
        result := make([]interface{}, len(v))
        for i, item := range v {
            result[i] = f.filterJSONObject(item)
        }
        return result
        
    default:
        return v
    }
}

// 在 AuditPlugin 中使用增强过滤器
func (p *AuditPlugin) Init(core *framework.CoreServices) error {
    // ... 其他初始化代码 ...
    
    // 初始化敏感数据过滤器
    p.sensitiveFilter = NewSensitiveDataFilter()
    
    return nil
}

func (p *AuditPlugin) filterSensitiveData(data string) string {
    if p.sensitiveFilter != nil {
        return p.sensitiveFilter.Filter(data)
    }
    return data
}
```

### 4. 资源名称缓存优化

```go
// 带缓存的资源名称获取
type ResourceNameCache struct {
    cache     *sync.Map
    ttl       time.Duration
    apiProvider framework.ApiResourceProvider
}

type ResourceCacheEntry struct {
    Name      string
    ExpiresAt time.Time
}

func (p *AuditPlugin) getResourceNameWithCache(ctx context.Context, method, path string) string {
    if p.core.ApiResourceProvider == nil {
        return p.generateGenericResourceName(method, p.normalizePath(path))
    }
    
    // 生成缓存key
    cacheKey := fmt.Sprintf("%s:%s", method, path)
    
    // 检查缓存
    if value, ok := p.resourceCache.Load(cacheKey); ok {
        entry := value.(*ResourceCacheEntry)
        if time.Now().Before(entry.ExpiresAt) {
            return entry.Name
        }
        // 过期删除
        p.resourceCache.Delete(cacheKey)
    }
    
    // 从API提供者获取
    resourceName, err := p.core.ApiResourceProvider.GetApiResourceName(ctx, method, path)
    if err != nil || resourceName == "" {
        resourceName = p.generateGenericResourceName(method, p.normalizePath(path))
    }
    
    // 缓存结果（5分钟TTL）
    entry := &ResourceCacheEntry{
        Name:      resourceName,
        ExpiresAt: time.Now().Add(5 * time.Minute),
    }
    p.resourceCache.Store(cacheKey, entry)
    
    return resourceName
}
```

## 📊 配置优化

### 新增配置项

```go
type AuditConfig struct {
    Enabled   bool     `json:"Enabled,optional"`
    SkipPaths []string `json:"SkipPaths,optional"`
    
    // 内存控制配置
    MaxBodySize      int64 `json:"MaxBodySize,default=10485760"`      // 10MB
    MaxResponseSize  int64 `json:"MaxResponseSize,default=1048576"`   // 1MB
    SampleSize       int   `json:"SampleSize,default=1024"`           // 1KB
    
    // 异步处理配置
    AsyncEnabled     bool  `json:"AsyncEnabled,default=true"`
    AsyncWorkers     int   `json:"AsyncWorkers,default=3"`
    AsyncBufferSize  int   `json:"AsyncBufferSize,default=1000"`
    
    // 缓存配置
    ResourceCacheEnabled bool `json:"ResourceCacheEnabled,default=true"`
    ResourceCacheTTL     int  `json:"ResourceCacheTTL,default=300"`     // 5分钟
    
    // 过滤配置
    SensitiveFilterEnabled bool     `json:"SensitiveFilterEnabled,default=true"`
    CustomSensitiveFields  []string `json:"CustomSensitiveFields,optional"`
}
```

## 🧪 测试策略

### 1. 内存安全测试
```go
func TestLargeRequestBody(t *testing.T) {
    // 测试大文件上传不会导致OOM
    // 测试内存使用在合理范围内
}

func TestMemoryLeak(t *testing.T) {
    // 长时间压力测试，检查内存泄漏
}
```

### 2. 性能测试
```bash
# 异步处理效果测试
go test -bench=BenchmarkAsyncAudit
go test -bench=BenchmarkSyncAudit

# 缓存效果测试
go test -bench=BenchmarkResourceNameCache
```

### 3. 敏感数据过滤测试
```go
func TestSensitiveDataFiltering(t *testing.T) {
    testCases := []struct {
        input    string
        expected string
    }{
        {`{"password":"123456"}`, `{"password":"***FILTERED***"}`},
        {`{"phone":"13812345678"}`, `{"phone":"***FILTERED***"}`},
        // 更多测试用例...
    }
    
    filter := NewSensitiveDataFilter()
    for _, tc := range testCases {
        result := filter.Filter(tc.input)
        assert.Equal(t, tc.expected, result)
    }
}
```

## 📈 预期效果

### 内存优化
- 内存使用峰值降低 **70-80%**
- 大文件处理不再导致OOM
- 内存使用更加稳定和可预测

### 性能提升  
- 响应时间优化 **30-50%**
- 吞吐量提升 **2-3倍**
- 资源名称获取优化 **60-80%**

### 安全加固
- 敏感数据过滤准确率 **95%+**
- 支持JSON结构化过滤
- 可自定义敏感字段规则

## ⚠️ 注意事项

1. **异步可靠性**: 确保审计日志不丢失，实现重试和死信机制
2. **内存监控**: 持续监控缓存和队列的内存使用情况  
3. **过滤精度**: 平衡敏感数据保护和审计信息完整性
4. **性能影响**: 确保优化不影响主要业务功能性能

## 🚀 实施优先级

1. **P0**: 流式请求体处理（防止OOM）
2. **P0**: 异步审计日志写入（性能提升）
3. **P1**: 增强敏感数据过滤（安全加固）
4. **P1**: 资源名称缓存（性能优化）
5. **P2**: 监控和告警（可观测性）

## 📋 验收标准

- [ ] 大文件上传不会导致服务OOM
- [ ] 异步审计队列正常工作，无丢失
- [ ] 敏感数据过滤准确率达标
- [ ] 资源名称缓存命中率>80%
- [ ] 内存使用稳定在合理范围
- [ ] 响应时间满足性能要求
- [ ] 所有现有审计功能保持正常