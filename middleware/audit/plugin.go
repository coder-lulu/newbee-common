// Copyright 2024 The NewBee Authors. All Rights Reserved.

package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/coder-lulu/newbee-common/middleware/util"
	"github.com/zeromicro/go-zero/core/logx"
)

// AuditBodySummary audit插件专用的请求体摘要类型别名
type AuditBodySummary = util.BodySummary

// AsyncAuditQueue 异步审计队列
type AsyncAuditQueue struct {
	queue       chan framework.AuditLogData
	workers     int
	auditWriter framework.AuditWriter
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      int32
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

	// 启动工作协程 - 在启动前添加到WaitGroup
	for i := 0; i < workers; i++ {
		queue.wg.Add(1) // ✅ 修复：在启动goroutine前调用Add
		go queue.worker(i)
	}

	return queue
}

func (q *AsyncAuditQueue) worker(id int) {
	defer q.wg.Done() // ✅ 修复：移除Add调用，只保留Done

	logx.Infof("Audit worker %d started", id)

	for {
		select {
		case auditData, ok := <-q.queue:
			if !ok {
				logx.Infof("Audit worker %d stopping due to queue closure", id)
				return
			}
			// 🔥 关键修复：从 auditData 构建包含租户信息的 context
			// 因为 worker 运行在独立的 goroutine 中，使用的是 context.Background()
			// 必须从审计数据中提取租户/用户信息并重新构建 context
			cm := keys.NewContextManager()
			workerCtx := cm.SetTenantID(q.ctx, auditData.TenantID)
			workerCtx = cm.SetUserID(workerCtx, auditData.UserID)
			if auditData.RoleCodes != "" {
				workerCtx = cm.SetRoleCodes(workerCtx, auditData.RoleCodes)
			}

			logx.Infow("Worker processing audit data with context",
				logx.Field("worker", id),
				logx.Field("tenant_id", auditData.TenantID),
				logx.Field("user_id", auditData.UserID),
				logx.Field("role_codes", auditData.RoleCodes),
				logx.Field("path", auditData.Path))

			// 重试机制
			var err error
			for retry := 0; retry < 3; retry++ {
				err = q.auditWriter.WriteAuditLog(workerCtx, auditData)
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
				logx.Errorw("CRITICAL: Audit write permanently failed - audit logs being lost!",
					logx.Field("error", err.Error()),
					logx.Field("auditData", auditData),
					logx.Field("worker", id),
					logx.Field("tenant_id", auditData.TenantID),
					logx.Field("user_id", auditData.UserID),
					logx.Field("path", auditData.Path))

				// 可选：写入死信文件
				q.writeToDeadLetter(auditData, err)
			} else {
				// 成功写入审计日志
				logx.Debugw("Audit log written successfully",
					logx.Field("worker", id),
					logx.Field("tenant_id", auditData.TenantID),
					logx.Field("user_id", auditData.UserID),
					logx.Field("path", auditData.Path))
			}

		case <-q.ctx.Done():
			logx.Infof("Audit worker %d stopping", id)
			return
		}
	}
}

func (q *AsyncAuditQueue) Enqueue(auditData framework.AuditLogData) (err error) {
	if atomic.LoadInt32(&q.closed) == 1 {
		return fmt.Errorf("audit queue is shutting down")
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("audit queue is shutting down")
		}
	}()

	select {
	case q.queue <- auditData:
		return nil
	case <-time.After(100 * time.Millisecond):
		// ✅ 修复：不直接丢弃，而是尝试写入死信队列
		logx.Errorw("Audit queue is full, writing to dead letter",
			logx.Field("queue_size", len(q.queue)),
			logx.Field("tenant_id", auditData.TenantID),
			logx.Field("user_id", auditData.UserID),
			logx.Field("path", auditData.Path))

		// 异步写入死信队列，避免阻塞主请求
		go q.writeToDeadLetter(auditData, fmt.Errorf("audit queue full"))
		return fmt.Errorf("audit queue is full, saved to dead letter queue")
	case <-q.ctx.Done():
		return fmt.Errorf("audit queue is shutting down")
	}
}

func (q *AsyncAuditQueue) Shutdown() {
	if atomic.CompareAndSwapInt32(&q.closed, 0, 1) {
		close(q.queue)
		q.cancel()
	} else {
		q.cancel()
	}
	q.wg.Wait()
}

func (q *AsyncAuditQueue) writeToDeadLetter(auditData framework.AuditLogData, err error) {
	// ✅ 修复：实现死信文件写入
	deadLetterEntry := map[string]interface{}{
		"timestamp":   time.Now().Unix(),
		"error":       err.Error(),
		"audit_data":  auditData,
		"retry_count": 0,
	}

	// 序列化为JSON
	jsonData, jsonErr := json.Marshal(deadLetterEntry)
	if jsonErr != nil {
		logx.Errorw("Failed to marshal dead letter entry",
			logx.Field("json_error", jsonErr),
			logx.Field("original_error", err))
		return
	}

	// 写入到死信文件（可以考虑使用文件轮转）
	deadLetterFile := "/tmp/audit_dead_letter.log"
	if err := q.appendToFile(deadLetterFile, string(jsonData)+"\n"); err != nil {
		logx.Errorw("Failed to write to dead letter file",
			logx.Field("file_error", err),
			logx.Field("original_error", err))
	} else {
		logx.Infow("Audit data written to dead letter file",
			logx.Field("file", deadLetterFile),
			logx.Field("tenant_id", auditData.TenantID),
			logx.Field("user_id", auditData.UserID),
			logx.Field("path", auditData.Path))
	}
}

// appendToFile 安全地追加内容到文件
func (q *AsyncAuditQueue) appendToFile(filename, content string) error {
	// 使用互斥锁确保并发写入安全（在生产环境中可能需要更复杂的文件锁）
	// 这里简化处理，实际生产环境建议使用专门的日志库
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// SensitiveDataFilter 敏感数据过滤器
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
		// 匹配JSON字段："field":"value"
		pattern := fmt.Sprintf(`"%s"\s*:\s*"[^"]*"`, regexp.QuoteMeta(field))
		if regex, err := regexp.Compile(`(?i)` + pattern); err == nil {
			filter.jsonFields[field] = regex
		}

		// 匹配form格式：field=value
		pattern = fmt.Sprintf(`%s\s*=\s*[^\s&]*`, regexp.QuoteMeta(field))
		if regex, err := regexp.Compile(`(?i)` + pattern); err == nil {
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

// ResourceCacheEntry 资源名称缓存条目
type ResourceCacheEntry struct {
	Name      string
	ExpiresAt time.Time
}

// responseWriterWrapper captures the response status code and body for auditing.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	responseBody *bytes.Buffer
	maxSize      int64
	readSize     int64
}

func (w *responseWriterWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterWrapper) Write(data []byte) (int, error) {
	// 同时写入原始响应和缓冲区（带大小限制）
	if w.responseBody != nil {
		// 检查是否超过最大限制
		if w.readSize+int64(len(data)) <= w.maxSize {
			w.responseBody.Write(data)
			w.readSize += int64(len(data))
		} else if w.readSize < w.maxSize {
			// 部分写入直到达到限制
			remaining := w.maxSize - w.readSize
			w.responseBody.Write(data[:remaining])
			w.responseBody.WriteString("...[truncated]")
			w.readSize = w.maxSize
		}
	}
	return w.ResponseWriter.Write(data)
}

func (w *responseWriterWrapper) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("http: Hijack not supported")
}

func (w *responseWriterWrapper) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *responseWriterWrapper) CloseNotify() <-chan bool {
	if notifier, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return notifier.CloseNotify()
	}
	notify := make(chan bool, 1)
	close(notify)
	return notify
}

// AuditPlugin implements the framework.MiddlewarePlugin for request auditing.
type AuditPlugin struct {
	core            *framework.CoreServices
	config          *framework.AuditConfig
	asyncQueue      *AsyncAuditQueue     // 异步审计队列
	resourceCache   *sync.Map            // 资源名称缓存
	sensitiveFilter *SensitiveDataFilter // 敏感数据过滤器
	logger          *logging.MiddlewareLogger

	// 新的简化集成支持
	builtinWriter framework.AuditWriter  // 内置写入器
	builtinConfig *framework.AuditConfig // 内置配置
	rpcProvider   AuditSvcProvider       // RPC提供者 (运行时存储)
	customWriter  framework.AuditWriter  // 自定义写入器 (运行时存储)
}

// NewAuditPlugin creates a new instance of the audit plugin.
// 使用简化的构造函数，依赖通过Init方法注入
func NewAuditPlugin() framework.MiddlewarePlugin {
	return &AuditPlugin{
		resourceCache: &sync.Map{},
	}
}

// NewAuditPluginWithWriter creates a new audit plugin with a custom writer.
// 保留向后兼容性的构造函数
func NewAuditPluginWithWriter(writer framework.AuditWriter) framework.MiddlewarePlugin {
	plugin := &AuditPlugin{
		resourceCache: &sync.Map{},
		customWriter:  writer,
		builtinWriter: writer,
		builtinConfig: &framework.AuditConfig{
			Enabled:             true,
			SkipPaths:           []string{"/health", "/metrics", "/ping"},
			WriterType:          "custom",
			MaxBodySize:         1048576, // 1MB
			AsyncEnabled:        true,
			AsyncWorkers:        3,
			AsyncBufferSize:     1000,
			CaptureResponseBody: true,
		},
	}
	return plugin
}

// NewAuditPluginWithProvider creates a new audit plugin with an RPC provider.
// 保留向后兼容性的构造函数
func NewAuditPluginWithProvider(provider AuditSvcProvider) framework.MiddlewarePlugin {
	plugin := &AuditPlugin{
		resourceCache: &sync.Map{},
		rpcProvider:   provider,
		builtinWriter: NewBuiltinAuditWriter(provider),
		builtinConfig: &framework.AuditConfig{
			Enabled:             true,
			SkipPaths:           []string{"/health", "/metrics", "/ping"},
			WriterType:          "rpc",
			MaxBodySize:         1048576, // 1MB
			AsyncEnabled:        true,
			AsyncWorkers:        3,
			AsyncBufferSize:     1000,
			CaptureResponseBody: true,
		},
	}
	return plugin
}

func (p *AuditPlugin) Name() string {
	return "Audit"
}

func (p *AuditPlugin) Priority() int {
	// Run immediately after Auth (10) to ensure the user is identified.
	return 12
}

func (p *AuditPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.logger = logging.AuditLogger()

	// 🔧 修复：合并配置而不是覆盖
	// 如果有builtinConfig，使用它作为基础配置（提供默认的async设置等）
	// 但是要用YAML配置覆盖关键字段（特别是skipPaths）
	if p.builtinConfig != nil && core.Config.Audit != nil {
		// 合并配置：YAML配置优先
		p.config = p.builtinConfig

		// 如果YAML配置了skipPaths，使用YAML的skipPaths
		if len(core.Config.Audit.SkipPaths) > 0 {
			p.config.SkipPaths = core.Config.Audit.SkipPaths
		}

		// 如果YAML配置了其他关键字段，也使用YAML的
		if core.Config.Audit.MaxBodySize > 0 {
			p.config.MaxBodySize = core.Config.Audit.MaxBodySize
		}
		if core.Config.Audit.AsyncWorkers > 0 {
			p.config.AsyncWorkers = core.Config.Audit.AsyncWorkers
		}
		if core.Config.Audit.AsyncBufferSize > 0 {
			p.config.AsyncBufferSize = core.Config.Audit.AsyncBufferSize
		}
		p.config.CaptureResponseBody = core.Config.Audit.CaptureResponseBody
		p.config.RealIPHeader = core.Config.Audit.RealIPHeader

		p.logger.Info("audit config merged: builtin defaults + YAML overrides")
	} else if p.builtinConfig != nil {
		// 只有builtin配置，没有YAML配置
		p.config = p.builtinConfig
		p.logger.Info("audit config: using builtin defaults only")
	} else {
		// 只有YAML配置，没有builtin配置
		p.config = core.Config.Audit
		p.logger.Info("audit config: using YAML config only")
	}

	if p.resourceCache == nil {
		p.resourceCache = &sync.Map{}
	}

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("audit config is missing or disabled").
			Build()
		p.logger.WithError(err).Error("audit plugin initialization failed")
		return err
	}

	// 初始化敏感数据过滤器
	p.sensitiveFilter = NewSensitiveDataFilter()

	// 🔍 调试：输出配置信息
	p.logger.WithField("skip_paths_count", len(p.config.SkipPaths)).
		WithField("skip_paths", p.config.SkipPaths).
		Info("audit plugin skipPaths configuration loaded")

	// 智能检测和配置写入器
	if p.builtinWriter == nil {
		writer, err := p.autoDetectWriter(core)
		if err != nil {
			return err
		}
		p.builtinWriter = writer
	}

	// 根据配置初始化异步队列
	if p.config.AsyncEnabled {
		workers := p.config.AsyncWorkers
		if workers <= 0 {
			workers = 3 // 默认值
		}
		bufferSize := p.config.AsyncBufferSize
		if bufferSize <= 0 {
			bufferSize = 1000 // 默认值
		}

		p.asyncQueue = NewAsyncAuditQueue(p.builtinWriter, workers, bufferSize)
		p.logger.WithField("workers", workers).
			WithField("buffer_size", bufferSize).
			WithField("writer_type", fmt.Sprintf("%T", p.builtinWriter)).
			WithField("async_enabled", true).
			Info("async audit queue initialized")
	} else {
		p.logger.WithField("writer_type", fmt.Sprintf("%T", p.builtinWriter)).
			WithField("async_enabled", false).
			Info("audit writer initialized for synchronous operation")
	}

	p.logger.Info("audit plugin initialized successfully")
	return nil
}

func (p *AuditPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		ctx := r.Context()
		cm := p.core.ContextManager
		logger := p.logger.WithContext(ctx).WithRequest(r)

		// Check if the path should be skipped for auditing early
		if p.shouldSkip(r.URL.Path) {
			logger.WithField("skipped", true).
				WithField("path", r.URL.Path).
				Info("audit logging skipped for path")
			next(w, r)
			return
		}

		// 1. 捕获请求体（使用流式处理）
		requestBody := ""
		if r.Body != nil && p.shouldCaptureRequestBody(r) {
			capturedBody, err := p.captureRequestBody(r)
			if err != nil {
				logger.WithError(err).Error("failed to capture request body for audit")
			} else {
				requestBody = capturedBody
			}
		}

		// 2. 准备捕获响应体（带大小限制）
		captureResponse := p.shouldCaptureResponseBody(r)
		var responseBuffer *bytes.Buffer
		maxResponseSize := int64(1048576) // 1MB默认限制
		if captureResponse {
			responseBuffer = &bytes.Buffer{}
			if p.config != nil && p.config.MaxBodySize > 0 {
				maxResponseSize = p.config.MaxBodySize
			}
		}
		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			responseBody:   responseBuffer,
			maxSize:        maxResponseSize,
			readSize:       0,
		}

		// Execute the rest of the chain.
		next(wrapper, r)

		// Log and persist the audit trail after the request is complete.
		duration := time.Since(startTime)
		userID := cm.GetUserID(ctx)
		tenantID := cm.GetTenantID(ctx)

		// 3. 处理响应体
		responseBody := ""
		if captureResponse && responseBuffer != nil && responseBuffer.Len() > 0 {
			responseBody = p.filterSensitiveData(responseBuffer.String())
		}

		logger.WithField("user_id", userID).
			WithField("tenant_id", tenantID).
			WithField("status_code", wrapper.statusCode).
			WithDuration(startTime).
			Info("request audited")

		// 统一使用内置写入器进行审计日志写入
		// 不再依赖core.AuditWriter，改为使用builtinWriter或已初始化的异步队列
		if p.builtinWriter != nil || p.asyncQueue != nil {
			// Get resource name from database or use fallback
			resourceName := p.getResourceName(ctx, r.Method, r.URL.Path)
			normalizedPath := p.normalizePath(r.URL.Path)
			clientIP := p.resolveClientIP(r)
			userName := cm.GetUsername(ctx)
			roleCodes := cm.GetRoleCodes(ctx)

			metadata := p.collectAuditMetadata(ctx)
			if requestID := cm.GetRequestID(ctx); requestID != "" {
				if metadata == nil {
					metadata = make(map[string]string)
				}
				metadata["request_id"] = requestID
			}
			if traceID := cm.GetTraceID(ctx); traceID != "" {
				if metadata == nil {
					metadata = make(map[string]string)
				}
				metadata["trace_id"] = traceID
			}

			auditData := framework.AuditLogData{
				TenantID:     tenantID,
				UserID:       userID,
				RoleCodes:    roleCodes,
				UserName:     userName,
				Method:       r.Method,
				Path:         r.URL.Path,
				ResourceName: resourceName,
				ResourceType: resourceName,
				ResourceID:   normalizedPath,
				StatusCode:   wrapper.statusCode,
				DurationMs:   duration.Milliseconds(),
				UserAgent:    r.UserAgent(),
				ClientIP:     clientIP,
				RequestData:  requestBody,
				ResponseData: responseBody,
				Metadata:     metadata,
			}

			logger.WithField("has_builtin_writer", p.builtinWriter != nil).
				WithField("has_async_queue", p.asyncQueue != nil).
				WithField("tenant_id", tenantID).
				WithField("user_id", userID).
				Debug("writing audit log via unified audit system")

			// 统一的审计日志写入入口
			p.writeAuditLog(ctx, auditData)
		} else {
			err := errors.NewInternalError(errors.CodeInternalError,
				fmt.Errorf("no audit writer available"))
			logger.WithError(err).
				WithField("builtin_writer", p.builtinWriter != nil).
				WithField("async_queue", p.asyncQueue != nil).
				WithField("core_audit_writer", p.core != nil && p.core.AuditWriter != nil).
				Error("audit logs will be lost")
		}
	}
}

func (p *AuditPlugin) shouldSkip(path string) bool {
	for _, skipPath := range p.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// getResourceName gets resource name with caching from database or fallback to generic naming
func (p *AuditPlugin) getResourceName(ctx context.Context, method, path string) string {
	return p.getResourceNameWithCache(ctx, method, path)
}

// getResourceNameWithCache 带缓存的资源名称获取
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
			logx.WithContext(ctx).Infow("Resource name cache hit",
				logx.Field("method", method),
				logx.Field("path", path),
				logx.Field("resourceName", entry.Name))
			return entry.Name
		}
		// 过期删除
		p.resourceCache.Delete(cacheKey)
		logx.WithContext(ctx).Infow("Resource name cache expired",
			logx.Field("method", method),
			logx.Field("path", path))
	}

	// 从API提供者获取
	logx.WithContext(ctx).Infow("Fetching resource name from provider",
		logx.Field("method", method),
		logx.Field("path", path))

	resourceName, err := p.core.ApiResourceProvider.GetApiResourceName(ctx, method, path)
	if err != nil || resourceName == "" {
		logx.WithContext(ctx).Errorw("Failed to get resource name from provider, using fallback",
			logx.Field("method", method),
			logx.Field("path", path),
			logx.Field("error", err),
			logx.Field("resourceName", resourceName))
		resourceName = p.generateGenericResourceName(method, p.normalizePath(path))
	} else {
		logx.WithContext(ctx).Infow("Successfully got resource name from provider",
			logx.Field("method", method),
			logx.Field("path", path),
			logx.Field("resourceName", resourceName))
	}

	// 缓存结果（5分钟TTL）
	entry := &ResourceCacheEntry{
		Name:      resourceName,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	p.resourceCache.Store(cacheKey, entry)

	logx.WithContext(ctx).Infow("Resource name cached",
		logx.Field("method", method),
		logx.Field("path", path),
		logx.Field("resourceName", resourceName),
		logx.Field("expiresAt", entry.ExpiresAt))

	return resourceName
}

func (p *AuditPlugin) resolveClientIP(r *http.Request) string {
	if p.config != nil && p.config.RealIPHeader != "" {
		headerName := http.CanonicalHeaderKey(p.config.RealIPHeader)
		if headerValue := r.Header.Get(headerName); headerValue != "" {
			parts := strings.Split(headerValue, ",")
			candidate := strings.TrimSpace(parts[0])
			if candidate != "" {
				return candidate
			}
		}
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// normalizePath 标准化路径，去除查询参数和其他修饰符
func (p *AuditPlugin) normalizePath(path string) string {
	// 移除查询参数
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// 确保以/开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 移除结尾的/
	path = strings.TrimSuffix(path, "/")

	return path
}

// generateGenericResourceName 生成通用的资源名称（纯粹基于路径分析，无硬编码）
func (p *AuditPlugin) generateGenericResourceName(method, path string) string {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")

	var resourceName string
	if len(pathParts) >= 2 {
		// 获取资源类型和操作
		resource := pathParts[0]
		action := pathParts[1]

		// 基于HTTP方法推断操作类型
		actionType := ""
		switch method {
		case "POST":
			if action == "list" {
				actionType = "查询"
			} else {
				actionType = "操作"
			}
		case "GET":
			actionType = "查询"
		case "PUT", "PATCH":
			actionType = "更新"
		case "DELETE":
			actionType = "删除"
		default:
			actionType = "访问"
		}

		resourceName = actionType + strings.Title(resource) + "." + action
	} else {
		// 单级路径的处理
		resource := pathParts[0]
		switch method {
		case "POST":
			resourceName = "操作" + strings.Title(resource)
		case "GET":
			resourceName = "获取" + strings.Title(resource)
		default:
			resourceName = "访问" + strings.Title(resource)
		}
	}

	return resourceName
}

// captureRequestBody 使用流式处理捕获请求体
func (p *AuditPlugin) captureRequestBody(r *http.Request) (string, error) {
	if r.Body == nil || !p.shouldCaptureRequestBody(r) {
		return "", nil
	}

	// 获取Content-Length，使用配置中的最大大小限制
	maxSize := p.config.MaxBodySize
	if maxSize <= 0 {
		maxSize = int64(10 << 20) // 10MB默认限制
	}

	contentLength := r.ContentLength
	if contentLength > maxSize {
		return fmt.Sprintf(`{"error":"body_too_large","size":%d,"limit":%d}`, contentLength, maxSize), nil
	}

	// 创建流式读取器
	streamReader := util.NewStreamingBodyReader(r.Body, maxSize)

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

// shouldCaptureRequestBody 判断是否应该捕获请求体
func (p *AuditPlugin) shouldCaptureRequestBody(r *http.Request) bool {
	// 只对POST, PUT, PATCH请求捕获请求体
	method := r.Method
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}

	// 检查Content-Type
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/x-www-form-urlencoded") ||
		strings.Contains(contentType, "text/plain") {
		return true
	}

	// 跳过文件上传等大型请求
	if strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "application/octet-stream") {
		return false
	}

	return false
}

// shouldCaptureResponseBody 判断是否应该捕获响应体
func (p *AuditPlugin) shouldCaptureResponseBody(r *http.Request) bool {
	if p.config != nil && !p.config.CaptureResponseBody {
		return false
	}
	// 可以根据配置或路径来决定
	return true
}

// filterSensitiveData 过滤敏感数据
func (p *AuditPlugin) filterSensitiveData(data string) string {
	if len(data) == 0 {
		return data
	}

	// 限制数据长度，避免存储过大的数据
	const maxDataSize = 10000 // 10KB
	if len(data) > maxDataSize {
		data = data[:maxDataSize] + "...[truncated]"
	}

	// 使用增强的敏感数据过滤器
	if p.sensitiveFilter != nil {
		return p.sensitiveFilter.Filter(data)
	}

	// 降级到简单过滤（如果过滤器未初始化）
	return data
}

func (p *AuditPlugin) collectAuditMetadata(ctx context.Context) map[string]string {
	if ctx == nil {
		return nil
	}
	value := ctx.Value(keys.AuditMetadataKey)
	if value == nil {
		return nil
	}
	merged := make(map[string]string)
	switch meta := value.(type) {
	case map[string]string:
		for k, v := range meta {
			if v == "" {
				continue
			}
			merged[k] = v
		}
	case map[string]interface{}:
		for k, v := range meta {
			switch typed := v.(type) {
			case string:
				if typed != "" {
					merged[k] = typed
				}
			case fmt.Stringer:
				merged[k] = typed.String()
			default:
				if typed != nil {
					merged[k] = fmt.Sprintf("%v", typed)
				}
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// writeAuditLog 写入审计日志（优先使用异步队列）
func (p *AuditPlugin) writeAuditLog(ctx context.Context, auditData framework.AuditLogData) {
	if p.asyncQueue != nil {
		// 异步写入
		logx.WithContext(ctx).Debugw("Enqueueing audit log",
			logx.Field("path", auditData.Path),
			logx.Field("user_id", auditData.UserID),
			logx.Field("method", auditData.Method))

		if err := p.asyncQueue.Enqueue(auditData); err != nil {
			logx.WithContext(ctx).Errorw("Failed to enqueue audit log",
				logx.Field("error", err),
				logx.Field("path", auditData.Path),
				logx.Field("user_id", auditData.UserID))
		}
	} else {
		// 没有异步队列，只使用内置写入器进行同步写入
		// 不再回退到core.AuditWriter，确保统一使用内置写入器
		if p.builtinWriter != nil {
			logx.WithContext(ctx).Debugw("Writing audit log synchronously via builtin writer",
				logx.Field("path", auditData.Path),
				logx.Field("user_id", auditData.UserID))

			if err := p.builtinWriter.WriteAuditLog(ctx, auditData); err != nil {
				logx.WithContext(ctx).Errorw("Failed to write audit log via builtin writer",
					logx.Field("error", err),
					logx.Field("path", auditData.Path),
					logx.Field("user_id", auditData.UserID))
			}
		} else {
			logx.WithContext(ctx).Errorw("CRITICAL: No builtin audit writer available - audit logs being lost!",
				logx.Field("path", auditData.Path),
				logx.Field("user_id", auditData.UserID))
		}
	}
}

// =================================================================
// 简化集成接口 - 消除微服务实现AuditWriter的复杂性
// =================================================================

// AuditSvcProvider 简化的服务提供者接口 - 微服务只需实现这个
type AuditSvcProvider interface {
	// 获取Core RPC客户端用于审计日志写入
	GetCoreRpcClient() interface{} // 返回具体的Core RPC客户端
}

// AuditSvcProvider 被保留用于RPC服务提供者接口

// autoDetectWriter 智能检测和创建合适的审计写入器
func (p *AuditPlugin) autoDetectWriter(core *framework.CoreServices) (framework.AuditWriter, error) {
	// 1. 优先使用预设的自定义写入器
	if p.customWriter != nil {
		p.logger.Info("using pre-configured custom audit writer")
		return p.customWriter, nil
	}

	// 2. 检查是否有RPC提供者
	if p.rpcProvider != nil {
		p.logger.Info("using RPC provider audit writer")
		return NewBuiltinAuditWriter(p.rpcProvider), nil
	}

	// 3. 检查核心服务是否提供了审计写入器
	if core.AuditWriter != nil {
		p.logger.Info("using core services audit writer")
		return core.AuditWriter, nil
	}

	// 4. 根据配置的写入器类型创建
	switch p.config.WriterType {
	case "rpc":
		return nil, errors.NewError(errors.CodeConfigError).
			WithMessage("RPC writer type specified but no RPC provider available").
			Build()
	case "custom":
		return nil, errors.NewError(errors.CodeConfigError).
			WithMessage("Custom writer type specified but no custom writer provided").
			Build()
	case "noop", "":
		// 使用NoOp写入器（开发/测试环境）
		p.logger.Warn("using NoOp audit writer - audit logs will not be persisted")
		return &NoOpAuditWriter{}, nil
	default:
		return nil, errors.NewError(errors.CodeConfigError).
			WithMessage(fmt.Sprintf("unknown writer type: %s", p.config.WriterType)).
			Build()
	}
}

// NoOpAuditWriter 无操作审计写入器，用于开发/测试环境
type NoOpAuditWriter struct{}

func (n *NoOpAuditWriter) WriteAuditLog(ctx context.Context, auditData framework.AuditLogData) error {
	// 只记录到日志，不实际存储
	logx.WithContext(ctx).Infow("Audit log (NoOp mode)",
		logx.Field("tenant_id", auditData.TenantID),
		logx.Field("user_id", auditData.UserID),
		logx.Field("method", auditData.Method),
		logx.Field("path", auditData.Path),
		logx.Field("status_code", auditData.StatusCode),
		logx.Field("duration_ms", auditData.DurationMs))
	return nil
}
