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

package framework

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// StructuredLogger provides advanced structured logging capabilities
type StructuredLogger struct {
	config    *LoggingConfig
	writers   []LogWriter
	fields    map[string]interface{}
	context   context.Context
	mutex     sync.RWMutex
	formatter LogFormatter
	processor LogProcessor
	hooks     []LogHook
}

// LoggingConfig defines logging configuration
type LoggingConfig struct {
	Level            LogLevel               `json:"level" yaml:"level"`
	Format           LogFormat              `json:"format" yaml:"format"`
	Output           []string               `json:"output" yaml:"output"`
	EnableCaller     bool                   `json:"enable_caller" yaml:"enable_caller"`
	EnableStacktrace bool                   `json:"enable_stacktrace" yaml:"enable_stacktrace"`
	TimestampFormat  string                 `json:"timestamp_format" yaml:"timestamp_format"`
	ServiceName      string                 `json:"service_name" yaml:"service_name"`
	ServiceVersion   string                 `json:"service_version" yaml:"service_version"`
	Environment      string                 `json:"environment" yaml:"environment"`
	Fields           map[string]interface{} `json:"fields" yaml:"fields"`
	SamplingConfig   *LogSamplingConfig     `json:"sampling" yaml:"sampling"`
	FileConfig       *FileLogConfig         `json:"file" yaml:"file"`
	ConsoleConfig    *ConsoleLogConfig      `json:"console" yaml:"console"`
	RotationConfig   *LogRotationConfig     `json:"rotation" yaml:"rotation"`
}

// LogLevel represents logging levels
type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogFormat represents log output formats
type LogFormat int

const (
	JSONFormat LogFormat = iota
	TextFormat
	CompactFormat
)

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp  time.Time              `json:"@timestamp"`
	Level      LogLevel               `json:"level"`
	Message    string                 `json:"message"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
	Caller     *CallerInfo            `json:"caller,omitempty"`
	Stacktrace string                 `json:"stacktrace,omitempty"`
	TraceID    string                 `json:"trace_id,omitempty"`
	SpanID     string                 `json:"span_id,omitempty"`
	Service    ServiceInfo            `json:"service"`
	Request    *RequestInfo           `json:"request,omitempty"`
	Error      *ErrorInfo             `json:"error,omitempty"`
}

// CallerInfo represents caller information
type CallerInfo struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
}

// ServiceInfo represents service information
type ServiceInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
	Instance    string `json:"instance,omitempty"`
}

// RequestInfo represents request information
type RequestInfo struct {
	ID         string            `json:"id,omitempty"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	UserID     string            `json:"user_id,omitempty"`
	TenantID   string            `json:"tenant_id,omitempty"`
}

// ErrorInfo represents error information
type ErrorInfo struct {
	Type       string                 `json:"type"`
	Message    string                 `json:"message"`
	Stacktrace string                 `json:"stacktrace,omitempty"`
	Code       string                 `json:"code,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// LogSamplingConfig defines sampling configuration for logs
type LogSamplingConfig struct {
	Enabled     bool             `json:"enabled" yaml:"enabled"`
	Initial     int              `json:"initial" yaml:"initial"`
	Thereafter  int              `json:"thereafter" yaml:"thereafter"`
	Tick        time.Duration    `json:"tick" yaml:"tick"`
	LevelConfig map[LogLevel]int `json:"level_config" yaml:"level_config"`
}

// FileLogConfig defines file logging configuration
type FileLogConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Path       string `json:"path" yaml:"path"`
	MaxSize    int64  `json:"max_size" yaml:"max_size"`
	MaxBackups int    `json:"max_backups" yaml:"max_backups"`
	MaxAge     int    `json:"max_age" yaml:"max_age"`
	Compress   bool   `json:"compress" yaml:"compress"`
}

// ConsoleLogConfig defines console logging configuration
type ConsoleLogConfig struct {
	Enabled     bool `json:"enabled" yaml:"enabled"`
	ColorOutput bool `json:"color_output" yaml:"color_output"`
}

// LogRotationConfig defines log rotation configuration
type LogRotationConfig struct {
	Enabled  bool          `json:"enabled" yaml:"enabled"`
	MaxSize  int64         `json:"max_size" yaml:"max_size"`
	MaxFiles int           `json:"max_files" yaml:"max_files"`
	MaxAge   time.Duration `json:"max_age" yaml:"max_age"`
	Compress bool          `json:"compress" yaml:"compress"`
}

// LogWriter interface for writing logs
type LogWriter interface {
	Write(entry *LogEntry) error
	Close() error
}

// LogFormatter interface for formatting logs
type LogFormatter interface {
	Format(entry *LogEntry) ([]byte, error)
}

// LogProcessor interface for processing logs
type LogProcessor interface {
	Process(entry *LogEntry) *LogEntry
}

// LogHook interface for log hooks
type LogHook interface {
	Fire(entry *LogEntry) error
	Levels() []LogLevel
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(config *LoggingConfig) *StructuredLogger {
	if config == nil {
		config = DefaultLoggingConfig()
	}

	logger := &StructuredLogger{
		config:    config,
		writers:   make([]LogWriter, 0),
		fields:    make(map[string]interface{}),
		context:   context.Background(),
		formatter: NewJSONFormatter(config),
		processor: NewDefaultLogProcessor(),
		hooks:     make([]LogHook, 0),
	}

	// Setup writers based on configuration
	logger.setupWriters()

	// Add default fields
	for key, value := range config.Fields {
		logger.fields[key] = value
	}

	return logger
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Level:            InfoLevel,
		Format:           JSONFormat,
		Output:           []string{"console"},
		EnableCaller:     true,
		EnableStacktrace: false,
		TimestampFormat:  time.RFC3339Nano,
		ServiceName:      "middleware-framework",
		ServiceVersion:   "1.0.0",
		Environment:      "production",
		Fields:           make(map[string]interface{}),
		ConsoleConfig: &ConsoleLogConfig{
			Enabled:     true,
			ColorOutput: false,
		},
		FileConfig: &FileLogConfig{
			Enabled:    false,
			Path:       "/var/log/middleware/app.log",
			MaxSize:    100 * 1024 * 1024, // 100MB
			MaxBackups: 10,
			MaxAge:     30,
			Compress:   true,
		},
		SamplingConfig: &LogSamplingConfig{
			Enabled:    false,
			Initial:    100,
			Thereafter: 100,
			Tick:       time.Second,
		},
	}
}

// setupWriters configures log writers based on configuration
func (sl *StructuredLogger) setupWriters() {
	for _, output := range sl.config.Output {
		switch output {
		case "console":
			if sl.config.ConsoleConfig.Enabled {
				sl.writers = append(sl.writers, NewConsoleWriter(sl.config.ConsoleConfig))
			}
		case "file":
			if sl.config.FileConfig.Enabled {
				writer, err := NewFileWriter(sl.config.FileConfig)
				if err == nil {
					sl.writers = append(sl.writers, writer)
				}
			}
		}
	}

	// Fallback to console if no writers configured
	if len(sl.writers) == 0 {
		sl.writers = append(sl.writers, NewConsoleWriter(&ConsoleLogConfig{
			Enabled:     true,
			ColorOutput: false,
		}))
	}
}

// Log writes a log entry
func (sl *StructuredLogger) Log(level LogLevel, message string, fields ...LogField) {
	if level < sl.config.Level {
		return
	}

	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Fields:    make(map[string]interface{}),
		Service: ServiceInfo{
			Name:        sl.config.ServiceName,
			Version:     sl.config.ServiceVersion,
			Environment: sl.config.Environment,
		},
	}

	// Add logger fields
	sl.mutex.RLock()
	for key, value := range sl.fields {
		entry.Fields[key] = value
	}
	sl.mutex.RUnlock()

	// Add provided fields
	for _, field := range fields {
		entry.Fields[field.Key] = field.Value
	}

	// Extract trace information from context
	if span := SpanFromContext(sl.context); span != nil {
		entry.TraceID = span.TraceID
		entry.SpanID = span.SpanID
	}

	// Add caller information if enabled
	if sl.config.EnableCaller {
		entry.Caller = getCaller(3)
	}

	// Add stacktrace if enabled and error level
	if sl.config.EnableStacktrace && level >= ErrorLevel {
		entry.Stacktrace = getStacktrace(3)
	}

	// Process entry through processor
	if sl.processor != nil {
		entry = sl.processor.Process(entry)
	}

	// Fire hooks
	for _, hook := range sl.hooks {
		for _, hookLevel := range hook.Levels() {
			if hookLevel == level {
				hook.Fire(entry)
				break
			}
		}
	}

	// Write to all writers
	for _, writer := range sl.writers {
		writer.Write(entry)
	}
}

// Debug logs a debug message
func (sl *StructuredLogger) Debug(msg string, fields ...LogField) {
	sl.Log(DebugLevel, msg, fields...)
}

// Info logs an info message
func (sl *StructuredLogger) Info(msg string, fields ...LogField) {
	sl.Log(InfoLevel, msg, fields...)
}

// Warn logs a warning message
func (sl *StructuredLogger) Warn(msg string, fields ...LogField) {
	sl.Log(WarnLevel, msg, fields...)
}

// Error logs an error message
func (sl *StructuredLogger) Error(msg string, fields ...LogField) {
	sl.Log(ErrorLevel, msg, fields...)
}

// Fatal logs a fatal message
func (sl *StructuredLogger) Fatal(msg string, fields ...LogField) {
	sl.Log(FatalLevel, msg, fields...)
	os.Exit(1)
}

// With returns a new logger with additional fields
func (sl *StructuredLogger) With(fields ...LogField) Logger {
	newLogger := &StructuredLogger{
		config:    sl.config,
		writers:   sl.writers,
		fields:    make(map[string]interface{}),
		context:   sl.context,
		formatter: sl.formatter,
		processor: sl.processor,
		hooks:     sl.hooks,
	}

	// Copy existing fields
	sl.mutex.RLock()
	for key, value := range sl.fields {
		newLogger.fields[key] = value
	}
	sl.mutex.RUnlock()

	// Add new fields
	for _, field := range fields {
		newLogger.fields[field.Key] = field.Value
	}

	return newLogger
}

// WithContext returns a new logger with context
func (sl *StructuredLogger) WithContext(ctx context.Context) Logger {
	newLogger := &StructuredLogger{
		config:    sl.config,
		writers:   sl.writers,
		fields:    make(map[string]interface{}),
		context:   ctx,
		formatter: sl.formatter,
		processor: sl.processor,
		hooks:     sl.hooks,
	}

	// Copy existing fields
	sl.mutex.RLock()
	for key, value := range sl.fields {
		newLogger.fields[key] = value
	}
	sl.mutex.RUnlock()

	return newLogger
}

// WithRequest adds request information to the logger
func (sl *StructuredLogger) WithRequest(req *Request) Logger {
	reqInfo := &RequestInfo{
		ID:         req.ID,
		Method:     req.Method,
		Path:       req.Path,
		UserAgent:  req.UserAgent,
		RemoteAddr: req.RemoteAddr,
	}

	// Extract user context
	if userID, exists := req.Context["user_id"]; exists {
		if uid, ok := userID.(string); ok {
			reqInfo.UserID = uid
		}
	}
	if tenantID, exists := req.Context["tenant_id"]; exists {
		if tid, ok := tenantID.(string); ok {
			reqInfo.TenantID = tid
		}
	}

	return sl.With(Field("request", reqInfo))
}

// WithError adds error information to the logger
func (sl *StructuredLogger) WithError(err error) Logger {
	if err == nil {
		return sl
	}

	errorInfo := &ErrorInfo{
		Type:    fmt.Sprintf("%T", err),
		Message: err.Error(),
	}

	if sl.config.EnableStacktrace {
		errorInfo.Stacktrace = getStacktrace(2)
	}

	return sl.With(Field("error", errorInfo))
}

// AddHook adds a log hook
func (sl *StructuredLogger) AddHook(hook LogHook) {
	sl.hooks = append(sl.hooks, hook)
}

// Writer implementations

// ConsoleWriter writes logs to console
type ConsoleWriter struct {
	config *ConsoleLogConfig
	writer io.Writer
}

// NewConsoleWriter creates a new console writer
func NewConsoleWriter(config *ConsoleLogConfig) *ConsoleWriter {
	return &ConsoleWriter{
		config: config,
		writer: os.Stdout,
	}
}

// Write writes a log entry to console
func (cw *ConsoleWriter) Write(entry *LogEntry) error {
	formatter := NewJSONFormatter(&LoggingConfig{
		TimestampFormat: time.RFC3339Nano,
	})

	data, err := formatter.Format(entry)
	if err != nil {
		return err
	}

	_, err = cw.writer.Write(append(data, '\n'))
	return err
}

// Close closes the console writer
func (cw *ConsoleWriter) Close() error {
	return nil
}

// FileWriter writes logs to file
type FileWriter struct {
	config *FileLogConfig
	file   *os.File
	mutex  sync.Mutex
}

// NewFileWriter creates a new file writer
func NewFileWriter(config *FileLogConfig) (*FileWriter, error) {
	// Ensure directory exists
	dir := filepath.Dir(config.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &FileWriter{
		config: config,
		file:   file,
	}, nil
}

// Write writes a log entry to file
func (fw *FileWriter) Write(entry *LogEntry) error {
	formatter := NewJSONFormatter(&LoggingConfig{
		TimestampFormat: time.RFC3339Nano,
	})

	data, err := formatter.Format(entry)
	if err != nil {
		return err
	}

	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	_, err = fw.file.Write(append(data, '\n'))
	if err != nil {
		return err
	}

	return fw.file.Sync()
}

// Close closes the file writer
func (fw *FileWriter) Close() error {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	if fw.file != nil {
		return fw.file.Close()
	}
	return nil
}

// Formatter implementations

// JSONFormatter formats logs as JSON
type JSONFormatter struct {
	config *LoggingConfig
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(config *LoggingConfig) *JSONFormatter {
	return &JSONFormatter{config: config}
}

// Format formats a log entry as JSON
func (jf *JSONFormatter) Format(entry *LogEntry) ([]byte, error) {
	return json.Marshal(entry)
}

// Processor implementations

// DefaultLogProcessor provides default log processing
type DefaultLogProcessor struct{}

// NewDefaultLogProcessor creates a new default log processor
func NewDefaultLogProcessor() *DefaultLogProcessor {
	return &DefaultLogProcessor{}
}

// Process processes a log entry
func (dlp *DefaultLogProcessor) Process(entry *LogEntry) *LogEntry {
	// Add hostname if not present
	if _, exists := entry.Fields["hostname"]; !exists {
		if hostname, err := os.Hostname(); err == nil {
			entry.Fields["hostname"] = hostname
		}
	}

	// Add process ID
	entry.Fields["pid"] = os.Getpid()

	return entry
}

// Utility functions

// getCaller returns caller information
func getCaller(skip int) *CallerInfo {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}

	funcName := "unknown"
	if fn := runtime.FuncForPC(pc); fn != nil {
		funcName = fn.Name()
		// Strip package path
		if idx := strings.LastIndex(funcName, "/"); idx != -1 {
			funcName = funcName[idx+1:]
		}
	}

	// Strip full path, keep only filename
	if idx := strings.LastIndex(file, "/"); idx != -1 {
		file = file[idx+1:]
	}

	return &CallerInfo{
		File:     file,
		Line:     line,
		Function: funcName,
	}
}

// getStacktrace returns stack trace
func getStacktrace(skip int) string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	lines := strings.Split(string(buf[:n]), "\n")

	// Skip the first few lines which are internal
	if len(lines) > skip*2 {
		return strings.Join(lines[skip*2:], "\n")
	}
	return string(buf[:n])
}

// Framework integration

// LoggingMiddleware creates a logging middleware for the framework
func LoggingMiddleware(logger Logger) MiddlewareHandler {
	return &loggingMiddleware{
		logger: logger,
	}
}

type loggingMiddleware struct {
	logger Logger
}

// Handle implements MiddlewareHandler
func (lm *loggingMiddleware) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	startTime := time.Now()

	// Create logger with request context
	reqLogger := lm.logger.WithContext(ctx)
	if sl, ok := reqLogger.(*StructuredLogger); ok {
		reqLogger = sl.WithRequest(req)
	}

	// Log request start
	reqLogger.Info("Request started",
		String("method", req.Method),
		String("path", req.Path),
		String("user_agent", req.UserAgent),
		String("remote_addr", req.RemoteAddr),
	)

	// Process request
	resp, err := next(ctx, req)

	duration := time.Since(startTime)

	// Determine log level based on response
	logLevel := InfoLevel
	if err != nil {
		logLevel = ErrorLevel
	} else if resp != nil && resp.StatusCode >= 400 {
		logLevel = WarnLevel
	}

	// Prepare log fields
	fields := []LogField{
		String("method", req.Method),
		String("path", req.Path),
		Duration("duration", duration),
	}

	if resp != nil {
		fields = append(fields, Int("status_code", resp.StatusCode))
	}

	if err != nil {
		if sl, ok := reqLogger.(*StructuredLogger); ok {
			reqLogger = sl.WithError(err)
		}
		fields = append(fields, String("error", err.Error()))
	}

	// Log request completion
	message := "Request completed"
	if err != nil {
		message = "Request failed"
	}

	reqLogger.Log(logLevel, message, fields...)

	return resp, err
}
