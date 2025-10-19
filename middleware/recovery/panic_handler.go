// Copyright 2024 The NewBee Authors. All Rights Reserved.

package recovery

import (
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/zeromicro/go-zero/core/logx"
)

// PanicHandler 中间件panic恢复处理器
type PanicHandler struct {
	logger        *logging.StructuredLogger
	enableStack   bool
	maxStackSize  int
	notifyHandler func(error, string) // 可选的通知处理器
}

// PanicInfo panic信息
type PanicInfo struct {
	Error      interface{} `json:"error"`
	Stack      string      `json:"stack"`
	Timestamp  time.Time   `json:"timestamp"`
	RequestURI string      `json:"request_uri,omitempty"`
	Method     string      `json:"method,omitempty"`
	UserAgent  string      `json:"user_agent,omitempty"`
	RemoteAddr string      `json:"remote_addr,omitempty"`
}

// NewPanicHandler 创建panic处理器
func NewPanicHandler(component string) *PanicHandler {
	return &PanicHandler{
		logger:       logging.NewStructuredLogger(component),
		enableStack:  true,
		maxStackSize: 8192, // 8KB stack trace limit
	}
}

// WithNotifyHandler 设置通知处理器
func (p *PanicHandler) WithNotifyHandler(handler func(error, string)) *PanicHandler {
	p.notifyHandler = handler
	return p
}

// WithStackTrace 设置是否启用栈追踪
func (p *PanicHandler) WithStackTrace(enable bool) *PanicHandler {
	p.enableStack = enable
	return p
}

// WithMaxStackSize 设置最大栈大小
func (p *PanicHandler) WithMaxStackSize(size int) *PanicHandler {
	p.maxStackSize = size
	return p
}

// RecoverMiddleware 中间件panic恢复中间件
func (p *PanicHandler) RecoverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				p.handlePanic(w, r, recovered)
			}
		}()
		
		next(w, r)
	}
}

// RecoverWithCallback 带回调的恢复函数
func (p *PanicHandler) RecoverWithCallback(callback func(), onPanic func(interface{})) {
	defer func() {
		if recovered := recover(); recovered != nil {
			p.logPanic(recovered, "callback function")
			if onPanic != nil {
				// 安全地调用panic回调
				func() {
					defer func() {
						if innerRecovered := recover(); innerRecovered != nil {
							p.logPanic(innerRecovered, "panic callback")
						}
					}()
					onPanic(recovered)
				}()
			}
		}
	}()
	
	callback()
}

// SafeGo 安全的goroutine启动
func (p *PanicHandler) SafeGo(fn func()) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				p.logPanic(recovered, "goroutine")
				
				// 通知处理器
				if p.notifyHandler != nil {
					err := fmt.Errorf("goroutine panic: %v", recovered)
					p.notifyHandler(err, p.getStackTrace())
				}
			}
		}()
		
		fn()
	}()
}

// handlePanic 处理HTTP请求中的panic
func (p *PanicHandler) handlePanic(w http.ResponseWriter, r *http.Request, recovered interface{}) {
	// 构建panic信息
	panicInfo := &PanicInfo{
		Error:      recovered,
		Timestamp:  time.Now(),
		RequestURI: r.RequestURI,
		Method:     r.Method,
		UserAgent:  r.Header.Get("User-Agent"),
		RemoteAddr: r.RemoteAddr,
	}
	
	if p.enableStack {
		panicInfo.Stack = p.getStackTrace()
	}
	
	// 记录结构化日志
	p.logPanicStructured(panicInfo)
	
	// 通知处理器
	if p.notifyHandler != nil {
		err := fmt.Errorf("http handler panic: %v", recovered)
		p.notifyHandler(err, panicInfo.Stack)
	}
	
	// 返回统一错误响应
	p.writeErrorResponse(w, r, recovered)
}

// logPanic 记录panic日志
func (p *PanicHandler) logPanic(recovered interface{}, context string) {
	stack := ""
	if p.enableStack {
		stack = p.getStackTrace()
	}
	
	logx.Errorf("[PANIC] %s panic recovered: %v\nStack: %s", 
		context, recovered, stack)
}

// logPanicStructured 记录结构化panic日志
func (p *PanicHandler) logPanicStructured(panicInfo *PanicInfo) {
	entry := &logging.StructuredLog{
		Error: &logging.ErrorInfo{
			Type:    fmt.Sprintf("%T", panicInfo.Error),
			Message: fmt.Sprintf("%v", panicInfo.Error),
			Stack:   panicInfo.Stack,
		},
		Request: &logging.RequestInfo{
			Method:     panicInfo.Method,
			Path:       panicInfo.RequestURI,
			UserAgent:  panicInfo.UserAgent,
			RemoteAddr: panicInfo.RemoteAddr,
		},
		Fields: map[string]interface{}{
			"panic_recovered": true,
			"panic_time":      panicInfo.Timestamp.Format(time.RFC3339Nano),
		},
	}
	
	p.logger.LogStructured(logging.LogLevelFatal, "middleware panic recovered", entry)
}

// writeErrorResponse 写入错误响应
func (p *PanicHandler) writeErrorResponse(w http.ResponseWriter, r *http.Request, recovered interface{}) {
	// 创建内部错误
	middlewareErr := errors.NewInternalError(errors.CodeInternalError, 
		fmt.Errorf("internal server error: %v", recovered))
	
	// 添加请求ID（如果存在）
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		middlewareErr.RequestID = requestID
	}
	
	// 写入HTTP响应
	middlewareErr.WriteHTTPResponse(w)
}

// getStackTrace 获取栈追踪信息
func (p *PanicHandler) getStackTrace() string {
	stack := debug.Stack()
	
	// 限制栈大小
	if len(stack) > p.maxStackSize {
		stack = stack[:p.maxStackSize]
	}
	
	return string(stack)
}

// getFilteredStack 获取过滤后的栈追踪（移除不必要的内部调用）
func (p *PanicHandler) getFilteredStack() string {
	stack := debug.Stack()
	lines := strings.Split(string(stack), "\n")
	
	var filtered []string
	skip := 0
	
	for _, line := range lines {
		// 跳过panic恢复相关的栈帧
		if strings.Contains(line, "runtime/panic.go") ||
		   strings.Contains(line, "recovery/panic_handler.go") {
			skip = 2 // 跳过当前行和下一行（文件路径行）
			continue
		}
		
		if skip > 0 {
			skip--
			continue
		}
		
		filtered = append(filtered, line)
		
		// 限制栈深度
		if len(filtered) > 50 { // 最多25层调用栈
			break
		}
	}
	
	result := strings.Join(filtered, "\n")
	
	// 限制总大小
	if len(result) > p.maxStackSize {
		result = result[:p.maxStackSize]
	}
	
	return result
}

// GetCallerInfo 获取调用者信息
func GetCallerInfo(skip int) (string, string, int) {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "", "", 0
	}
	
	fn := runtime.FuncForPC(pc)
	funcName := ""
	if fn != nil {
		funcName = fn.Name()
	}
	
	return funcName, file, line
}

// SafeCall 安全调用函数，捕获panic并转换为error
func SafeCall(fn func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic recovered: %v", recovered)
		}
	}()
	
	return fn()
}

// SafeCallWithValue 安全调用返回值的函数
func SafeCallWithValue[T any](fn func() (T, error)) (result T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var zero T
			result = zero
			err = fmt.Errorf("panic recovered: %v", recovered)
		}
	}()
	
	return fn()
}

// GlobalPanicHandler 全局panic处理器
var GlobalPanicHandler = NewPanicHandler("global")

// InstallGlobalPanicHandler 安装全局panic处理器
func InstallGlobalPanicHandler(notifyHandler func(error, string)) {
	GlobalPanicHandler.WithNotifyHandler(notifyHandler)
	
	// 处理未捕获的panic
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				GlobalPanicHandler.logPanic(recovered, "global panic handler")
				
				if notifyHandler != nil {
					err := fmt.Errorf("unhandled panic: %v", recovered)
					notifyHandler(err, GlobalPanicHandler.getStackTrace())
				}
			}
		}()
		
		// 这里可以添加全局错误监控逻辑
		select {} // 永久阻塞
	}()
}

// Must 函数包装器，将panic转换为错误
func Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// MustNot 确保没有错误，有错误则panic
func MustNot(err error) {
	if err != nil {
		panic(err)
	}
}

// Try 尝试执行函数，返回结果和是否成功
func Try[T any](fn func() T) (result T, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	
	result = fn()
	ok = true
	return
}