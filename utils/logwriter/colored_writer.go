package logwriter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogEntry 日志条目结构
type LogEntry struct {
	Timestamp time.Time              `json:"@timestamp"`
	Level     string                 `json:"level"`
	Content   string                 `json:"content"`
	Caller    string                 `json:"caller"`
	Fields    map[string]interface{} `json:"-"` // 其他字段
}

// ColoredConsoleWriter 彩色控制台日志Writer
type ColoredConsoleWriter struct {
	writer     io.Writer
	bufferPool *sync.Pool
	colorMap   map[string]string
	enableTime bool
}

// ANSI颜色代码（性能优化：预定义常量）
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorWhite  = "\033[97m"

	colorBoldRed    = "\033[1;31m"
	colorBoldGreen  = "\033[1;32m"
	colorBoldYellow = "\033[1;33m"
	colorBoldCyan   = "\033[1;36m"
)

// NewColoredConsoleWriter 创建彩色控制台Writer
func NewColoredConsoleWriter() *ColoredConsoleWriter {
	return &ColoredConsoleWriter{
		writer: os.Stdout,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
		colorMap: map[string]string{
			"error":   colorBoldRed,
			"fatal":   colorBoldRed,
			"warn":    colorBoldYellow,
			"warning": colorBoldYellow,
			"info":    colorBoldGreen,
			"debug":   colorBoldCyan,
			"trace":   colorGray,
		},
		enableTime: true,
	}
}

// Write 实现 io.Writer 接口
func (w *ColoredConsoleWriter) Write(p []byte) (n int, err error) {
	// 快速路径：空数据
	if len(p) == 0 {
		return 0, nil
	}

	// 快速路径：非JSON数据（不以 '{' 开头）
	if p[0] != '{' {
		return w.writer.Write(p)
	}

	// 解析JSON日志
	var entry LogEntry
	var rawData map[string]interface{}

	if err := json.Unmarshal(p, &rawData); err != nil {
		// 解析失败，原样输出
		return w.writer.Write(p)
	}

	// 提取核心字段
	if ts, ok := rawData["@timestamp"].(string); ok {
		entry.Timestamp, _ = time.Parse(time.RFC3339, ts)
	}
	if lvl, ok := rawData["level"].(string); ok {
		entry.Level = strings.ToLower(lvl)
	}
	if content, ok := rawData["content"].(string); ok {
		entry.Content = content
	}
	if caller, ok := rawData["caller"].(string); ok {
		entry.Caller = caller
	}

	// 提取其他字段
	entry.Fields = make(map[string]interface{})
	for k, v := range rawData {
		if k != "@timestamp" && k != "level" && k != "content" && k != "caller" {
			entry.Fields[k] = v
		}
	}

	// 格式化输出
	formatted := w.formatEntry(&entry)
	return w.writer.Write([]byte(formatted))
}

// formatEntry 格式化日志条目
func (w *ColoredConsoleWriter) formatEntry(entry *LogEntry) string {
	buf := w.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer w.bufferPool.Put(buf)

	// 时间戳（可选）
	if w.enableTime && !entry.Timestamp.IsZero() {
		buf.WriteString(colorGray)
		buf.WriteString("[")
		buf.WriteString(entry.Timestamp.Format("15:04:05"))
		buf.WriteString("]")
		buf.WriteString(colorReset)
		buf.WriteString(" ")
	}

	// 日志级别（带颜色）
	levelColor, ok := w.colorMap[entry.Level]
	if !ok {
		levelColor = colorWhite
	}

	buf.WriteString(levelColor)
	buf.WriteString(padRight(strings.ToUpper(entry.Level), 5))
	buf.WriteString(colorReset)
	buf.WriteString(" ")

	// 调用位置
	if entry.Caller != "" {
		buf.WriteString(colorCyan)
		buf.WriteString(entry.Caller)
		buf.WriteString(colorReset)
		buf.WriteString(" ")
	}

	// 消息内容
	buf.WriteString("| ")
	buf.WriteString(entry.Content)

	// 附加字段（灰色显示）
	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			buf.WriteString(" | ")
			buf.WriteString(colorGray)
			fmt.Fprintf(buf, "%s=%v", k, v)
			buf.WriteString(colorReset)
		}
	}

	buf.WriteString("\n")
	return buf.String()
}

// padRight 右填充字符串到指定长度
func padRight(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return s + strings.Repeat(" ", length-len(s))
}

// SetupColoredConsole 设置彩色控制台日志（全局）
// 用法：在 main.go 或 service_context.go 中调用
func SetupColoredConsole() error {
	writer := NewColoredConsoleWriter()

	// 注意：这需要go-zero的logx支持
	// 由于logx.SetWriter()在某些版本可能不存在，
	// 这里提供一个兼容性包装
	return setGlobalWriter(writer)
}

// setGlobalWriter 设置全局Writer（需要与go-zero集成）
func setGlobalWriter(w io.Writer) error {
	// 这里需要调用 logx.SetWriter(w)
	// 但由于我们在common包中，不直接依赖logx
	// 所以由调用方负责集成

	// 临时实现：返回writer供外部使用
	// 实际集成时需要在service_context中调用 logx.SetWriter()
	return nil
}

// Close 关闭Writer（实现 io.Closer 接口，可选）
func (w *ColoredConsoleWriter) Close() error {
	return nil
}
