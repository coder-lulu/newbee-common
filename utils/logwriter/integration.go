package logwriter

import (
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/service"
)

// EnableColoredLogging 启用彩色日志（推荐在开发环境使用）
//
// 用法示例：
//   if c.Mode == service.DevMode {
//       logwriter.EnableColoredLogging()
//   }
func EnableColoredLogging() {
	coloredWriter := NewColoredConsoleWriter()
	// 使用 logx.NewWriter 包装 io.Writer
	writer := logx.NewWriter(coloredWriter)
	logx.SetWriter(writer)
}

// EnableColoredLoggingForDevMode 条件启用彩色日志（仅开发模式）
//
// 用法示例：
//   logwriter.EnableColoredLoggingForDevMode(c.Mode)
func EnableColoredLoggingForDevMode(mode string) {
	if mode == service.DevMode {
		EnableColoredLogging()
	}
}

// SetupWithOptions 使用自定义选项设置日志
func SetupWithOptions(enableTime bool, mode string) {
	if mode != service.DevMode {
		return // 非开发环境不启用彩色日志
	}

	coloredWriter := NewColoredConsoleWriter()
	coloredWriter.enableTime = enableTime
	// 使用 logx.NewWriter 包装 io.Writer
	writer := logx.NewWriter(coloredWriter)
	logx.SetWriter(writer)
}
