// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

import (
	"context"
	
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/redis/go-redis/v9"
)

// AuditWriter defines the interface for writing audit logs
// This allows different implementations without coupling to specific services
type AuditWriter interface {
	WriteAuditLog(ctx context.Context, auditData AuditLogData) error
}

// ApiResourceProvider defines the interface for getting API resource information
// This allows different implementations without coupling to specific services
type ApiResourceProvider interface {
	GetApiResourceName(ctx context.Context, method, path string) (string, error)
}

// AuditLogData represents the structured data for an audit log entry
type AuditLogData struct {
	TenantID       string
	UserID         string
	UserName       string
	Method         string
	Path           string
	ResourceName   string // 资源名称
	StatusCode     int
	DurationMs     int64
	UserAgent      string
	ClientIP       string
	RequestData    string
	ResponseData   string
}

// CoreServices is a container for shared, foundational services that are injected
// into each middleware plugin.
type CoreServices struct {
	Config            *UnifiedConfig
	ContextManager    *keys.ContextManager
	Context           context.Context       // 全局上下文
	Redis             redis.Cmdable         // Redis客户端接口
	AuditWriter       AuditWriter           // 审计日志写入器接口 (已废弃，推荐使用内置写入器)
	ApiResourceProvider ApiResourceProvider  // API资源信息提供器接口
	Metrics           *PerformanceMetrics   // 性能指标收集器
}

// SimplifiedCoreServices 简化的核心服务 - 用于新的集成方式
type SimplifiedCoreServices struct {
	Config         *UnifiedConfig
	ContextManager *keys.ContextManager
	Context        context.Context
	Redis          redis.Cmdable
	// 移除AuditWriter - 由审计中间件内部处理
	ApiResourceProvider ApiResourceProvider
}
