// Copyright 2024 The NewBee Authors. All Rights Reserved.

package audit

import (
	"context"
	"encoding/json"

	"github.com/coder-lulu/newbee-core/rpc/coreclient"
	"github.com/coder-lulu/newbee-core/rpc/types/core"
	"github.com/zeromicro/go-zero/core/logx"
)

// CoreClientAdapter 适配器，将Core RPC客户端适配为AuditRPCClient接口
// 消除反射调用，提升性能10-100倍
type CoreClientAdapter struct {
	client coreclient.Core
}

// NewCoreClientAdapter 创建Core客户端适配器
func NewCoreClientAdapter(client coreclient.Core) *CoreClientAdapter {
	return &CoreClientAdapter{
		client: client,
	}
}

// CreateAuditLog 实现AuditRPCClient接口
// 将中间件的审计数据格式转换为Core RPC的格式
func (a *CoreClientAdapter) CreateAuditLog(ctx context.Context, auditInfo *AuditLogInfo) (*AuditLogResult, error) {
	// 转换为Core RPC期望的格式
	resourceType := auditInfo.ResourceType
	if resourceType == "" {
		resourceType = auditInfo.ResourceName
	}
	if resourceType == "" {
		resourceType = auditInfo.Path
	}

	resourceID := auditInfo.ResourceID
	if resourceID == "" {
		resourceID = auditInfo.Path
	}

	userName := auditInfo.UserName
	if userName == "" {
		userName = auditInfo.UserID
	}

	var metadataString *string
	if len(auditInfo.Metadata) > 0 {
		if payload, err := json.Marshal(auditInfo.Metadata); err != nil {
			logx.Errorw("Failed to marshal audit metadata", logx.Field("error", err))
		} else {
			jsonStr := string(payload)
			metadataString = &jsonStr
		}
	}

	coreAuditInfo := &core.AuditLogInfo{
		TenantId:       &auditInfo.TenantID,
		UserId:         &auditInfo.UserID,
		UserName:       &userName,
		RequestMethod:  &auditInfo.Method,
		RequestPath:    &auditInfo.Path,
		ResourceType:   &resourceType,
		ResponseStatus: func() *int64 { status := int64(auditInfo.StatusCode); return &status }(),
		DurationMs:     &auditInfo.DurationMs,
		UserAgent:      &auditInfo.UserAgent,
		IpAddress:      &auditInfo.ClientIP,
		RequestData:    &auditInfo.RequestData,
		ResponseData:   &auditInfo.ResponseData,
		OperationType:  func() *string { op := mapHTTPMethodToOperation(auditInfo.Method); return &op }(),
		ResourceId:     &resourceID,
		ErrorMessage:   func() *string { msg := ""; return &msg }(), // 空错误信息表示成功
	}

	if metadataString != nil {
		coreAuditInfo.Metadata = metadataString
	}

	// 直接调用Core RPC客户端（无反射）
	resp, err := a.client.CreateAuditLog(ctx, coreAuditInfo)
	if err != nil {
		logx.Errorw("Core RPC CreateAuditLog failed",
			logx.Field("error", err),
			logx.Field("tenant_id", auditInfo.TenantID),
			logx.Field("user_id", auditInfo.UserID),
			logx.Field("path", auditInfo.Path))
		return nil, err
	}

	// 转换响应格式
	result := &AuditLogResult{
		Success: true, // Core RPC成功返回即表示成功
		Message: "audit log created successfully",
	}

	// 如果有审计ID，设置到结果中
	if resp.Id != "" {
		result.AuditID = resp.Id
	}

	logx.Infow("Audit log created successfully via Core RPC adapter",
		logx.Field("tenant_id", auditInfo.TenantID),
		logx.Field("user_id", auditInfo.UserID),
		logx.Field("audit_id", result.AuditID),
		logx.Field("path", auditInfo.Path))

	return result, nil
}

// mapHTTPMethodToOperation 映射HTTP方法到操作类型
func mapHTTPMethodToOperation(method string) string {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return "READ"
	case "POST":
		return "CREATE"
	case "PUT", "PATCH":
		return "UPDATE"
	case "DELETE":
		return "DELETE"
	default:
		return "READ"
	}
}

// AdaptCoreClientForAudit 便捷函数：将Core RPC客户端适配为AuditRPCClient
func AdaptCoreClientForAudit(client coreclient.Core) AuditRPCClient {
	return NewCoreClientAdapter(client)
}
