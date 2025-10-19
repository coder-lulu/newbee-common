package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/utils/pointy"
	"github.com/coder-lulu/newbee-core/rpc/types/core"
	"github.com/zeromicro/go-zero/core/logx"
)

// 内置审计写入器 - 简化集成，消除微服务实现AuditWriter的复杂性

// BuiltinAuditWriter 通用审计数据写入器 - 内置在中间件中
type BuiltinAuditWriter struct {
	svcProvider AuditSvcProvider
	rpcClient   interface{} // 具体的RPC客户端类型
}

// NewBuiltinAuditWriter 创建内置审计写入器
func NewBuiltinAuditWriter(svcProvider AuditSvcProvider) *BuiltinAuditWriter {
	writer := &BuiltinAuditWriter{
		svcProvider: svcProvider,
	}

	// 获取RPC客户端
	if svcProvider != nil {
		writer.rpcClient = svcProvider.GetCoreRpcClient()

		// 添加调试日志
		if writer.rpcClient == nil {
			logx.Errorw("CRITICAL: Core RPC client is nil from service provider",
				logx.Field("svcProvider_type", fmt.Sprintf("%T", svcProvider)))
		} else {
			logx.Infow("BuiltinAuditWriter initialized with valid RPC client",
				logx.Field("rpcClient_type", fmt.Sprintf("%T", writer.rpcClient)))
		}
	} else {
		logx.Error("CRITICAL: Service provider is nil, audit logs will be lost!")
	}

	return writer
}

// WriteAuditLog 实现framework.AuditWriter接口
func (w *BuiltinAuditWriter) WriteAuditLog(ctx context.Context, auditData framework.AuditLogData) error {
	if w.rpcClient == nil {
		return fmt.Errorf("core RPC client not available")
	}

	// 优先尝试类型断言，避免反射调用
	if auditClient, ok := w.rpcClient.(AuditRPCClient); ok {
		return w.writeToRpcDirect(ctx, auditData, auditClient)
	}

	// 降级到反射调用（向后兼容）
	logx.Errorw("Using reflection fallback for RPC call - consider implementing AuditRPCClient interface",
		logx.Field("client_type", fmt.Sprintf("%T", w.rpcClient)))
	return w.writeToRpc(ctx, auditData)
}

// writeToRpcDirect 直接调用RPC服务（无反射）
func (w *BuiltinAuditWriter) writeToRpcDirect(ctx context.Context, auditData framework.AuditLogData, client AuditRPCClient) error {
	// 构建审计信息
	auditInfo := &AuditLogInfo{
		TenantID:     auditData.TenantID,
		UserID:       auditData.UserID,
		UserName:     w.resolveUserName(auditData),
		Method:       auditData.Method,
		Path:         auditData.Path,
		ResourceName: auditData.ResourceName,
		ResourceType: w.resolveResourceType(auditData),
		ResourceID:   w.resolveResourceID(auditData),
		StatusCode:   auditData.StatusCode,
		DurationMs:   auditData.DurationMs,
		UserAgent:    auditData.UserAgent,
		ClientIP:     auditData.ClientIP,
		RequestData:  auditData.RequestData,
		ResponseData: auditData.ResponseData,
		Metadata:     auditData.Metadata,
	}

	// 直接调用，性能比反射快10-100倍
	result, err := client.CreateAuditLog(ctx, auditInfo)
	if err != nil {
		logx.Errorw("Failed to create audit log via direct RPC call", logx.Field("error", err))
		return err
	}

	if !result.Success {
		err := fmt.Errorf("audit log creation failed: %s", result.Message)
		logx.Errorw("Audit log creation returned failure", logx.Field("error", err))
		return err
	}

	logx.Infow("Audit log created successfully via direct RPC call",
		logx.Field("tenant_id", auditData.TenantID),
		logx.Field("user_id", auditData.UserID),
		logx.Field("audit_id", result.AuditID),
		logx.Field("path", auditData.Path))

	return nil
}

// writeToRpc 写入到RPC服务（反射调用 - 向后兼容）
func (w *BuiltinAuditWriter) writeToRpc(ctx context.Context, auditData framework.AuditLogData) error {
	if w.rpcClient == nil {
		logx.Error("Core RPC client is nil")
		return nil // 静默失败，避免影响主业务
	}

	// 通过反射调用RPC客户端的CreateAuditLog方法
	return w.callCreateAuditLogViaReflection(ctx, auditData)
}

// callCreateAuditLogViaReflection 通过反射调用RPC客户端的CreateAuditLog方法
func (w *BuiltinAuditWriter) callCreateAuditLogViaReflection(ctx context.Context, auditData framework.AuditLogData) error {
	// 构造审计日志信息
	auditInfo := w.buildAuditLogInfo(auditData)

	// 使用反射调用CreateAuditLog方法
	clientValue := reflect.ValueOf(w.rpcClient)

	// 查找CreateAuditLog方法（在原始值上查找，不要调用Elem()）
	method := clientValue.MethodByName("CreateAuditLog")
	if !method.IsValid() {
		// 调试信息：列出所有可用的方法
		clientType := reflect.TypeOf(w.rpcClient)
		methodCount := clientValue.NumMethod()
		methods := make([]string, methodCount)
		for i := 0; i < methodCount; i++ {
			methods[i] = clientType.Method(i).Name
		}

		logx.Errorw("CreateAuditLog method not found on client",
			logx.Field("client_type", clientType),
			logx.Field("available_methods", methods))
		return fmt.Errorf("CreateAuditLog method not found on RPC client %T", w.rpcClient)
	}

	// 准备参数
	ctxValue := reflect.ValueOf(ctx)
	auditInfoValue := reflect.ValueOf(auditInfo)

	logx.Debugw("Calling CreateAuditLog via reflection",
		logx.Field("client_type", reflect.TypeOf(w.rpcClient)),
		logx.Field("method_valid", method.IsValid()),
		logx.Field("audit_info_type", reflect.TypeOf(auditInfo)))

	// 调用方法
	results := method.Call([]reflect.Value{ctxValue, auditInfoValue})

	// 检查返回值
	if len(results) >= 2 {
		if errValue := results[1]; !errValue.IsNil() {
			if err, ok := errValue.Interface().(error); ok {
				logx.Errorw("Failed to create audit log via RPC", logx.Field("error", err))
				return err
			}
		}
	}

	logx.Infow("Audit log created successfully via RPC",
		logx.Field("tenant_id", auditData.TenantID),
		logx.Field("user_id", auditData.UserID),
		logx.Field("path", auditData.Path))

	return nil
}

// buildAuditLogInfo 构造审计日志信息
func (w *BuiltinAuditWriter) buildAuditLogInfo(auditData framework.AuditLogData) interface{} {
	// 映射HTTP方法到操作类型
	operationType := w.mapMethodToOperationType(auditData.Method)

	// 直接构造正确的core.AuditLogInfo结构体
	resourceType := w.resolveResourceType(auditData)
	resourceID := w.resolveResourceID(auditData)

	var metadataString *string
	if len(auditData.Metadata) > 0 {
		if payload, err := json.Marshal(auditData.Metadata); err == nil {
			value := string(payload)
			metadataString = &value
		} else {
			logx.Errorw("Failed to marshal audit metadata", logx.Field("error", err))
		}
	}

	resolvedUserName := w.resolveUserName(auditData)

	auditInfo := &core.AuditLogInfo{
		TenantId:       pointy.GetPointer(auditData.TenantID),
		UserId:         pointy.GetPointer(auditData.UserID),
		UserName:       pointy.GetPointer(resolvedUserName),
		RequestMethod:  pointy.GetPointer(auditData.Method),
		RequestPath:    pointy.GetPointer(auditData.Path),
		ResponseStatus: pointy.GetPointer(int64(auditData.StatusCode)),
		DurationMs:     pointy.GetPointer(auditData.DurationMs),
		UserAgent:      pointy.GetPointer(auditData.UserAgent),
		IpAddress:      pointy.GetPointer(auditData.ClientIP),
		RequestData:    pointy.GetPointer(auditData.RequestData),
		ResponseData:   pointy.GetPointer(auditData.ResponseData),
		OperationType:  pointy.GetPointer(operationType),
		ResourceType:   pointy.GetPointer(resourceType),
		ResourceId:     pointy.GetPointer(resourceID),
		ErrorMessage:   pointy.GetPointer(""), // 成功请求时错误信息为空
	}

	if metadataString != nil {
		auditInfo.Metadata = metadataString
	}

	logx.Debugw("Built core.AuditLogInfo struct",
		logx.Field("tenant_id", auditData.TenantID),
		logx.Field("user_id", auditData.UserID),
		logx.Field("operation_type", operationType),
		logx.Field("path", auditData.Path))

	return auditInfo
}

func (w *BuiltinAuditWriter) resolveResourceType(auditData framework.AuditLogData) string {
	if auditData.ResourceType != "" {
		return auditData.ResourceType
	}
	if auditData.ResourceName != "" {
		return auditData.ResourceName
	}
	return auditData.Path
}

func (w *BuiltinAuditWriter) resolveResourceID(auditData framework.AuditLogData) string {
	if auditData.ResourceID != "" {
		return auditData.ResourceID
	}
	return auditData.Path
}

func (w *BuiltinAuditWriter) resolveUserName(auditData framework.AuditLogData) string {
	if auditData.UserName != "" {
		return auditData.UserName
	}
	return auditData.UserID
}

// mapMethodToOperationType 映射HTTP方法到操作类型
func (w *BuiltinAuditWriter) mapMethodToOperationType(method string) string {
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

// =================================================================
// 简化的服务上下文接口 - 微服务只需要实现这个
// =================================================================

// SimplifiedSvcContext 简化的服务上下文接口
// 微服务只需要实现这个接口，不需要实现完整的AuditWriter
type SimplifiedSvcContext interface {
	// 获取Core RPC客户端 - 具体类型由微服务决定
	GetCoreRpcClient() interface{}

	// 可选：获取数据库连接（用于直接数据库写入）
	GetDB() interface{}
}

// DirectDBWriter 直接数据库写入器（可选实现）
type DirectDBWriter struct {
	db interface{} // 数据库连接
}

func NewDirectDBWriter(db interface{}) *DirectDBWriter {
	return &DirectDBWriter{db: db}
}

func (w *DirectDBWriter) WriteAuditLog(ctx context.Context, auditData framework.AuditLogData) error {
	// TODO: 实现直接数据库写入逻辑
	// 可以使用ent、gorm或原生SQL
	logx.Infow("Direct DB audit log write", logx.Field("audit_data", auditData))
	return nil
}

// =================================================================
// 向后兼容适配器 - 适配现有服务上下文
// =================================================================

// SimpleSvcAdapter 简单的服务上下文适配器
// 将任何具有GetCoreRpcClient方法的服务上下文适配为AuditSvcProvider
type SimpleSvcAdapter struct {
	svcCtx interface{} // 服务上下文
}

// NewSimpleSvcAdapter 创建简单的服务上下文适配器
func NewSimpleSvcAdapter(svcCtx interface{}) *SimpleSvcAdapter {
	return &SimpleSvcAdapter{
		svcCtx: svcCtx,
	}
}

// GetCoreRpcClient 实现AuditSvcProvider接口
func (adapter *SimpleSvcAdapter) GetCoreRpcClient() interface{} {
	if adapter.svcCtx == nil {
		return nil
	}

	// 使用反射查找GetCoreRpcClient方法
	svcValue := reflect.ValueOf(adapter.svcCtx)

	// 先尝试在原始值上查找方法
	method := svcValue.MethodByName("GetCoreRpcClient")
	if !method.IsValid() {
		// 如果是指针，也尝试在指针类型上查找方法
		if svcValue.Kind() == reflect.Ptr && !svcValue.IsNil() {
			method = svcValue.MethodByName("GetCoreRpcClient")
		}
	}

	if !method.IsValid() {
		logx.Errorw("GetCoreRpcClient method not found on service context",
			logx.Field("context_type", reflect.TypeOf(adapter.svcCtx)))
		return nil
	}

	// 调用方法获取RPC客户端
	results := method.Call([]reflect.Value{})
	if len(results) > 0 {
		return results[0].Interface()
	}

	return nil
}
