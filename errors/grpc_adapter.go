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

package errors

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCErrorAdapter gRPC 错误适配器
type GRPCErrorAdapter struct {
	includeDetails bool
	includeContext bool
	includeTrace   bool
}

// NewGRPCErrorAdapter 创建 gRPC 错误适配器
func NewGRPCErrorAdapter() *GRPCErrorAdapter {
	return &GRPCErrorAdapter{
		includeDetails: true,
		includeContext: false,
		includeTrace:   false,
	}
}

// WithDetails 设置是否包含详细信息
func (a *GRPCErrorAdapter) WithDetails(include bool) *GRPCErrorAdapter {
	a.includeDetails = include
	return a
}

// WithContext 设置是否包含上下文信息
func (a *GRPCErrorAdapter) WithContext(include bool) *GRPCErrorAdapter {
	a.includeContext = include
	return a
}

// WithTrace 设置是否包含追踪信息
func (a *GRPCErrorAdapter) WithTrace(include bool) *GRPCErrorAdapter {
	a.includeTrace = include
	return a
}

// ToGRPCError 将错误转换为 gRPC 错误
func (a *GRPCErrorAdapter) ToGRPCError(err error) error {
	if err == nil {
		return nil
	}

	var unifiedErr *UnifiedError
	if ue, ok := err.(*UnifiedError); ok {
		unifiedErr = ue
	} else {
		unifiedErr = Wrap(err, ErrCodeInternal, "internal server error")
	}

	grpcCode := a.getGRPCCode(unifiedErr.Code)

	// 构建状态详细信息
	st := status.New(grpcCode, unifiedErr.Message)

	// 使用 gRPC metadata 添加详细信息而不是 status details
	// 这样避免了 protobuf 依赖问题

	return st.Err()
}

// getGRPCCode 根据错误代码获取 gRPC 状态码
func (a *GRPCErrorAdapter) getGRPCCode(code ErrorCode) codes.Code {
	switch code {
	case ErrCodeValidation:
		return codes.InvalidArgument
	case ErrCodeNotFound:
		return codes.NotFound
	case ErrCodeUnauthorized:
		return codes.Unauthenticated
	case ErrCodeForbidden, ErrCodeDataPermission:
		return codes.PermissionDenied
	case ErrCodeConflict:
		return codes.AlreadyExists
	case ErrCodeTimeout:
		return codes.DeadlineExceeded
	case ErrCodeRateLimit:
		return codes.ResourceExhausted
	case ErrCodeDatabase, ErrCodeConnection:
		return codes.Unavailable
	case ErrCodeConfig:
		return codes.Internal
	case ErrCodeBusiness:
		return codes.FailedPrecondition
	case ErrCodeNetwork, ErrCodeRPC:
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

// 错误详细信息通过 gRPC metadata 传递，避免 protobuf 依赖

// GRPCUnaryServerInterceptor gRPC 一元服务器拦截器
func GRPCUnaryServerInterceptor(adapter *GRPCErrorAdapter) grpc.UnaryServerInterceptor {
	if adapter == nil {
		adapter = NewGRPCErrorAdapter()
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err != nil {
			// 使用错误处理器处理错误
			processedErr := Handle(ctx, err)

			// 转换为 gRPC 错误
			grpcErr := adapter.ToGRPCError(processedErr)
			return resp, grpcErr
		}
		return resp, nil
	}
}

// GRPCStreamServerInterceptor gRPC 流服务器拦截器
func GRPCStreamServerInterceptor(adapter *GRPCErrorAdapter) grpc.StreamServerInterceptor {
	if adapter == nil {
		adapter = NewGRPCErrorAdapter()
	}

	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := handler(srv, stream)
		if err != nil {
			// 使用错误处理器处理错误
			processedErr := Handle(stream.Context(), err)

			// 转换为 gRPC 错误
			grpcErr := adapter.ToGRPCError(processedErr)
			return grpcErr
		}
		return nil
	}
}

// GRPCRecoveryInterceptor gRPC 恢复拦截器
func GRPCRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				var panicErr error
				if e, ok := rec.(error); ok {
					panicErr = e
				} else {
					panicErr = InternalWithCause("panic in gRPC handler", nil)
				}

				// 处理 panic 错误
				processedErr := Handle(ctx, panicErr)
				err = globalGRPCAdapter.ToGRPCError(processedErr)
			}
		}()

		return handler(ctx, req)
	}
}

// GRPCStreamRecoveryInterceptor gRPC 流恢复拦截器
func GRPCStreamRecoveryInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if rec := recover(); rec != nil {
				var panicErr error
				if e, ok := rec.(error); ok {
					panicErr = e
				} else {
					panicErr = InternalWithCause("panic in gRPC stream handler", nil)
				}

				// 处理 panic 错误
				processedErr := Handle(stream.Context(), panicErr)
				err = globalGRPCAdapter.ToGRPCError(processedErr)
			}
		}()

		return handler(srv, stream)
	}
}

// GRPCErrorHandlerInterceptor 带错误处理器的 gRPC 拦截器
func GRPCErrorHandlerInterceptor(handler ErrorHandler, adapter *GRPCErrorAdapter) grpc.UnaryServerInterceptor {
	if adapter == nil {
		adapter = NewGRPCErrorAdapter()
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, grpcHandler grpc.UnaryHandler) (interface{}, error) {
		resp, err := grpcHandler(ctx, req)
		if err != nil {
			// 使用指定的错误处理器处理错误
			processedErr := handler.Handle(ctx, err)

			// 转换为 gRPC 错误
			grpcErr := adapter.ToGRPCError(processedErr)
			return resp, grpcErr
		}
		return resp, nil
	}
}

// GRPCMetadataHandler gRPC 元数据处理器
func GRPCMetadataHandler(ctx context.Context, err *UnifiedError) error {
	// 添加错误信息到 gRPC 元数据
	md := metadata.Pairs(
		"error-code", string(err.Code),
		"error-severity", string(err.Severity),
		"error-retryable", fmt.Sprintf("%v", err.Retryable),
	)

	if err.TraceID != "" {
		md = metadata.Join(md, metadata.Pairs("trace-id", err.TraceID))
	}

	if err.RetryAfter > 0 {
		md = metadata.Join(md, metadata.Pairs("retry-after", fmt.Sprintf("%d", int64(err.RetryAfter.Seconds()))))
	}

	// 发送元数据
	grpc.SendHeader(ctx, md)

	return nil
}

// 全局 gRPC 适配器
var globalGRPCAdapter = NewGRPCErrorAdapter().WithDetails(false).WithTrace(true)

// ToGRPCError 使用全局适配器转换 gRPC 错误
func ToGRPCError(err error) error {
	return globalGRPCAdapter.ToGRPCError(err)
}

// SetGlobalGRPCAdapter 设置全局 gRPC 适配器
func SetGlobalGRPCAdapter(adapter *GRPCErrorAdapter) {
	globalGRPCAdapter = adapter
}

// GetGlobalGRPCAdapter 获取全局 gRPC 适配器
func GetGlobalGRPCAdapter() *GRPCErrorAdapter {
	return globalGRPCAdapter
}

// 注册 gRPC 元数据处理器到全局错误处理器
func init() {
	RegisterHandler(GRPCMetadataHandler)
}

// FromGRPCError 从 gRPC 错误转换为统一错误
func FromGRPCError(err error) *UnifiedError {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return Wrap(err, ErrCodeRPC, "gRPC error")
	}

	code := fromGRPCCode(st.Code())
	unifiedErr := New(code, st.Message())

	// 详细信息可以从 gRPC metadata 中获取
	// 这里简化处理，只使用基本的 gRPC status 信息

	return unifiedErr
}

// fromGRPCCode 从 gRPC 状态码转换为错误代码
func fromGRPCCode(code codes.Code) ErrorCode {
	switch code {
	case codes.InvalidArgument:
		return ErrCodeValidation
	case codes.NotFound:
		return ErrCodeNotFound
	case codes.Unauthenticated:
		return ErrCodeUnauthorized
	case codes.PermissionDenied:
		return ErrCodeForbidden
	case codes.AlreadyExists:
		return ErrCodeConflict
	case codes.DeadlineExceeded:
		return ErrCodeTimeout
	case codes.ResourceExhausted:
		return ErrCodeRateLimit
	case codes.Unavailable:
		return ErrCodeDatabase
	case codes.FailedPrecondition:
		return ErrCodeBusiness
	case codes.Internal:
		return ErrCodeInternal
	default:
		return ErrCodeRPC
	}
}
