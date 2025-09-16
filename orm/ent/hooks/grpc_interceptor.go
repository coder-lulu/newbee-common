// Copyright 2024 The NewBee Authors. All Rights Reserved.

package hooks

import (
	"context"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// SystemContextClientInterceptor 是一个 gRPC 客户端拦截器，
// 负责将 SystemContext 标识传递到服务端
func SystemContextClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// 检查是否为 SystemContext
		if isSystemContext(ctx) {
			// 将 SystemContext 标识添加到 gRPC metadata
			md, ok := metadata.FromOutgoingContext(ctx)
			if !ok {
				md = metadata.New(nil)
			}
			md.Set(string(keys.SystemContextKey), "true")
			ctx = metadata.NewOutgoingContext(ctx, md)
		}

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// SystemContextStreamClientInterceptor 是一个 gRPC 流式客户端拦截器，
// 负责将 SystemContext 标识传递到服务端
func SystemContextStreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		// 检查是否为 SystemContext
		if isSystemContext(ctx) {
			// 将 SystemContext 标识添加到 gRPC metadata
			md, ok := metadata.FromOutgoingContext(ctx)
			if !ok {
				md = metadata.New(nil)
			}
			md.Set(string(keys.SystemContextKey), "true")
			ctx = metadata.NewOutgoingContext(ctx, md)
		}

		return streamer(ctx, desc, cc, method, opts...)
	}
}