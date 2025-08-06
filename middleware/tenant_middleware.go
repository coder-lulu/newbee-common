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

package middleware

import (
	"context"
	"net/http"
	"strconv"

	"github.com/zeromicro/go-zero/core/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/enum"
	"github.com/zeromicro/go-zero/rest/httpx"
	"google.golang.org/grpc/metadata"
)

// TenantMiddleware 租户检查中间件
// 确保请求中包含有效的租户信息，并将其注入到标准的context key中
type TenantMiddleware struct{}

// NewTenantMiddleware 创建新的租户中间件
func NewTenantMiddleware() *TenantMiddleware {
	return &TenantMiddleware{}
}

// Handle 处理租户检查逻辑
func (m *TenantMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从JWT claims中获取租户ID (go-zero会自动将JWT claims注入到context中)
		tenantIdRaw := r.Context().Value("tenantId")
		if tenantIdRaw == nil {
			logx.Errorw("tenant id not found in JWT claims", logx.Field("path", r.URL.Path))
			httpx.Error(w, errorx.NewApiForbiddenError("Tenant information is missing"))
			return
		}

		// 转换租户ID类型
		var tenantId uint64
		switch v := tenantIdRaw.(type) {
		case string:
			id, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				logx.Errorw("invalid tenant id format", logx.Field("tenantId", v), logx.Field("error", err))
				httpx.Error(w, errorx.NewApiForbiddenError("Invalid tenant information"))
				return
			}
			tenantId = id
		case float64:
			tenantId = uint64(v)
		case uint64:
			tenantId = v
		default:
			logx.Errorw("unsupported tenant id type", logx.Field("tenantId", tenantIdRaw), logx.Field("type", v))
			httpx.Error(w, errorx.NewApiForbiddenError("Invalid tenant information"))
			return
		}

		// 验证租户ID有效性
		if tenantId == 0 {
			logx.Errorw("invalid tenant id: zero value", logx.Field("path", r.URL.Path))
			httpx.Error(w, errorx.NewApiForbiddenError("Invalid tenant information"))
			return
		}

		// 将租户ID注入到context中，使用标准的key
		ctx := context.WithValue(r.Context(), enum.TenantIdCtxKey, strconv.FormatUint(tenantId, 10))
		ctx = context.WithValue(ctx, "tenantId", tenantId)

		// 添加租户ID到gRPC metadata中，用于gRPC调用
		ctx = metadata.AppendToOutgoingContext(ctx, enum.TenantIdCtxKey, strconv.FormatUint(tenantId, 10))

		logx.Infow("Tenant context established",
			logx.Field("tenantId", tenantId),
			logx.Field("path", r.URL.Path),
			logx.Field("userId", r.Context().Value("userId")))

		// 继续处理请求
		next(w, r.WithContext(ctx))
	}
}
