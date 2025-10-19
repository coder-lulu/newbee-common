// Copyright 2023 The Ryan SU Authors (https://github.com/suyuan32). All Rights Reserved.
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

package tenantctx

import (
	"context"
	"strconv"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/metadata"
)

type TenantKey string

const PublicAccess TenantKey = "public-access"

// GetTenantIDFromCtx returns tenant id from context.
// If error occurs, return default tenant ID.
// 现在使用统一的keys包来确保一致性
func GetTenantIDFromCtx(ctx context.Context) uint64 {
	// 1. 直接从上下文中读取（即使是SystemContext，也允许显式值）
	if tenantIDStr, ok := ctx.Value(keys.TenantIDKey).(string); ok && tenantIDStr != "" {
		if id, err := strconv.Atoi(tenantIDStr); err == nil {
			return uint64(id)
		}
	}

	// 2. 尝试从 gRPC metadata 中读取
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if data := md.Get(keys.TenantIDKey.String()); len(data) > 0 && data[0] != "" {
			if id, err := strconv.Atoi(data[0]); err == nil {
				return uint64(id)
			}
		}
	}

	// 3. 如果是系统上下文且没有显式租户ID，则返回0
	if flag, ok := ctx.Value(keys.SystemContextKey).(bool); ok && flag {
		return 0
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if flags := md.Get(string(keys.SystemContextKey)); len(flags) > 0 && flags[0] == "true" {
			return 0
		}
	}

	// 4. 记录缺失情况并返回0，保持兼容
	logx.Error("failed to get tenant id from context", logx.Field("detail", ctx))
	return 0
}

// GetPublicAccessCtx returns true when context is for public access only.
func GetPublicAccessCtx(ctx context.Context) bool {
	var policy string
	var ok bool

	if policy, ok = ctx.Value(PublicAccess).(string); !ok {
		if md, ok := metadata.FromIncomingContext(ctx); !ok {
			return false
		} else {
			if data := md.Get(string(PublicAccess)); len(data) > 0 {
				policy = data[0]
			} else {
				return false
			}
		}
	}

	if policy == "allow" {
		return true
	}

	return false
}

// PublicCtx returns a context for accessing public/shared data only.
// This should only be used for:
// - System-wide configuration data (OAuth providers, email templates)
// - Public tenant information (name, status - no sensitive data)
// - Global dictionaries (countries, currencies)
// NEVER use for user data, business data, or any tenant-sensitive information.
func PublicCtx(ctx context.Context) context.Context {
	ctx = metadata.AppendToOutgoingContext(ctx, string(PublicAccess), "allow")
	return context.WithValue(ctx, PublicAccess, "allow")
}
