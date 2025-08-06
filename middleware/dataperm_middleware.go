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

package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/redis/go-redis/v9"
	"github.com/coder-lulu/newbee-common/i18n"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/deptctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/rolectx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
	"github.com/zeromicro/go-zero/core/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

// DataPermRPCClient 定义RPC客户端接口，用于初始化权限数据
type DataPermRPCClient interface {
	InitRoleDataPermToRedis(ctx context.Context, req interface{}) (interface{}, error)
	InitDeptDataPermToRedis(ctx context.Context, req interface{}) (interface{}, error)
}

// DataPermConfig 数据权限中间件配置
type DataPermConfig struct {
	// EnableTenantMode 是否启用租户模式
	EnableTenantMode bool
	// DefaultTenantId 默认租户ID（非租户模式使用）
	DefaultTenantId uint64
	// CacheExpiration Redis缓存过期时间（秒），0表示永不过期
	CacheExpiration int
}

// DataPermMiddleware 数据权限中间件
type DataPermMiddleware struct {
	Redis     redis.UniversalClient
	RPCClient DataPermRPCClient
	Trans     *i18n.Translator
	Config    *DataPermConfig
}

// NewDataPermMiddleware 创建新的数据权限中间件实例
func NewDataPermMiddleware(
	redis redis.UniversalClient,
	rpcClient DataPermRPCClient,
	trans *i18n.Translator,
	config *DataPermConfig,
) *DataPermMiddleware {
	// 设置默认配置
	if config == nil {
		config = &DataPermConfig{
			EnableTenantMode: false,
			DefaultTenantId:  entenum.TenantDefaultId,
			CacheExpiration:  0, // 永不过期
		}
	}

	return &DataPermMiddleware{
		Redis:     redis,
		RPCClient: rpcClient,
		Trans:     trans,
		Config:    config,
	}
}

// Handle 处理数据权限中间件逻辑
func (m *DataPermMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var subDept, dataScope, customDept string
		var tenantId uint64 = m.Config.DefaultTenantId

		// 获取部门ID
		deptId, err := deptctx.GetDepartmentIDFromCtx(ctx)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		// 获取角色代码
		roleCodes, err := rolectx.GetRoleIDFromCtx(ctx)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		// 如果启用租户模式，获取租户ID
		if m.Config.EnableTenantMode {
			tenantId = tenantctx.GetTenantIDFromCtx(ctx)
			if tenantId == 0 {
				httpx.Error(w, errorx.NewInternalError("tenant ID not found in context"))
				return
			}
		}

		// 获取数据权限范围
		dataScope, err = m.getDataScope(ctx, roleCodes, tenantId)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		// 将数据权限范围注入上下文
		ctx = datapermctx.WithScopeContext(ctx, dataScope)

		// 根据权限范围处理相关数据
		switch dataScope {
		case entenum.DataPermOwnDeptAndSubStr:
			subDept, err = m.getSubDeptData(ctx, deptId, tenantId)
			if err != nil {
				httpx.Error(w, err)
				return
			}
			ctx = datapermctx.WithSubDeptContext(ctx, subDept)

		case entenum.DataPermCustomDeptStr:
			customDept, err = m.getCustomDeptData(ctx, roleCodes, tenantId)
			if err != nil {
				httpx.Error(w, err)
				return
			}
			ctx = datapermctx.WithCustomDeptContext(ctx, customDept)
		}

		next(w, r.WithContext(ctx))
	}
}

// getDataScope 获取数据权限范围
func (m *DataPermMiddleware) getDataScope(ctx context.Context, roleCodes []string, tenantId uint64) (string, error) {
	var redisKey string
	if m.Config.EnableTenantMode {
		redisKey = datapermctx.GetTenantRoleScopeDataPermRedisKey(roleCodes, tenantId)
	} else {
		redisKey = datapermctx.GetRoleScopeDataPermRedisKey(roleCodes)
	}

	dataScope, err := m.Redis.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 缓存未命中，初始化权限数据
			_, err = m.RPCClient.InitRoleDataPermToRedis(ctx, struct{}{})
			if err != nil {
				return "", err
			}

			// 重新获取
			dataScope, err = m.Redis.Get(ctx, redisKey).Result()
			if err != nil {
				return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
			}
		} else {
			logx.Error("redis error", logx.Field("detail", err))
			return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
		}
	}

	return dataScope, nil
}

// getSubDeptData 获取子部门数据
func (m *DataPermMiddleware) getSubDeptData(ctx context.Context, deptId uint64, tenantId uint64) (string, error) {
	var redisKey string
	if m.Config.EnableTenantMode {
		redisKey = datapermctx.GetTenantSubDeptDataPermRedisKey(deptId, tenantId)
	} else {
		redisKey = datapermctx.GetSubDeptDataPermRedisKey(deptId)
	}

	subDept, err := m.Redis.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 缓存未命中，初始化部门数据
			_, err = m.RPCClient.InitDeptDataPermToRedis(ctx, struct{}{})
			if err != nil {
				return "", err
			}

			// 重新获取
			subDept, err = m.Redis.Get(ctx, redisKey).Result()
			if err != nil {
				return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
			}
		} else {
			logx.Error("redis error", logx.Field("detail", err))
			return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
		}
	}

	return subDept, nil
}

// getCustomDeptData 获取自定义部门数据
func (m *DataPermMiddleware) getCustomDeptData(ctx context.Context, roleCodes []string, tenantId uint64) (string, error) {
	var redisKey string
	if m.Config.EnableTenantMode {
		redisKey = datapermctx.GetTenantRoleCustomDeptDataPermRedisKey(roleCodes, tenantId)
	} else {
		redisKey = datapermctx.GetRoleCustomDeptDataPermRedisKey(roleCodes)
	}

	customDept, err := m.Redis.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 缓存未命中，初始化部门数据
			_, err = m.RPCClient.InitDeptDataPermToRedis(ctx, struct{}{})
			if err != nil {
				return "", err
			}

			// 重新获取
			customDept, err = m.Redis.Get(ctx, redisKey).Result()
			if err != nil {
				return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
			}
		} else {
			logx.Error("redis error", logx.Field("detail", err))
			return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
		}
	}

	return customDept, nil
}