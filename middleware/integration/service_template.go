// Copyright 2024 The NewBee Authors. All Rights Reserved.

package integration

// No imports needed for template strings

// ServiceIntegrationTemplate 服务集成模板
// 提供标准化的服务初始化模板，确保所有服务集成方式一致
type ServiceIntegrationTemplate struct {
	ServiceName string
	ConfigType  string // "api" | "rpc"
}

// GenerateServiceContextTemplate 生成ServiceContext模板代码
func (t *ServiceIntegrationTemplate) GenerateServiceContextTemplate() string {
	if t.ConfigType == "rpc" {
		return t.generateRpcServiceTemplate()
	}
	return t.generateApiServiceTemplate()
}

// generateApiServiceTemplate 生成API服务的ServiceContext模板
func (t *ServiceIntegrationTemplate) generateApiServiceTemplate() string {
	return `// Copyright 2024 The NewBee Authors. All Rights Reserved.

package svc

import (
	"context"
	"embed"

	"github.com/coder-lulu/newbee-common/i18n"
	"github.com/coder-lulu/newbee-common/middleware/integration"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/zrpc"

	"` + t.ServiceName + `/internal/config"
	i18n2 "` + t.ServiceName + `/internal/i18n"
)

//go:embed i18n/locale/*.json
var LocaleFS embed.FS

type ServiceContext struct {
	Config         config.Config
	ContextManager *keys.ContextManager
	Trans          *i18n.Translator
	
	// 统一中间件链
	ManagedMiddlewareChain []rest.Middleware
	
	// 服务特定的依赖（根据需要添加）
	// Redis          redis.UniversalClient
	// SomeRpc        someclient.Some
}

func NewServiceContext(c config.Config) *ServiceContext {
	// 1. 初始化基础依赖
	rds := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    []string{c.RedisConf.Host},
		Password: c.RedisConf.Pass,
		DB:       c.RedisConf.Db,
	})

	// 2. 初始化国际化翻译器
	trans := i18n.NewTranslator(c.I18nConf, i18n2.LocaleFS)

	// 3. 🎯 使用统一中间件集成API
	result, err := integration.Setup(&integration.Config{
		Redis:     rds,
		JWTSecret: c.Middleware.Auth.AccessSecret,
		Mode:      integration.Production, // 可根据需要调整为Development/Testing
		Middleware: &c.Middleware,
		// 可选配置
		// ApiResourceProvider: customProvider,
		// AuditWriter: customWriter,
		// SkipPlugins: []string{"audit"}, // 如果某个服务不需要审计
	})
	if err != nil {
		panic("failed to setup middleware: " + err.Error())
	}

	// 4. 创建服务上下文
	return &ServiceContext{
		Config:                 c,
		ContextManager:         result.ContextManager,
		Trans:                  trans, // 使用直接初始化的国际化翻译器
		ManagedMiddlewareChain: result.Middlewares,
		// 初始化服务特定依赖
		// Redis:   rds,
		// SomeRpc: someclient.NewSome(zrpc.MustNewClient(c.SomeRpc)),
	}
}

// 实现StandardServiceContext接口
func (s *ServiceContext) GetContextManager() *keys.ContextManager {
	return s.ContextManager
}

func (s *ServiceContext) GetManagedMiddlewareChain() []rest.Middleware {
	return s.ManagedMiddlewareChain
}

func (s *ServiceContext) GetTranslator() *i18n.Translator {
	return s.Trans
}`
}

// generateRpcServiceTemplate 生成RPC服务的ServiceContext模板
func (t *ServiceIntegrationTemplate) generateRpcServiceTemplate() string {
	return `// Copyright 2024 The NewBee Authors. All Rights Reserved.

package svc

import (
	"context"

	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/orm/ent"
	"github.com/coder-lulu/newbee-common/orm/ent/hooks"
	"github.com/redis/go-redis/v9"

	"` + t.ServiceName + `/internal/config"
)

type ServiceContext struct {
	Config         config.Config
	ContextManager *keys.ContextManager
	DB             *ent.Client
	Redis          redis.UniversalClient
	
	// 服务特定的依赖（根据需要添加）
	// SomeRpc        someclient.Some
}

func NewServiceContext(c config.Config) *ServiceContext {
	// 1. 初始化数据库连接
	db := ent.NewClient(
		ent.Database(c.DatabaseConf.Type),
		ent.ConnectParams(c.DatabaseConf.GetDSN()),
	)

	// 2. 🎯 使用统一Hook系统 - 一键设置租户和部门Hook
	// 根据服务需要，添加特定的系统表排除规则
	// hooks.AddExcludedTable("system_table1")
	// hooks.AddExcludedTable("system_table2")

	// 一键设置：初始化配置 + 注册所有hooks (租户Hook + 部门Hook)
	if err := hooks.QuickSetup(db); err != nil {
		panic("统一Hook初始化失败: " + err.Error())
	}

	// 注册数据权限拦截器（根据服务需要）
	// hooks.RegisterDataPermissionInterceptorsWithTenant(db,
	//     "table1", "table2", "table3")

	// 3. 初始化Redis
	rds := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    []string{c.RedisConf.Host},
		Password: c.RedisConf.Pass,
		DB:       c.RedisConf.Db,
	})

	// 4. 初始化ContextManager
	cm := keys.NewContextManager()

	return &ServiceContext{
		Config:         c,
		ContextManager: cm,
		DB:             db,
		Redis:          rds,
		// 初始化服务特定依赖
		// SomeRpc: someclient.NewSome(zrpc.MustNewClient(c.SomeRpc)),
	}
}

// 实现基础上下文管理接口
func (s *ServiceContext) GetContextManager() *keys.ContextManager {
	return s.ContextManager
}`
}

// GenerateMainTemplate 生成main函数模板
func (t *ServiceIntegrationTemplate) GenerateMainTemplate() string {
	if t.ConfigType == "rpc" {
		return t.generateRpcMainTemplate()
	}
	return t.generateApiMainTemplate()
}

// generateApiMainTemplate 生成API服务main函数模板
func (t *ServiceIntegrationTemplate) generateApiMainTemplate() string {
	return `// Copyright 2024 The NewBee Authors. All Rights Reserved.

package main

import (
	"flag"
	"fmt"

	"github.com/coder-lulu/newbee-common/middleware/integration"
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/rest"

	"` + t.ServiceName + `/internal/config"
	"` + t.ServiceName + `/internal/handler"
	"` + t.ServiceName + `/internal/svc"
)

var configFile = flag.String("f", "etc/` + t.ServiceName + `.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)

	server := rest.MustNewServer(c.RestConf, rest.WithCors(c.CROSConf.Address))
	defer server.Stop()

	ctx := svc.NewServiceContext(c)

	// 应用统一中间件链
	for _, middleware := range ctx.ManagedMiddlewareChain {
		server.Use(middleware)
	}

	handler.RegisterHandlers(server, ctx)

	fmt.Printf("Starting server at %s:%d...\n", c.Host, c.Port)
	server.Start()
}`
}

// generateRpcMainTemplate 生成RPC服务main函数模板
func (t *ServiceIntegrationTemplate) generateRpcMainTemplate() string {
	return `// Copyright 2024 The NewBee Authors. All Rights Reserved.

package main

import (
	"flag"
	"fmt"

	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/service"
	"github.com/zeromicro/go-zero/zrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"` + t.ServiceName + `/internal/config"
	"` + t.ServiceName + `/internal/server"
	"` + t.ServiceName + `/internal/svc"
	"` + t.ServiceName + `/` + t.ServiceName + `"
)

var configFile = flag.String("f", "etc/` + t.ServiceName + `.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)
	ctx := svc.NewServiceContext(c)

	s := zrpc.MustNewServer(c.RpcServerConf, func(grpcServer *grpc.Server) {
		` + t.ServiceName + `.Register` + t.ServiceName + `Server(grpcServer, server.New` + t.ServiceName + `Server(ctx))

		if c.Mode == service.DevMode || c.Mode == service.TestMode {
			reflection.Register(grpcServer)
		}
	})
	defer s.Stop()

	fmt.Printf("Starting rpc server at %s...\n", c.ListenOn)
	s.Start()
}`
}

// GenerateConfigTemplate 生成配置模板
func (t *ServiceIntegrationTemplate) GenerateConfigTemplate() string {
	baseConfig := `# Copyright 2024 The NewBee Authors. All Rights Reserved.

Name: ` + t.ServiceName + `
Host: 0.0.0.0
Port: 8080

# 数据库配置
DatabaseConf:
  Type: mysql
  Host: localhost
  Port: 3306
  DBName: ` + t.ServiceName + `
  Username: root
  Password: ""
  MaxOpenConn: 100

# Redis配置
RedisConf:
  Host: localhost:6379
  Pass: ""
  Db: 0

# 国际化配置
I18nConf:
  Default: zh
  Langs:
    - zh
    - en

# 统一中间件配置
Middleware:
  # 认证中间件
  Auth:
    Enabled: true
    AccessSecret: "your-jwt-secret"
    SkipPaths:
      - "/health"
      - "/ping"
      - "/swagger"

  # 租户检查中间件  
  TenantCheck:
    Enabled: true
    ValidateStatus: true
    RateLimitEnabled: true
    MaxRequestsPerMin: 1000
    CacheEnabled: true
    SkipPaths:
      - "/health"
      - "/ping"

  # 数据权限中间件
  DataPerm:
    Enabled: true
    SkipPaths:
      - "/health"
      - "/ping"

  # 审计中间件
  Audit:
    Enabled: true
    SkipPaths:
      - "/health"
      - "/ping"
      - "/swagger"`

	if t.ConfigType == "api" {
		return baseConfig + `

# REST服务配置
RestConf:
  ServiceConf:
    Name: ` + t.ServiceName + `
    Mode: dev
  Host: 0.0.0.0
  Port: 8080
  Timeout: 30s

# CORS配置
CROSConf:
  Address: "*"`
	}

	return baseConfig + `

# RPC服务配置
RpcServerConf:
  ServiceConf:
    Name: ` + t.ServiceName + `
    Mode: dev
  ListenOn: 0.0.0.0:9090
  Timeout: 30s`
}

// GenerateRoutesTemplate 生成routes.go模板（仅API服务）
func (t *ServiceIntegrationTemplate) GenerateRoutesTemplate() string {
	if t.ConfigType != "api" {
		return ""
	}

	return `// Copyright 2024 The NewBee Authors. All Rights Reserved.

package handler

import (
	"net/http"

	"github.com/zeromicro/go-zero/rest"

	"` + t.ServiceName + `/internal/svc"
)

func RegisterHandlers(server *rest.Server, serverCtx *svc.ServiceContext) {
	// 公开接口（无需认证）
	server.AddRoutes(
		[]rest.Route{
			{
				Method:  http.MethodGet,
				Path:    "/health",
				Handler: healthHandler,
			},
			{
				Method:  http.MethodGet,
				Path:    "/ping", 
				Handler: pingHandler,
			},
		},
	)

	// 受保护的接口（需要完整的中间件链）
	server.AddRoutes(
		rest.WithMiddlewares(
			serverCtx.ManagedMiddlewareChain, // 使用统一中间件链
			[]rest.Route{
				{
					Method:  http.MethodGet,
					Path:    "/api/example",
					Handler: exampleHandler(serverCtx),
				},
				// 添加更多受保护的路由...
			},
		),
	)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func exampleHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 这里可以安全地使用svcCtx.ContextManager获取认证信息
		ctx := r.Context()
		userID := svcCtx.ContextManager.GetUserID(ctx)
		tenantID := svcCtx.ContextManager.GetTenantID(ctx)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(` + "`" + `{"message": "Hello", "user_id": "%s", "tenant_id": "%s"}` + "`" + `, userID, tenantID)))
	}
}`
}