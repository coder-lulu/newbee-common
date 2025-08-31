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

package dataperm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder-lulu/newbee-common/i18n"
	middleware "github.com/coder-lulu/newbee-common/middleware"
	"github.com/coder-lulu/newbee-common/middleware/types"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/datapermctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/deptctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/rolectx"
	"github.com/coder-lulu/newbee-common/orm/ent/entctx/tenantctx"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

// DataPermRPCClient 定义RPC客户端接口，用于初始化权限数据
type DataPermRPCClient interface {
	InitRoleDataPermToRedis(ctx context.Context, req interface{}) (interface{}, error)
	InitDeptDataPermToRedis(ctx context.Context, req interface{}) (interface{}, error)
}

// PermissionRequest 权限请求结构
type PermissionRequest struct {
	RoleCodes []string  `json:"role_codes"`
	TenantID  uint64    `json:"tenant_id"`
	DeptID    uint64    `json:"dept_id"`
	Operation string    `json:"operation"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

// PermissionResult 权限结果结构
type PermissionResult struct {
	DataScope     string        `json:"data_scope"`
	SubDept       string        `json:"sub_dept"`
	CustomDept    string        `json:"custom_dept"`
	Level         string        `json:"level"`
	Source        string        `json:"source"` // cache, basic, emergency, deny
	ExecutionTime time.Duration `json:"execution_time"`
	CacheHit      bool          `json:"cache_hit"`
	FallbackUsed  bool          `json:"fallback_used"`
	ErrorMessage  string        `json:"error_message,omitempty"`
}

// LegacyDataPermConfig 遗留数据权限中间件配置
type LegacyDataPermConfig struct {
	// EnableTenantMode 是否启用租户模式
	EnableTenantMode bool
	// DefaultTenantId 默认租户ID（非租户模式使用）
	DefaultTenantId uint64
	// CacheExpiration Redis缓存过期时间（秒），0表示永不过期
	CacheExpiration int
	// L1Cache L1缓存配置
	L1CacheEnabled bool           `json:"l1_cache_enabled"`
	L1CacheConfig  *types.L1CacheConfig `json:"l1_cache_config,omitempty"`
	// CircuitBreaker 熔断器配置
	CircuitBreakerEnabled bool                  `json:"circuit_breaker_enabled"`
	RedisCircuitBreaker   *types.CircuitBreakerConfig `json:"redis_circuit_breaker,omitempty"`
	RPCCircuitBreaker     *types.CircuitBreakerConfig `json:"rpc_circuit_breaker,omitempty"`
	// Timeout 超时控制配置
	TimeoutConfig *types.TimeoutConfig `json:"timeout_config,omitempty"`
	// Performance configuration | 性能配置
	MemoryThreshold int64   `json:"memory_threshold,omitempty"`
	CPUThreshold    float64 `json:"cpu_threshold,omitempty"`
	// Fallback strategy configuration | 降级策略配置
	FallbackEnabled bool                    `json:"fallback_enabled"`
	FallbackConfig  *types.FallbackStrategyConfig `json:"fallback_config,omitempty"`
}

// DataPermMiddleware 数据权限中间件
type DataPermMiddleware struct {
	Redis     redis.UniversalClient
	RPCClient DataPermRPCClient
	Trans     *i18n.Translator
	Config    *LegacyDataPermConfig
	// 异步刷新控制
	refreshingKeys   sync.Map
	refreshSemaphore chan struct{}
	// Goroutine管理器 - 防止泄漏
	goroutineManager types.GoroutineManager
	// L1缓存层
	l1Cache types.L1Cache
	// 熔断器保护
	redisCircuitBreaker types.CircuitBreaker
	rpcCircuitBreaker   types.CircuitBreaker
	// 性能监控
	metricsCollector    types.MetricsCollector
	performanceAnalyzer types.PerformanceAnalyzer
	// 缓存键优化器
	keyOptimizer *middleware.CacheKeyOptimizer
	// 批量Redis客户端
	batchRedisClient *middleware.BatchRedisClient
	// 多级降级策略
	fallbackStrategy *middleware.FallbackStrategy
	// 健康检查注册表
	healthRegistry *middleware.HealthCheckRegistry
	// 基础监控收集器
	basicMonitor *middleware.BasicMonitoringCollector
}

// NewDataPermMiddleware 创建新的数据权限中间件实例
func NewDataPermMiddleware(
	redis redis.UniversalClient,
	rpcClient DataPermRPCClient,
	trans *i18n.Translator,
	config *LegacyDataPermConfig,
) *DataPermMiddleware {
	// 设置默认配置
	if config == nil {
		config = &LegacyDataPermConfig{
			EnableTenantMode:      false,
			DefaultTenantId:       entenum.TenantDefaultId,
			CacheExpiration:       0,    // 永不过期
			L1CacheEnabled:        true, // 默认启用L1缓存
			CircuitBreakerEnabled: true, // 默认启用熔断器
			FallbackEnabled:       true, // 默认启用降级策略
		}
	}

	// 根据配置调整信号量大小
	semaphoreSize := 10
	if config.DefaultTenantId > 1000000 { // 大租户环境
		semaphoreSize = 20
	}

	// 创建goroutine管理器配置
	gmConfig := &GoroutineManagerConfig{
		MaxGoroutines:       semaphoreSize * 2, // 允许比信号量更多的goroutines
		DefaultTimeout:      15 * time.Second,  // 默认超时时间
		GracefulShutdown:    5 * time.Second,   // 优雅关闭超时
		EnableMetrics:       true,
		EnableStackTrace:    true,
		LeakDetection:       true,
		HealthCheckInterval: 60 * time.Second,
	}

	middleware := &DataPermMiddleware{
		Redis:            redis,
		RPCClient:        rpcClient,
		Trans:            trans,
		Config:           config,
		refreshSemaphore: make(chan struct{}, semaphoreSize),
		goroutineManager: NewGoroutineManager("dataperm-middleware", gmConfig),
		metricsCollector: GetDefaultMetricsCollector(),
	}

	// 初始化L1缓存
	if config.L1CacheEnabled {
		l1Config := config.L1CacheConfig
		if l1Config == nil {
			// 为数据权限优化的默认配置
			l1Config = DefaultL1CacheConfig()
			l1Config.MaxSize = 2000               // 适合数据权限场景的大小
			l1Config.DefaultTTL = 3 * time.Minute // 较短的TTL确保数据新鲜度
			l1Config.HitRateTarget = 0.85         // 高命中率目标
		}
		middleware.l1Cache = NewL1Cache(l1Config)

		logx.Infow("DataPerm L1 Cache initialized",
			logx.Field("maxSize", l1Config.MaxSize),
			logx.Field("defaultTTL", l1Config.DefaultTTL),
			logx.Field("hitRateTarget", l1Config.HitRateTarget))
	}

	// 初始化熔断器
	if config.CircuitBreakerEnabled {
		// Redis熔断器配置
		redisConfig := config.RedisCircuitBreaker
		if redisConfig == nil {
			redisConfig = DefaultCircuitBreakerConfig()
			redisConfig.Name = "dataperm-redis"
			redisConfig.FailureThreshold = 5
			redisConfig.FailureRate = 0.1 // 10%失败率触发，更严格
			redisConfig.MinimumRequestThreshold = 10
			redisConfig.Timeout = 10 * time.Second
			// 添加状态变更回调以记录监控指标
			redisConfig.OnStateChange = func(name string, from, to CircuitBreakerState) {
				middleware.metricsCollector.RecordCircuitBreakerState("dataperm", name, to)
				middleware.metricsCollector.RecordCustomMetric("circuit_breaker_state_change", 1.0, map[string]string{
					"middleware": "dataperm",
					"breaker":    name,
					"from":       from.String(),
					"to":         to.String(),
				})
			}
		}
		middleware.redisCircuitBreaker = NewCircuitBreaker(redisConfig)

		// RPC熔断器配置
		rpcConfig := config.RPCCircuitBreaker
		if rpcConfig == nil {
			rpcConfig = DefaultCircuitBreakerConfig()
			rpcConfig.Name = "dataperm-rpc"
			rpcConfig.FailureThreshold = 3
			rpcConfig.FailureRate = 0.15 // 15%失败率触发
			rpcConfig.MinimumRequestThreshold = 5
			rpcConfig.Timeout = 20 * time.Second // 缩短超时时间
			// 添加状态变更回调以记录监控指标
			rpcConfig.OnStateChange = func(name string, from, to CircuitBreakerState) {
				middleware.metricsCollector.RecordCircuitBreakerState("dataperm", name, to)
				middleware.metricsCollector.RecordCustomMetric("circuit_breaker_state_change", 1.0, map[string]string{
					"middleware": "dataperm",
					"breaker":    name,
					"from":       from.String(),
					"to":         to.String(),
				})
			}
		}
		middleware.rpcCircuitBreaker = NewCircuitBreaker(rpcConfig)

		logx.Infow("DataPerm Circuit Breakers initialized",
			logx.Field("redisEnabled", true),
			logx.Field("rpcEnabled", true))
	}

	// 初始化性能分析器
	analyzerConfig := DefaultAnalyzerConfig()
	// Use configuration values if provided, otherwise use defaults
	if config.MemoryThreshold > 0 {
		analyzerConfig.MemoryThreshold = config.MemoryThreshold
		logx.Infow("DataPerm: Using configured memory threshold", logx.Field("threshold", config.MemoryThreshold))
	} else {
		analyzerConfig.MemoryThreshold = 50 * 1024 * 1024 // 50MB default
	}
	if config.CPUThreshold > 0 {
		analyzerConfig.CPUThreshold = config.CPUThreshold
		logx.Infow("DataPerm: Using configured CPU threshold", logx.Field("threshold", config.CPUThreshold))
	} else {
		analyzerConfig.CPUThreshold = 80.0 // 80% default
	}
	middleware.performanceAnalyzer = NewPerformanceAnalyzer(analyzerConfig, middleware.metricsCollector)
	middleware.performanceAnalyzer.Start()

	// 初始化缓存键优化器 - 现在支持异步初始化
	middleware.keyOptimizer = middleware.NewCacheKeyOptimizer(true) // 重新启用，使用异步初始化
	logx.Infow("DataPerm cache key optimizer enabled with async initialization")

	// 初始化批量Redis客户端
	batchSize := 100
	batchTimeout := 10 * time.Millisecond
	middleware.batchRedisClient = middleware.NewBatchRedisClient(redis, batchSize, batchTimeout)
	logx.Infow("DataPerm batch Redis client initialized",
		logx.Field("batchSize", batchSize),
		logx.Field("batchTimeout", batchTimeout))

	// 初始化健康检查注册表
	middleware.healthRegistry = middleware.NewHealthCheckRegistry()

	// 初始化基础监控收集器
	basicMonitorConfig := &middleware.BasicMonitoringConfig{
		Enabled:            true,
		CollectionInterval: 30 * time.Second,
		MetricsRetention:   24 * time.Hour,
		EnableHealthCheck:  true,
		HealthCheckPort:    9091,
		EnableProfiling:    false,
		ProfilingPort:      6061,
	}
	middleware.basicMonitor = middleware.NewBasicMonitoringCollector(basicMonitorConfig, middleware.metricsCollector)

	// 初始化降级策略
	if config.FallbackEnabled {
		fallbackConfig := config.FallbackConfig
		if fallbackConfig == nil {
			fallbackConfig = DefaultFallbackStrategyConfig()
			// 为DataPerm中间件优化的配置
			fallbackConfig.EmergencyCacheSize = 5000
			fallbackConfig.EmergencyCacheTTL = 2 * time.Hour
			fallbackConfig.HealthCheckInterval = 30 * time.Second
		}
		middleware.fallbackStrategy = middleware.NewFallbackStrategy(fallbackConfig)

		// 注册Redis健康检查器
		redisHealthChecker := middleware.NewRedisHealthChecker("dataperm-redis", redis, 8)
		middleware.healthRegistry.Register(redisHealthChecker)
		middleware.fallbackStrategy.AddHealthChecker(redisHealthChecker)

		// 注册熔断器健康检查器
		if config.CircuitBreakerEnabled {
			breakers := map[string]middleware.CircuitBreaker{
				"redis": middleware.redisCircuitBreaker,
				"rpc":   middleware.rpcCircuitBreaker,
			}
			cbHealthChecker := middleware.NewCircuitBreakerHealthChecker("dataperm-circuit-breakers", 9, breakers)
			middleware.healthRegistry.Register(cbHealthChecker)
			middleware.fallbackStrategy.AddHealthChecker(cbHealthChecker)
		}

		logx.Infow("DataPerm fallback strategy initialized",
			logx.Field("emergencyCacheSize", fallbackConfig.EmergencyCacheSize),
			logx.Field("healthCheckInterval", fallbackConfig.HealthCheckInterval))
	}

	return middleware
}

// Handle 处理数据权限中间件逻辑
func (m *DataPermMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		ctx := r.Context()
		var subDept, dataScope, customDept string
		var tenantId uint64 = m.Config.DefaultTenantId
		var err error

		// 记录内存使用情况（采样）
		if startTime.UnixNano()%100 == 0 { // 1%采样率
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			m.metricsCollector.RecordMemoryUsage("dataperm", int64(memStats.HeapInuse))
		}

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
			// 尝试使用降级策略
			if m.Config.FallbackEnabled && m.fallbackStrategy != nil {
				if fallbackResult, fallbackErr := m.executeFallback(ctx, roleCodes, tenantId, "getDataScope"); fallbackErr == nil {
					dataScope = fallbackResult.DataScope
					logx.Warnw("DataPerm fallback executed for getDataScope",
						logx.Field("originalError", err.Error()),
						logx.Field("fallbackLevel", fallbackResult.Level),
						logx.Field("dataScope", dataScope))
				} else {
					httpx.Error(w, err)
					return
				}
			} else {
				httpx.Error(w, err)
				return
			}
		}

		// 将数据权限范围注入上下文
		ctx = datapermctx.WithScopeContext(ctx, dataScope)

		// 根据权限范围处理相关数据
		switch dataScope {
		case entenum.DataPermOwnDeptAndSubStr:
			subDept, err = m.getSubDeptData(ctx, deptId, tenantId)
			if err != nil {
				// 尝试使用降级策略
				if m.Config.FallbackEnabled && m.fallbackStrategy != nil {
					if fallbackResult, fallbackErr := m.executeFallback(ctx, roleCodes, tenantId, "getSubDeptData"); fallbackErr == nil {
						subDept = fallbackResult.SubDept
						logx.Warnw("DataPerm fallback executed for getSubDeptData",
							logx.Field("originalError", err.Error()),
							logx.Field("fallbackLevel", fallbackResult.Level))
					} else {
						httpx.Error(w, err)
						return
					}
				} else {
					httpx.Error(w, err)
					return
				}
			}
			ctx = datapermctx.WithSubDeptContext(ctx, subDept)

		case entenum.DataPermCustomDeptStr:
			customDept, err = m.getCustomDeptData(ctx, roleCodes, tenantId)
			if err != nil {
				// 尝试使用降级策略
				if m.Config.FallbackEnabled && m.fallbackStrategy != nil {
					if fallbackResult, fallbackErr := m.executeFallback(ctx, roleCodes, tenantId, "getCustomDeptData"); fallbackErr == nil {
						customDept = fallbackResult.CustomDept
						logx.Warnw("DataPerm fallback executed for getCustomDeptData",
							logx.Field("originalError", err.Error()),
							logx.Field("fallbackLevel", fallbackResult.Level))
					} else {
						httpx.Error(w, err)
						return
					}
				} else {
					httpx.Error(w, err)
					return
				}
			}
			ctx = datapermctx.WithCustomDeptContext(ctx, customDept)
		}

		// 执行下一个中间件/处理器
		next(w, r.WithContext(ctx))

		// 记录请求性能指标
		duration := time.Since(startTime)
		success := err == nil
		m.metricsCollector.RecordRequest("dataperm", r.Method, duration, success)

		if err != nil {
			m.metricsCollector.RecordError("dataperm", "request_processing", "middleware_error")
		}
	}
}

// getDataScope 获取数据权限范围
func (m *DataPermMiddleware) getDataScope(ctx context.Context, roleCodes []string, tenantId uint64) (string, error) {
	var redisKey string

	// 使用优化的缓存键生成
	if m.keyOptimizer != nil {
		req := &KeyGenerationRequest{
			RoleCodes: roleCodes,
			TenantID:  tenantId,
		}
		if m.Config.EnableTenantMode {
			req.Type = TenantRoleScopeKeyType
		} else {
			req.Type = RoleScopeKeyType
		}
		redisKey = m.keyOptimizer.GenerateOptimizedKey(req)
	} else {
		// 回退到原有方法
		if m.Config.EnableTenantMode {
			redisKey = datapermctx.GetTenantRoleScopeDataPermRedisKey(roleCodes, tenantId)
		} else {
			redisKey = datapermctx.GetRoleScopeDataPermRedisKey(roleCodes)
		}
	}

	// 首先尝试L1缓存
	if m.l1Cache != nil {
		cacheStart := time.Now()
		if cachedValue, hit := m.l1Cache.Get(ctx, redisKey); hit {
			cacheDuration := time.Since(cacheStart)
			m.metricsCollector.RecordCacheOperation("dataperm", "l1_get", true, cacheDuration)
			logx.Debugw("DataPerm L1 cache hit",
				logx.Field("key", redisKey),
				logx.Field("value", cachedValue))
			return cachedValue, nil
		} else {
			cacheDuration := time.Since(cacheStart)
			m.metricsCollector.RecordCacheOperation("dataperm", "l1_get", false, cacheDuration)
		}
	}

	// L1缓存未命中，通过熔断器保护查询Redis
	var dataScope string
	var err error

	redisOperation := func(ctx context.Context) error {
		// 应用超时控制
		timeout := 3 * time.Second
		if m.Config.TimeoutConfig != nil && m.Config.TimeoutConfig.RequestTimeout > 0 {
			timeout = m.Config.TimeoutConfig.RequestTimeout
		}

		return WithTimeout(ctx, timeout, func(timeoutCtx context.Context) error {
			redisStart := time.Now()

			// 使用批量Redis客户端进行查询
			var result string
			var redisErr error

			if m.batchRedisClient != nil {
				result, redisErr = m.batchRedisClient.GetBatch(timeoutCtx, redisKey)
			} else {
				// 回退到普通Redis查询
				result, redisErr = m.Redis.Get(timeoutCtx, redisKey).Result()
			}

			redisDuration := time.Since(redisStart)

			if redisErr != nil {
				m.metricsCollector.RecordCacheOperation("dataperm", "redis_get", false, redisDuration)
				dataScope = ""
				return redisErr
			}

			m.metricsCollector.RecordCacheOperation("dataperm", "redis_get", true, redisDuration)
			dataScope = result
			return nil
		})
	}

	if m.redisCircuitBreaker != nil {
		err = m.redisCircuitBreaker.Execute(ctx, redisOperation)
	} else {
		err = redisOperation(ctx)
	}

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 缓存未命中，异步刷新并返回默认权限
			m.startAsyncRefresh(ctx, redisKey, "role")
			// 返回默认权限范围，避免阻塞请求
			defaultValue := entenum.DataPermOwnDeptStr
			// 将默认值存入L1缓存，避免重复查询
			if m.l1Cache != nil {
				m.l1Cache.SetWithTTL(ctx, redisKey, defaultValue, 30*time.Second) // 短TTL for fallback
			}
			return defaultValue, nil
		} else if errors.Is(err, ErrCircuitBreakerOpen) || errors.Is(err, ErrCircuitBreakerTimeout) {
			// 熔断器开启或超时，直接返回默认权限并记录日志
			logx.Errorw("Redis protected by circuit breaker",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()))
			defaultValue := entenum.DataPermOwnDeptStr
			if m.l1Cache != nil {
				m.l1Cache.SetWithTTL(ctx, redisKey, defaultValue, 10*time.Second) // 更短的TTL
			}
			return defaultValue, nil
		} else {
			logx.Error("redis error", logx.Field("detail", err))
			return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
		}
	}

	// 将Redis结果存入L1缓存
	if m.l1Cache != nil {
		m.l1Cache.Set(ctx, redisKey, dataScope)
	}

	return dataScope, nil
}

// getSubDeptData 获取子部门数据
func (m *DataPermMiddleware) getSubDeptData(ctx context.Context, deptId uint64, tenantId uint64) (string, error) {
	var redisKey string

	// 使用优化的缓存键生成
	if m.keyOptimizer != nil {
		req := &KeyGenerationRequest{
			DeptID:   deptId,
			TenantID: tenantId,
		}
		if m.Config.EnableTenantMode {
			req.Type = TenantSubDeptKeyType
		} else {
			req.Type = SubDeptKeyType
		}
		redisKey = m.keyOptimizer.GenerateOptimizedKey(req)
	} else {
		// 回退到原有方法
		if m.Config.EnableTenantMode {
			redisKey = datapermctx.GetTenantSubDeptDataPermRedisKey(deptId, tenantId)
		} else {
			redisKey = datapermctx.GetSubDeptDataPermRedisKey(deptId)
		}
	}

	// 首先尝试L1缓存
	if m.l1Cache != nil {
		if cachedValue, hit := m.l1Cache.Get(ctx, redisKey); hit {
			return cachedValue, nil
		}
	}

	// L1缓存未命中，通过熔断器保护查询Redis
	var subDept string
	var err error

	redisOperation := func(ctx context.Context) error {
		timeout := 3 * time.Second
		if m.Config.TimeoutConfig != nil && m.Config.TimeoutConfig.RequestTimeout > 0 {
			timeout = m.Config.TimeoutConfig.RequestTimeout
		}

		return WithTimeout(ctx, timeout, func(timeoutCtx context.Context) error {
			var result string
			var redisErr error

			if m.batchRedisClient != nil {
				result, redisErr = m.batchRedisClient.GetBatch(timeoutCtx, redisKey)
			} else {
				result, redisErr = m.Redis.Get(timeoutCtx, redisKey).Result()
			}

			if redisErr != nil {
				subDept = ""
				return redisErr
			}
			subDept = result
			return nil
		})
	}

	if m.redisCircuitBreaker != nil {
		err = m.redisCircuitBreaker.Execute(ctx, redisOperation)
	} else {
		err = redisOperation(ctx)
	}

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 缓存未命中，异步刷新并返回默认部门权限
			m.startAsyncRefresh(ctx, redisKey, "dept")
			// 返回当前部门ID，避免阻塞请求
			defaultValue := fmt.Sprintf("%d", deptId)
			if m.l1Cache != nil {
				m.l1Cache.SetWithTTL(ctx, redisKey, defaultValue, 30*time.Second)
			}
			return defaultValue, nil
		} else if errors.Is(err, ErrCircuitBreakerOpen) || errors.Is(err, ErrCircuitBreakerTimeout) {
			logx.Errorw("Redis protected by circuit breaker in getSubDeptData",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()))
			defaultValue := fmt.Sprintf("%d", deptId)
			if m.l1Cache != nil {
				m.l1Cache.SetWithTTL(ctx, redisKey, defaultValue, 10*time.Second)
			}
			return defaultValue, nil
		} else {
			logx.Error("redis error", logx.Field("detail", err))
			return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
		}
	}

	// 将Redis结果存入L1缓存
	if m.l1Cache != nil {
		m.l1Cache.Set(ctx, redisKey, subDept)
	}

	return subDept, nil
}

// getCustomDeptData 获取自定义部门数据
func (m *DataPermMiddleware) getCustomDeptData(ctx context.Context, roleCodes []string, tenantId uint64) (string, error) {
	var redisKey string

	// 使用优化的缓存键生成
	if m.keyOptimizer != nil {
		req := &KeyGenerationRequest{
			RoleCodes: roleCodes,
			TenantID:  tenantId,
		}
		if m.Config.EnableTenantMode {
			req.Type = TenantCustomDeptKeyType
		} else {
			req.Type = CustomDeptKeyType
		}
		redisKey = m.keyOptimizer.GenerateOptimizedKey(req)
	} else {
		// 回退到原有方法
		if m.Config.EnableTenantMode {
			redisKey = datapermctx.GetTenantRoleCustomDeptDataPermRedisKey(roleCodes, tenantId)
		} else {
			redisKey = datapermctx.GetRoleCustomDeptDataPermRedisKey(roleCodes)
		}
	}

	// 首先尝试L1缓存
	if m.l1Cache != nil {
		if cachedValue, hit := m.l1Cache.Get(ctx, redisKey); hit {
			return cachedValue, nil
		}
	}

	// L1缓存未命中，通过熔断器保护查询Redis
	var customDept string
	var err error

	redisOperation := func(ctx context.Context) error {
		timeout := 3 * time.Second
		if m.Config.TimeoutConfig != nil && m.Config.TimeoutConfig.RequestTimeout > 0 {
			timeout = m.Config.TimeoutConfig.RequestTimeout
		}

		return WithTimeout(ctx, timeout, func(timeoutCtx context.Context) error {
			var result string
			var redisErr error

			if m.batchRedisClient != nil {
				result, redisErr = m.batchRedisClient.GetBatch(timeoutCtx, redisKey)
			} else {
				result, redisErr = m.Redis.Get(timeoutCtx, redisKey).Result()
			}

			if redisErr != nil {
				customDept = ""
				return redisErr
			}
			customDept = result
			return nil
		})
	}

	if m.redisCircuitBreaker != nil {
		err = m.redisCircuitBreaker.Execute(ctx, redisOperation)
	} else {
		err = redisOperation(ctx)
	}

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 缓存未命中，异步刷新并返回默认自定义部门权限
			m.startAsyncRefresh(ctx, redisKey, "dept")
			// 返回空字符串，表示无自定义部门权限
			defaultValue := ""
			if m.l1Cache != nil {
				m.l1Cache.SetWithTTL(ctx, redisKey, defaultValue, 30*time.Second)
			}
			return defaultValue, nil
		} else if errors.Is(err, ErrCircuitBreakerOpen) || errors.Is(err, ErrCircuitBreakerTimeout) {
			logx.Errorw("Redis protected by circuit breaker in getCustomDeptData",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()))
			defaultValue := ""
			if m.l1Cache != nil {
				m.l1Cache.SetWithTTL(ctx, redisKey, defaultValue, 10*time.Second)
			}
			return defaultValue, nil
		} else {
			logx.Error("redis error", logx.Field("detail", err))
			return "", errorx.NewInternalError(m.Trans.Trans(ctx, i18n.RedisError))
		}
	}

	// 将Redis结果存入L1缓存
	if m.l1Cache != nil {
		m.l1Cache.Set(ctx, redisKey, customDept)
	}

	return customDept, nil
}

// startAsyncRefresh 启动异步刷新，使用安全的goroutine管理器
func (m *DataPermMiddleware) startAsyncRefresh(ctx context.Context, redisKey, refreshType string) {
	// 检查goroutine管理器是否正在运行
	if !m.goroutineManager.IsRunning() {
		logx.Errorw("Goroutine manager is not running, skipping async refresh",
			logx.Field("redisKey", redisKey),
			logx.Field("refreshType", refreshType))
		return
	}

	select {
	case m.refreshSemaphore <- struct{}{}:
		// 使用goroutine管理器启动安全的goroutine
		goroutineName := fmt.Sprintf("refresh-%s-%s", refreshType, redisKey)
		err := m.goroutineManager.GoWithTimeout(goroutineName, 10*time.Second, func(goroutineCtx context.Context) error {
			defer func() {
				<-m.refreshSemaphore
				// 确保在panic情况下也能清理刷新状态
				m.refreshingKeys.Delete(redisKey)
			}()

			if refreshType == "role" {
				m.asyncRefreshRoleDataPerm(goroutineCtx, redisKey)
			} else {
				m.asyncRefreshDeptDataPerm(goroutineCtx, redisKey)
			}
			return nil
		})

		if err != nil {
			// 如果启动goroutine失败，立即释放信号量和清理状态
			<-m.refreshSemaphore
			m.refreshingKeys.Delete(redisKey) // 清理刷新状态
			logx.Errorw("Failed to start async refresh goroutine",
				logx.Field("redisKey", redisKey),
				logx.Field("refreshType", refreshType),
				logx.Field("error", err))
		}
	default:
		// 如果达到并发限制，记录日志但不阻塞
		logx.Errorw("Refresh semaphore full, skipping async refresh",
			logx.Field("redisKey", redisKey),
			logx.Field("refreshType", refreshType))
	}
}

// asyncRefreshRoleDataPerm 异步刷新角色数据权限缓存
func (m *DataPermMiddleware) asyncRefreshRoleDataPerm(ctx context.Context, redisKey string) {
	// 使用sync.Map检查和设置，避免竞态条件
	if _, loaded := m.refreshingKeys.LoadOrStore(redisKey, true); loaded {
		return // 已在刷新中
	}

	defer m.refreshingKeys.Delete(redisKey)

	// 继承原始上下文但设置新的超时
	refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// 从Redis Key中提取角色代码，确保RPC调用有正确的上下文
	roleCodes := m.extractRoleCodesFromRedisKey(redisKey)
	if len(roleCodes) > 0 {
		// 将角色代码添加到上下文中，供RPC服务使用
		refreshCtx = context.WithValue(refreshCtx, "roleCodes", strings.Join(roleCodes, ","))

		// 如果是租户模式，也需要传递租户ID
		if m.Config.EnableTenantMode {
			if tenantId := m.extractTenantIdFromRedisKey(redisKey); tenantId > 0 {
				refreshCtx = context.WithValue(refreshCtx, "tenantId", tenantId)
				// refreshCtx = tenantctx.SetTenantIDCtx(refreshCtx, tenantId) // Commented out - function not available
			}
		}
	}

	// 通过熔断器保护RPC调用
	rpcOperation := func(ctx context.Context) error {
		timeout := 5 * time.Second
		if m.Config.TimeoutConfig != nil && m.Config.TimeoutConfig.HandlerTimeout > 0 {
			timeout = m.Config.TimeoutConfig.HandlerTimeout
		}

		return WithTimeout(ctx, timeout, func(timeoutCtx context.Context) error {
			// 确保上下文包含必要的数据
			if len(roleCodes) > 0 {
				timeoutCtx = context.WithValue(timeoutCtx, "roleCodes", strings.Join(roleCodes, ","))
				if m.Config.EnableTenantMode {
					if tenantId := m.extractTenantIdFromRedisKey(redisKey); tenantId > 0 {
						timeoutCtx = context.WithValue(timeoutCtx, "tenantId", tenantId)
						// timeoutCtx = tenantctx.SetTenantIDCtx(timeoutCtx, tenantId) // Commented out - function not available
					}
				}
			}

			_, rpcErr := m.RPCClient.InitRoleDataPermToRedis(timeoutCtx, struct{}{})
			return rpcErr
		})
	}

	var err error
	if m.rpcCircuitBreaker != nil {
		err = m.rpcCircuitBreaker.Execute(refreshCtx, rpcOperation)
	} else {
		err = rpcOperation(refreshCtx)
	}

	if err != nil {
		if errors.Is(err, ErrCircuitBreakerOpen) || errors.Is(err, ErrCircuitBreakerTimeout) {
			logx.Errorw("RPC call protected by circuit breaker in asyncRefreshRoleDataPerm",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()),
				logx.Field("roleCodes", roleCodes))
		} else {
			logx.Errorw("Failed to refresh role data permission cache",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()),
				logx.Field("roleCodes", roleCodes))
		}
	} else {
		logx.Infow("Role data permission cache refreshed successfully",
			logx.Field("redisKey", redisKey),
			logx.Field("roleCodes", roleCodes))
		// 刷新成功后清除L1缓存中的相关条目，强制下次请求从Redis获取最新数据
		if m.l1Cache != nil {
			m.l1Cache.Delete(context.Background(), redisKey)
		}
	}
}

// asyncRefreshDeptDataPerm 异步刷新部门数据权限缓存
func (m *DataPermMiddleware) asyncRefreshDeptDataPerm(ctx context.Context, redisKey string) {
	// 使用sync.Map检查和设置，避免竞态条件
	if _, loaded := m.refreshingKeys.LoadOrStore(redisKey, true); loaded {
		return // 已在刷新中
	}

	defer m.refreshingKeys.Delete(redisKey)

	// 继承原始上下文但设置新的超时
	refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// 从Redis Key中提取部门ID，确保RPC调用有正确的上下文
	deptId := m.extractDeptIdFromRedisKey(redisKey)
	if deptId > 0 {
		// 将部门ID添加到上下文中，供RPC服务使用
		// refreshCtx = deptctx.SetDepartmentIDCtx(refreshCtx, deptId) // Commented out - function not available

		// 如果是租户模式，也需要传递租户ID
		if m.Config.EnableTenantMode {
			if tenantId := m.extractTenantIdFromRedisKey(redisKey); tenantId > 0 {
				refreshCtx = context.WithValue(refreshCtx, "tenantId", tenantId)
				// refreshCtx = tenantctx.SetTenantIDCtx(refreshCtx, tenantId) // Commented out - function not available
			}
		}
	}

	// 通过熔断器保护RPC调用
	rpcOperation := func(ctx context.Context) error {
		timeout := 5 * time.Second
		if m.Config.TimeoutConfig != nil && m.Config.TimeoutConfig.HandlerTimeout > 0 {
			timeout = m.Config.TimeoutConfig.HandlerTimeout
		}

		return WithTimeout(ctx, timeout, func(timeoutCtx context.Context) error {
			// 确保上下文包含必要的数据
			if deptId > 0 {
				// timeoutCtx = deptctx.SetDepartmentIDCtx(timeoutCtx, deptId) // Commented out - function not available
				if m.Config.EnableTenantMode {
					if tenantId := m.extractTenantIdFromRedisKey(redisKey); tenantId > 0 {
						timeoutCtx = context.WithValue(timeoutCtx, "tenantId", tenantId)
						// timeoutCtx = tenantctx.SetTenantIDCtx(timeoutCtx, tenantId) // Commented out - function not available
					}
				}
			}

			_, rpcErr := m.RPCClient.InitDeptDataPermToRedis(timeoutCtx, struct{}{})
			return rpcErr
		})
	}

	var err error
	if m.rpcCircuitBreaker != nil {
		err = m.rpcCircuitBreaker.Execute(refreshCtx, rpcOperation)
	} else {
		err = rpcOperation(refreshCtx)
	}

	if err != nil {
		if errors.Is(err, ErrCircuitBreakerOpen) || errors.Is(err, ErrCircuitBreakerTimeout) {
			logx.Errorw("RPC call protected by circuit breaker in asyncRefreshDeptDataPerm",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()),
				logx.Field("deptId", deptId))
		} else {
			logx.Errorw("Failed to refresh department data permission cache",
				logx.Field("redisKey", redisKey),
				logx.Field("error", err.Error()),
				logx.Field("deptId", deptId))
		}
	} else {
		logx.Infow("Department data permission cache refreshed successfully",
			logx.Field("redisKey", redisKey),
			logx.Field("deptId", deptId))
		// 刷新成功后清除L1缓存中的相关条目，强制下次请求从Redis获取最新数据
		if m.l1Cache != nil {
			m.l1Cache.Delete(context.Background(), redisKey)
		}
	}
}

// GetL1CacheStats returns L1 cache statistics for monitoring
func (m *DataPermMiddleware) GetL1CacheStats() *L1CacheStats {
	if m.l1Cache == nil {
		return nil
	}

	stats := m.l1Cache.GetStats()
	return &stats
}

// InvalidateL1Cache clears all L1 cache entries
func (m *DataPermMiddleware) InvalidateL1Cache() {
	if m.l1Cache != nil {
		m.l1Cache.Clear()
		logx.Info("DataPerm L1 Cache invalidated")
	}
}

// InvalidateL1CacheKey removes a specific key from L1 cache
func (m *DataPermMiddleware) InvalidateL1CacheKey(key string) {
	if m.l1Cache != nil {
		m.l1Cache.Delete(context.Background(), key)
		logx.Debugw("DataPerm L1 Cache key invalidated", logx.Field("key", key))
	}
}

// GetCircuitBreakerStats returns circuit breaker statistics for monitoring
func (m *DataPermMiddleware) GetCircuitBreakerStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if m.redisCircuitBreaker != nil {
		stats["redis"] = map[string]interface{}{
			"state":  m.redisCircuitBreaker.State().String(),
			"counts": m.redisCircuitBreaker.Counts(),
		}
	}

	if m.rpcCircuitBreaker != nil {
		stats["rpc"] = map[string]interface{}{
			"state":  m.rpcCircuitBreaker.State().String(),
			"counts": m.rpcCircuitBreaker.Counts(),
		}
	}

	return stats
}

// ResetCircuitBreakers resets all circuit breakers to closed state
func (m *DataPermMiddleware) ResetCircuitBreakers() {
	if m.redisCircuitBreaker != nil {
		m.redisCircuitBreaker.Reset()
		logx.Info("DataPerm Redis Circuit Breaker reset")
	}

	if m.rpcCircuitBreaker != nil {
		m.rpcCircuitBreaker.Reset()
		logx.Info("DataPerm RPC Circuit Breaker reset")
	}
}

// GetCacheKeyOptimizerStats returns cache key optimizer statistics
func (m *DataPermMiddleware) GetCacheKeyOptimizerStats() map[string]interface{} {
	if m.keyOptimizer == nil {
		return nil
	}

	stats := make(map[string]interface{})

	// 获取优化器指标
	metrics := m.keyOptimizer.GetMetrics()
	stats["optimizer"] = map[string]interface{}{
		"total_keys":      metrics.totalKeys,
		"cached_keys":     metrics.cachedKeys,
		"interned_keys":   metrics.internedKeys,
		"pooled_builders": metrics.pooledBuilders,
		"avg_key_length":  metrics.avgKeyLength,
		"memory_saved":    metrics.memorySaved,
	}

	// 获取缓存统计
	cacheStats := m.keyOptimizer.GetCacheStats()
	stats["cache"] = cacheStats

	return stats
}

// GetBatchRedisStats returns batch Redis client statistics
func (m *DataPermMiddleware) GetBatchRedisStats() map[string]interface{} {
	if m.batchRedisClient == nil {
		return nil
	}

	return m.batchRedisClient.GetStats()
}

// GetBasicMonitoringStats 获取基础监控统计信息
func (m *DataPermMiddleware) GetBasicMonitoringStats() map[string]interface{} {
	if m.basicMonitor == nil {
		return nil
	}

	stats := make(map[string]interface{})
	stats["health_status"] = m.basicMonitor.GetHealthStatus()
	stats["performance_data"] = m.basicMonitor.GetPerformanceData()
	stats["alerts_history"] = m.basicMonitor.GetAlertsHistory()
	stats["is_running"] = m.basicMonitor.IsRunning()

	return stats
}

// GetBasicMonitoringCollector 获取基础监控收集器
func (m *DataPermMiddleware) GetBasicMonitoringCollector() *middleware.BasicMonitoringCollector {
	return m.basicMonitor
}


// InvalidateCacheKeyOptimizer clears the cache key optimizer caches
func (m *DataPermMiddleware) InvalidateCacheKeyOptimizer() {
	if m.keyOptimizer != nil {
		m.keyOptimizer.Clear()
		logx.Info("DataPerm cache key optimizer invalidated")
	}
}

// extractRoleCodesFromRedisKey 从Redis key中提取角色代码
func (m *DataPermMiddleware) extractRoleCodesFromRedisKey(redisKey string) []string {
	// Redis key格式: core:data_perm:role:scope:[role1,role2]
	// 或 core:data_perm:role:scope:[role1,role2]:tenant:123
	parts := strings.Split(redisKey, ":")

	for _, part := range parts {
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			// 移除方括号
			roleCodesStr := strings.TrimPrefix(strings.TrimSuffix(part, "]"), "[")
			if roleCodesStr != "" {
				return strings.Split(roleCodesStr, ",")
			}
		}
	}

	logx.Errorw("Could not extract role codes from Redis key", logx.Field("redisKey", redisKey))
	return nil
}

// extractDeptIdFromRedisKey 从Redis key中提取部门ID
func (m *DataPermMiddleware) extractDeptIdFromRedisKey(redisKey string) uint64 {
	// Redis key格式: core:data_perm:dept:sub:123
	// 或 core:data_perm:dept:sub:123:tenant:456
	parts := strings.Split(redisKey, ":")

	for i, part := range parts {
		if part == "sub" && i+1 < len(parts) {
			if deptId, err := strconv.ParseUint(parts[i+1], 10, 64); err == nil {
				return deptId
			}
		}
	}

	logx.Errorw("Could not extract department ID from Redis key", logx.Field("redisKey", redisKey))
	return 0
}

// extractTenantIdFromRedisKey 从Redis key中提取租户ID
func (m *DataPermMiddleware) extractTenantIdFromRedisKey(redisKey string) uint64 {
	// Redis key格式: ...tenant:123
	parts := strings.Split(redisKey, ":")

	for i, part := range parts {
		if part == "tenant" && i+1 < len(parts) {
			if tenantId, err := strconv.ParseUint(parts[i+1], 10, 64); err == nil {
				return tenantId
			}
		}
	}

	// 如果没有找到租户ID，返回默认租户ID
	return m.Config.DefaultTenantId
}

// Close gracefully shuts down the middleware and its L1 cache
func (m *DataPermMiddleware) Close() error {
	var errors []error

	// 首先停止goroutine管理器，确保所有异步刷新操作完成
	if m.goroutineManager != nil {
		if err := m.goroutineManager.Stop(); err != nil {
			logx.Errorw("Failed to stop goroutine manager", logx.Field("error", err))
			errors = append(errors, err)
		} else {
			logx.Info("DataPermMiddleware goroutine manager stopped")
		}
	}

	if m.l1Cache != nil {
		if err := m.l1Cache.Close(); err != nil {
			logx.Errorw("Failed to close L1 cache", logx.Field("error", err))
			errors = append(errors, err)
		} else {
			logx.Info("DataPermMiddleware L1 cache closed")
		}
	}

	if m.performanceAnalyzer != nil {
		if err := m.performanceAnalyzer.Stop(); err != nil {
			logx.Errorw("Failed to stop performance analyzer", logx.Field("error", err))
			errors = append(errors, err)
		} else {
			logx.Info("DataPermMiddleware performance analyzer stopped")
		}
	}

	// 关闭缓存键优化器
	if m.keyOptimizer != nil {
		if err := m.keyOptimizer.Close(); err != nil {
			logx.Errorw("Failed to close cache key optimizer", logx.Field("error", err))
			errors = append(errors, err)
		} else {
			logx.Info("DataPermMiddleware cache key optimizer closed")
		}
	}

	// 关闭批量Redis客户端
	if m.batchRedisClient != nil {
		m.batchRedisClient.Close()
		logx.Info("DataPermMiddleware batch Redis client closed")
	}

	// 关闭基础监控收集器
	if m.basicMonitor != nil {
		if err := m.basicMonitor.Stop(); err != nil {
			logx.Errorw("Failed to stop basic monitoring collector", logx.Field("error", err))
			errors = append(errors, err)
		} else {
			logx.Info("DataPermMiddleware basic monitoring collector stopped")
		}
	}

	if len(errors) > 0 {
		return errors[0] // Return first error
	}

	logx.Info("DataPermMiddleware closed successfully")
	return nil
}
