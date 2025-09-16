// Copyright 2024 The NewBee Authors. All Rights Reserved.

package dataperm

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/coder-lulu/newbee-common/orm/ent/entenum"
	"github.com/zeromicro/go-zero/core/logx"
)

// RolePermission 角色权限配置
type RolePermission struct {
	RoleCode  string `json:"role_code"`
	DataScope string `json:"data_scope"`
}

// DataPermPlugin 数据权限插件 - 移除对Core RPC的依赖，使用本地配置和缓存
type DataPermPlugin struct {
	core            *framework.CoreServices
	config          *framework.DataPermConfig
	rolePermissions map[string]string // 角色代码 -> 数据权限范围的映射
	permissionCache sync.Map          // 权限缓存，避免重复计算
	defaultScope    string            // 默认权限范围
	logger          *logging.MiddlewareLogger
}

// NewDataPermPlugin 创建数据权限插件
func NewDataPermPlugin() framework.MiddlewarePlugin {
	return &DataPermPlugin{}
}

func (p *DataPermPlugin) Name() string {
	return "DataPermission"
}

func (p *DataPermPlugin) Priority() int {
	return 20 // 在Auth之后运行
}

func (p *DataPermPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.config = core.Config.DataPerm
	p.logger = logging.DataPermLogger()

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("dataperm config is missing or disabled").
			Build()
		p.logger.WithError(err).Error("data permission plugin initialization failed")
		return err
	}

	// 初始化权限映射和默认值
	p.rolePermissions = make(map[string]string)
	p.defaultScope = entenum.DataPermOwnStr // 默认使用个人权限，最严格

	// 初始化默认角色权限映射（可从配置文件或数据库加载）
	p.initDefaultRolePermissions()

	// 从Redis加载权限映射（如果可用）
	if core.Redis != nil {
		p.loadPermissionsFromRedis()
	}

	p.logger.WithField("role_count", len(p.rolePermissions)).
		WithField("default_scope", p.defaultScope).
		Info("data permission plugin initialized successfully")

	return nil
}

func (p *DataPermPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		logger := p.logger.WithContext(r.Context()).WithRequest(r)

		// 检查是否跳过
		if p.shouldSkip(r.URL.Path) {
			logger.WithField("skipped", true).Debug("data permission check skipped for path")
			next(w, r)
			return
		}

		ctx := r.Context()
		cm := p.core.ContextManager

		// 验证用户认证
		userID := cm.GetUserID(ctx)
		if userID == "" {
			err := errors.NewDataPermError(errors.CodeDataPermDenied, "", "")
			logger.WithError(err).WithDuration(startTime).Error("cannot process data permissions, user not authenticated")
			next(w, r)
			return
		}

		// 获取角色信息
		roleCodesVal := ctx.Value(keys.RoleCodesKey)
		roleCodes, _ := roleCodesVal.(string)
		if roleCodes == "" {
			logger.WithField("user_id", userID).WithDuration(startTime).Warn("no role codes found for user, using default permissions")
			// 使用默认权限继续处理
			roleCodes = ""
		}

		roleCodesList := strings.Split(roleCodes, ",")
		if len(roleCodesList) == 1 && roleCodesList[0] == "" {
			roleCodesList = []string{}
		}

		// 确定数据权限范围
		dataScope, err := p.determineDataScope(ctx, roleCodesList)
		if err != nil {
			logger.WithError(err).WithField("user_id", userID).WithField("roles", roleCodesList).Error("failed to determine data scope")
			// 使用最保守的权限
			dataScope = entenum.DataPermOwnStr
		}

		// 注入数据权限上下文
		newCtx := cm.SetDataScope(ctx, dataScope)

		logger.WithField("user_id", userID).
			WithField("data_scope", dataScope).
			WithField("roles", roleCodesList).
			WithDuration(startTime).
			Info("data permission applied successfully")

		next(w, r.WithContext(newCtx))
	}
}

// initDefaultRolePermissions 初始化默认的角色权限映射
func (p *DataPermPlugin) initDefaultRolePermissions() {
	// 定义常见角色的默认权限
	defaultPermissions := map[string]string{
		"superadmin": entenum.DataPermAllStr,           // 超级管理员：全部数据
		"admin":      entenum.DataPermAllStr,           // 管理员：全部数据
		"manager":    entenum.DataPermOwnDeptAndSubStr, // 管理者：本部门及子部门
		"leader":     entenum.DataPermOwnDeptStr,       // 主管：本部门
		"employee":   entenum.DataPermOwnStr,           // 员工：个人数据
		"viewer":     entenum.DataPermOwnStr,           // 查看者：个人数据
		"guest":      entenum.DataPermOwnStr,           // 访客：个人数据
	}

	// 复制到实例变量
	for role, perm := range defaultPermissions {
		p.rolePermissions[role] = perm
	}

	p.logger.WithField("count", len(defaultPermissions)).Info("default role permissions initialized")
}

// loadPermissionsFromRedis 从Redis加载动态权限配置
func (p *DataPermPlugin) loadPermissionsFromRedis() {
	if p.core.Redis == nil {
		return
	}

	ctx := context.Background()
	// 从Redis获取角色权限映射
	permissionsKey := "data_permissions:roles"
	rolePermissions, err := p.core.Redis.HGetAll(ctx, permissionsKey).Result()
	if err != nil {
		p.logger.WithError(err).Warn("failed to load permissions from Redis, using defaults")
		return
	}

	// 更新权限映射
	count := 0
	for roleCode, dataScope := range rolePermissions {
		if p.isValidDataScope(dataScope) {
			p.rolePermissions[roleCode] = dataScope
			count++
		}
	}

	p.logger.WithField("count", count).Info("permissions loaded from Redis")
}

// isValidDataScope 验证数据权限范围是否有效
func (p *DataPermPlugin) isValidDataScope(scope string) bool {
	validScopes := []string{
		entenum.DataPermAllStr,
		entenum.DataPermCustomDeptStr,
		entenum.DataPermOwnDeptAndSubStr,
		entenum.DataPermOwnDeptStr,
		entenum.DataPermOwnStr,
	}

	for _, validScope := range validScopes {
		if scope == validScope {
			return true
		}
	}
	return false
}

// determineDataScope 确定数据权限范围 - 重新实现为基于本地配置的方式
func (p *DataPermPlugin) determineDataScope(ctx context.Context, roleCodes []string) (string, error) {
	if len(roleCodes) == 0 {
		return p.defaultScope, nil
	}

	// 构建缓存键
	cacheKey := strings.Join(roleCodes, ",")

	// 检查缓存
	if cachedScope, ok := p.permissionCache.Load(cacheKey); ok {
		return cachedScope.(string), nil
	}

	// 确定最高权限级别
	highestScope := p.getHighestPermissionScope(roleCodes)

	// 缓存结果
	p.permissionCache.Store(cacheKey, highestScope)

	logx.WithContext(ctx).Infow("Data permission determined",
		logx.Field("roles", roleCodes),
		logx.Field("scope", highestScope))

	return highestScope, nil
}

// getHighestPermissionScope 获取角色列表中的最高权限级别
func (p *DataPermPlugin) getHighestPermissionScope(roleCodes []string) string {
	// 权限级别优先级（数字越大权限越高）
	scopePriority := map[string]int{
		entenum.DataPermOwnStr:           1, // 个人数据
		entenum.DataPermOwnDeptStr:       2, // 本部门
		entenum.DataPermOwnDeptAndSubStr: 3, // 本部门及子部门
		entenum.DataPermCustomDeptStr:    4, // 自定义部门
		entenum.DataPermAllStr:           5, // 全部数据
	}

	maxPriority := 0
	resultScope := p.defaultScope

	// 遍历所有角色，找到最高权限
	for _, roleCode := range roleCodes {
		if scope, exists := p.rolePermissions[roleCode]; exists {
			if priority, ok := scopePriority[scope]; ok {
				if priority > maxPriority {
					maxPriority = priority
					resultScope = scope
				}
			}
		}
	}

	return resultScope
}

// shouldSkip 检查路径是否应跳过数据权限检查
func (p *DataPermPlugin) shouldSkip(path string) bool {
	if p.config == nil || p.config.SkipPaths == nil {
		return false
	}
	for _, skipPath := range p.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}
