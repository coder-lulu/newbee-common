// Copyright 2024 The NewBee Authors. All Rights Reserved.

package permission

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/logging"
)

// EnforcerProvider provides a way for services to inject a Casbin enforcer
// without hard-coupling the middleware to service implementations.
type EnforcerProvider interface {
	GetCasbinEnforcer() interface{}
}

// RbacPlugin performs interface-level permission checks using Casbin.
// It should run after TenantCheck and before DataPerm.
type RbacPlugin struct {
	core     *framework.CoreServices
	config   *framework.PermissionConfig
	enforcer *casbin.Enforcer
	provider EnforcerProvider
	logger   *logging.MiddlewareLogger
}

const superAdminRoleCode = "superadmin"

// NewRbacPlugin creates a new RBAC permission plugin.
func NewRbacPlugin() framework.MiddlewarePlugin {
	return &RbacPlugin{}
}

// NewRbacPluginWithProvider creates a new RBAC plugin with a provider that returns an enforcer.
func NewRbacPluginWithProvider(p EnforcerProvider) framework.MiddlewarePlugin {
	return &RbacPlugin{provider: p}
}

// NewRbacPluginWithEnforcer creates a new RBAC plugin with a concrete enforcer.
func NewRbacPluginWithEnforcer(e *casbin.Enforcer) framework.MiddlewarePlugin {
	return &RbacPlugin{enforcer: e}
}

func (p *RbacPlugin) Name() string { return "RBAC" }

// Priority: run after Tenant (15) and before DataPerm (20)
func (p *RbacPlugin) Priority() int { return 18 }

func (p *RbacPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.logger = logging.NewMiddlewareLogger("rbac")
	p.config = core.Config.Permission

	if p.config == nil || !p.config.Enabled {
		// Should not be registered when disabled; treat as config error if it happens
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("rbac config is missing or disabled").Build()
		p.logger.WithError(err).Error("rbac plugin initialization failed")
		return err
	}

	// Resolve enforcer from provider if not directly set
	if p.enforcer == nil && p.provider != nil {
		if val := p.provider.GetCasbinEnforcer(); val != nil {
			if ef, ok := val.(*casbin.Enforcer); ok {
				p.enforcer = ef
				p.logger.Info("✅ 使用服务提供的Casbin执行器")
			} else {
				p.logger.WithField("provider_type",
					(func(v interface{}) string { return fmt.Sprintf("%T", v) })(val)).
					Warn("rbac provider returned non-enforcer type")
			}
		}
	}

	if p.enforcer == nil {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("casbin enforcer not provided for rbac plugin").Build()
		p.logger.WithError(err).Error("rbac plugin initialization failed")
		return err
	}

	p.logger.Info("rbac plugin initialized successfully")
	return nil
}

func (p *RbacPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger := p.logger.WithContext(r.Context()).WithRequest(r)

		// Skip paths if configured
		if p.shouldSkip(r.URL.Path) {
			logger.WithField("skipped", true).Debug("rbac check skipped for path")
			next(w, r)
			return
		}

		cm := p.core.ContextManager
		subStr := cm.GetRoleCodes(r.Context())
		subs := strings.Split(subStr, ",")

		// If no role codes found, treat as unauthorized (must pass auth first)
		if len(subs) == 0 {
			err := errors.NewAuthError(errors.CodeAuthUserNotFound, nil)
			logger.WithError(err).WithDuration(start).Error("rbac subject missing (user not authenticated)")
			err.WriteHTTPResponse(w)
			return
		}

		// 🔥 获取租户ID作为domain（直接使用字符串租户ID，保持与casbin规则一致）
		tenantID := strings.TrimSpace(cm.GetTenantID(r.Context()))
		domain := tenantID

		// Object: normalized path (without query string)
		obj := r.URL.Path
		if idx := strings.Index(obj, "?"); idx >= 0 {
			obj = obj[:idx]
		}
		// Action: HTTP method
		act := r.Method

		// 使用subs 来判断权限，subs中存储的是用户角色编码，为数组，只要有一个角色能匹配即默认有权限
		allowed := false
		skipCasbinCheck := false

		for _, sub := range subs {
			if strings.TrimSpace(sub) == superAdminRoleCode {
				skipCasbinCheck = true
				logger.WithField("role", sub).
					WithField("domain", domain).
					Info("🔓 [权限检查] superadmin role detected, skipping Casbin enforcement")
				break
			}
		}

		if !skipCasbinCheck {
			for _, sub := range subs {
				// 🐛 DEBUG: Enforce调用参数
				logger.WithField("sub", sub).WithField("domain", domain).WithField("obj", obj).WithField("act", act).Info("🔍 [DEBUG] Enforce参数")
				// 🔥 传入domain参数，支持RBAC with Domains模型
				roleAllowed, roleErr := p.enforcer.Enforce(sub, domain, obj, act)
				logger.WithField("sub", sub).WithField("domain", domain).WithField("obj", obj).WithField("act", act).Info("🔍 [DEBUG] Casbin.Enforce调用参数")
				// 🐛 DEBUG: Enforce返回结果
				logger.WithField("allowed", roleAllowed).WithField("error", roleErr).Info("🔍 [DEBUG] Enforce结果")
				if roleErr != nil {
					logger.WithField("allowed", roleAllowed).WithField("error", roleErr).Info("🔍 [DEBUG] Casbin.Enforce返回结果")
					// Conservative: deny on error
					permErr := errors.NewError(errors.CodeRBACPermissionDenied).
						WithMessage("rbac evaluation error").
						WithDetail("subject", sub).
						WithDetail("domain", domain).
						WithDetail("object", obj).
						WithDetail("action", act).Build()
					logger.WithError(permErr).WithDuration(start).Error("❌ [权限检查] Casbin执行器错误")
					permErr.WriteHTTPResponse(w)
					return
				}

				if roleAllowed {
					allowed = true
					logger.WithField("allowed_role", sub).
						WithField("domain", domain).
						WithField("object", obj).
						WithField("action", act).
						Debug("🔍 [权限检查] 找到匹配的角色权限")
					break // 找到一个匹配的角色即可，避免继续检查
				}
			}
		} else {
			allowed = true
		}

		if !allowed {
			permErr := errors.NewError(errors.CodeRBACPermissionDenied).
				WithMessage("permission denied").
				WithDetail("subject", subStr).
				WithDetail("domain", domain).
				WithDetail("object", obj).
				WithDetail("action", act).Build()
			logger.WithError(permErr).WithDuration(start).Warn("🚫 [权限检查] Casbin权限拒绝")

			permErr.WriteHTTPResponse(w)
			return
		}

		next(w, r)
	}
}

func (p *RbacPlugin) shouldSkip(path string) bool {
	if p.config == nil || len(p.config.SkipPaths) == 0 {
		return false
	}
	for _, sp := range p.config.SkipPaths {
		if strings.HasPrefix(path, sp) {
			return true
		}
	}
	return false
}
