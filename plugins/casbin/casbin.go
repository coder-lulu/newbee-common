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

package casbin

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/coder-lulu/newbee-common/config"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	rediswatcher "github.com/casbin/redis-watcher/v2"
	redis2 "github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

// CasbinConf is the configuration structure for Casbin
type CasbinConf struct {
	ModelText string `json:"ModelText,optional,env=CASBIN_MODEL_TEXT"`
}

// NewCasbin returns Casbin enforcer.
func (l CasbinConf) NewCasbin(dbType, dsn string) (*casbin.Enforcer, error) {
	// 🔥 使用gormadapter替代entadapter，支持标准casbin_rules表结构（v0-v5列）
	// v1列存储domain（租户ID），无需单独的tenant_id字段
	//
	// ⚠️ 重要：第三个参数传true，表示dbSpecified=true
	// 这样gormadapter不会在DSN后面拼接默认数据库名"casbin"
	// 避免DSN变成：root:123456@tcp(host:port)/db?parseTime=Truecasbin
	adapter, err := gormadapter.NewAdapter(dbType, dsn, true)
	logx.Must(err)

	var text string
	if l.ModelText == "" {
		// 🔥 使用 RBAC with Domains 模型，支持多租户隔离
		text = `
		[request_definition]
		r = sub, dom, obj, act

		[policy_definition]
		p = sub, dom, obj, act, eft

		[role_definition]
		g = _, _, _

		[policy_effect]
		e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

		[matchers]
		m = (g(r.sub, r.dom, p.sub) || (r.sub == p.sub)) && r.dom == p.dom && keyMatch2(r.obj, p.obj) && keyMatch2(r.act, p.act)
		`
	} else {
		text = l.ModelText
	}

	m, err := model.NewModelFromString(text)
	logx.Must(err)

	enforcer, err := casbin.NewEnforcer(m, adapter)
	logx.Must(err)

	err = enforcer.LoadPolicy()
	logx.Must(err)

	return enforcer, nil
}

// MustNewCasbin returns Casbin enforcer. If there are errors, it will exist.
func (l CasbinConf) MustNewCasbin(dbType, dsn string) *casbin.Enforcer {
	csb, err := l.NewCasbin(dbType, dsn)
	if err != nil {
		logx.Errorw("initialize Casbin failed", logx.Field("detail", err.Error()))
		log.Fatalf("initialize Casbin failed, error: %s", err.Error())
		return nil
	}

	return csb
}

// MustNewRedisWatcher returns redis watcher. If there are errors, it will exist.
// f function will be called if the policies are updated.
func (l CasbinConf) MustNewRedisWatcher(c redis.RedisConf, f func(string2 string)) persist.Watcher {
	opt := redis2.Options{
		Network:  "tcp",
		Username: c.User,
		Password: c.Pass,
	}

	if c.Tls {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	w, err := rediswatcher.NewWatcher(c.Host, rediswatcher.WatcherOptions{
		Options:    opt,
		Channel:    config.RedisCasbinChannel,
		IgnoreSelf: false,
	})
	logx.Must(err)

	err = w.SetUpdateCallback(f)
	logx.Must(err)

	return w
}

// MustNewCasbinWithRedisWatcher returns Casbin Enforcer with Redis watcher.
func (l CasbinConf) MustNewCasbinWithRedisWatcher(dbType, dsn string, c redis.RedisConf) *casbin.Enforcer {
	cbn := l.MustNewCasbin(dbType, dsn)
	w := l.MustNewRedisWatcher(c, func(data string) {
		rediswatcher.DefaultUpdateCallback(cbn)(data)
	})
	err := cbn.SetWatcher(w)
	logx.Must(err)
	return cbn
}

// MustNewOriginalRedisWatcher returns redis watcher which uses original go redis. If there are errors, it will exist.
// f function will be called if the policies are updated.
func (l CasbinConf) MustNewOriginalRedisWatcher(c config.RedisConf, f func(string2 string)) persist.Watcher {
	opt := redis2.Options{
		Network:  "tcp",
		Username: c.Username,
		Password: c.Pass,
	}

	if c.Tls {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	w, err := rediswatcher.NewWatcher(c.Host, rediswatcher.WatcherOptions{
		Options:    opt,
		Channel:    fmt.Sprintf("%s-%d", config.RedisCasbinChannel, c.Db),
		IgnoreSelf: false,
	})
	logx.Must(err)

	err = w.SetUpdateCallback(f)
	logx.Must(err)

	return w
}

// MustNewCasbinWithOriginalRedisWatcher returns Casbin Enforcer with original Redis watcher.
func (l CasbinConf) MustNewCasbinWithOriginalRedisWatcher(dbType, dsn string, c config.RedisConf) *casbin.Enforcer {
	cbn := l.MustNewCasbin(dbType, dsn)
	w := l.MustNewOriginalRedisWatcher(c, func(data string) {
		rediswatcher.DefaultUpdateCallback(cbn)(data)
	})
	err := cbn.SetWatcher(w)
	logx.Must(err)
	return cbn
}
