package gtoken

import (
	"context"
	"errors"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

// Middleware 绑定group
func (m *GfToken) Middleware(group *ghttp.RouterGroup) error {
	if !m.InitConfig() {
		return errors.New("InitConfig fail")
	}

	// 设置为Group模式
	m.MiddlewareType = MiddlewareTypeGroup
	g.Log().Info(context.Background(), "[GToken][params:"+m.String()+"]start... ")

	// 缓存模式
	if m.CacheMode > CacheModeRedis {
		g.Log().Error(context.Background(), "[GToken]CacheMode set error")
		return errors.New("CacheMode set error")
	}
	// 登录
	if m.LoginPath == "" || m.LoginBeforeFunc == nil {
		g.Log().Error(context.Background(), "[GToken]LoginPath or LoginBeforeFunc not set")
		return errors.New("LoginPath or LoginBeforeFunc not set")
	}
	// 登出
	if m.LogoutPath == "" {
		g.Log().Error(context.Background(), "[GToken]LogoutPath not set")
		return errors.New("LogoutPath not set")
	}

	group.Middleware(m.authMiddleware)
	group.ALL(m.LoginPath, m.Login)
	group.ALL(m.LogoutPath, m.Logout)

	return nil
}

// AuthMiddleware 绑定登录状态校验
func (m *GfToken) AuthMiddleware(group *ghttp.RouterGroup) bool {
	if !m.InitConfig() {
		return false
	}
	// 设置为Group模式
	m.MiddlewareType = MiddlewareTypeGroup
	// 缓存模式
	if m.CacheMode > CacheModeRedis {
		g.Log().Error(context.Background(), "[GToken]CacheMode set error")
		return false
	}
	group.Middleware(m.authMiddleware)
	return true
}
