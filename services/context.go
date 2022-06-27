package services

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"camera/authorization"
	"camera/authorization/identity"
	"camera/config"
	"camera/logging"
	"camera/sessions"
)

const (
	ServiceConfigKey  = "service_config"
	ServiceLoggingKey = "service_logging"
)

var ctx context.Context = nil
var once sync.Once = sync.Once{}

func NewServiceContext(configName string) {

	once.Do(func() {
		cfg, err := config.Load(configName)
		if err != nil {
			panic(fmt.Sprintf("Not found file: %v\n", configName))
		}
		ctx = context.WithValue(context.Background(), ServiceConfigKey, cfg)

		logger := logging.NewDefaultLogger(cfg)
		ctx = context.WithValue(ctx, ServiceLoggingKey, logger)

		session_component := sessions.CreateSessionComponent(cfg)
		ctx = context.WithValue(ctx, sessions.ServiceSessionKey,
			session_component)

		roles := authorization.NewRoleCondition(cfg)
		ctx = context.WithValue(ctx, identity.ServiceRolesKey, roles)

		userStore := authorization.NewUserStore()
		ctx = context.WithValue(ctx, identity.ServiceUserStoreKey, userStore)
	})
}

func GetService(target interface{}) {
	var ok bool = false

	valueTarget := reflect.ValueOf(target)
	if valueTarget.Kind() == reflect.Ptr && valueTarget.Elem().CanSet() {
		switch value := target.(type) {
		case *logging.Logger:
			*value, ok = ctx.Value(ServiceLoggingKey).(logging.Logger)
		case *config.Configuration:
			*value, ok = ctx.Value(ServiceConfigKey).(config.Configuration)
		case *sessions.SessionComponent:
			*value, ok = ctx.Value(sessions.ServiceSessionKey).(sessions.SessionComponent)
		case *identity.AuthorizationCondition:
			*value, ok = ctx.Value(identity.ServiceRolesKey).(identity.AuthorizationCondition)
		case *identity.UserStore:
			*value, ok = ctx.Value(identity.ServiceUserStoreKey).(identity.UserStore)
		default:
		}
	}

	if !ok {
		panic("Not found requesting service")
	}
}
