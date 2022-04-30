package services

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"camera/config"
	"camera/logging"
	"camera/sessions"
)

const (
	ServiceConfigKey  = "service_config"
	ServiceLoggingKey = "service_logging"
	ServiceSessionKey = "service_session"
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
		ctx = context.WithValue(ctx, ServiceSessionKey, session_component)
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
			*value, ok = ctx.Value(ServiceSessionKey).(sessions.SessionComponent)
		default:
		}
	}

	if !ok {
		panic("Not found requesting service")
	}
}
