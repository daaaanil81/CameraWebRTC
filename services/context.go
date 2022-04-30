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

const serviceConfigKey = "service_config"
const serviceLoggingKey = "service_logging"
const serviceSessionKey = "service_session"

var ctx context.Context = nil
var once sync.Once = sync.Once{}

func NewServiceContext(configName string) {

	once.Do(func() {
		cfg, err := config.Load(configName)
		if err != nil {
			panic(fmt.Sprintf("Not found file: %v\n", configName))
		}
		ctx = context.WithValue(context.Background(), serviceConfigKey, cfg)

		logger := logging.NewDefaultLogger(cfg)
		ctx = context.WithValue(ctx, serviceLoggingKey, logger)

		session_component := sessions.CreateSessionComponent(cfg)
		ctx = context.WithValue(ctx, serviceSessionKey, session_component)
	})
}

func GetService(target interface{}) {
	var ok bool = false

	valueTarget := reflect.ValueOf(target)
	if valueTarget.Kind() == reflect.Ptr && valueTarget.Elem().CanSet() {
		switch value := target.(type) {
		case *logging.Logger:
			*value, ok = ctx.Value(serviceLoggingKey).(logging.Logger)
		case *config.Configuration:
			*value, ok = ctx.Value(serviceConfigKey).(config.Configuration)
		case *sessions.SessionComponent:
			*value, ok = ctx.Value(serviceSessionKey).(sessions.SessionComponent)
		default:
		}
	}

	if !ok {
		panic("Not found requesting service")
	}
}
