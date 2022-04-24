package services

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"camera/config"
	"camera/logging"
)

const serviceConfigKey = "service_config"
const serviceLoggingKey = "service_logging"

var ctx context.Context = nil

func NewServiceContext(configName string) {
	once := sync.Once{}

	once.Do(func() {
		cfg, err := config.Load(configName)
		if err != nil {
			panic(fmt.Sprintf("Not found file: %v\n", configName))
		}
		ctx = context.WithValue(context.Background(), serviceConfigKey, cfg)

		logger := logging.NewDefaultLogger(cfg)
		ctx = context.WithValue(ctx, serviceLoggingKey, logger)
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
		default:
		}
	}

	if !ok {
		panic("Not found requesting service")
	}
}
