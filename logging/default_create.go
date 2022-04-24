package logging

import (
	"camera/config"
	"log"
	"os"
	"strings"
)

func NewDefaultLogger(cfg config.Configuration) Logger {
	var level LogLevel = Debug

	if levelString, ok := cfg.GetString("logging:level"); ok {
		level = LogLevelFromString(levelString)
	}

	flags := log.LstdFlags | log.Lmsgprefix
	return &DefaultLogger{
		minLevel: level,
		loggers: map[LogLevel]*log.Logger{
			Trace:       log.New(os.Stdout, traceLabel, flags),
			Debug:       log.New(os.Stdout, debugLabel, flags),
			Information: log.New(os.Stdout, infoLabel, flags),
			Warning:     log.New(os.Stdout, warnLabel, flags),
			Fatal:       log.New(os.Stdout, fatalLabel, flags),
		},
		triggerPanic: true,
	}
}

func LogLevelFromString(val string) (level LogLevel) {
	switch strings.ToLower(val) {
	case "trace":
		level = Trace
	case "debug":
		level = Debug
	case "info":
		level = Information
	case "warning":
		level = Warning
	case "fatal":
		level = Fatal
	default:
		level = Debug
	}

	return
}
