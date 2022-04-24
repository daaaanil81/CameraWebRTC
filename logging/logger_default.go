package logging

import (
	"fmt"
	"log"
)

type DefaultLogger struct {
	minLevel     LogLevel
	loggers      map[LogLevel]*log.Logger
	triggerPanic bool
}

func (l *DefaultLogger) MinLogLevel() LogLevel {
	return l.minLevel
}

func (l *DefaultLogger) write(level LogLevel, message string) {
	if l.minLevel <= level {
		l.loggers[level].Output(2, message)
	}
}

func (l *DefaultLogger) Trace(message string) {
	l.write(Trace, message)
}

func (l *DefaultLogger) Tracef(format string, values ...interface{}) {
	l.write(Trace, fmt.Sprintf(format, values...))
}

func (l *DefaultLogger) Debug(message string) {
	l.write(Debug, message)
}

func (l *DefaultLogger) Debugf(format string, values ...interface{}) {
	l.write(Debug, fmt.Sprintf(format, values...))
}

func (l *DefaultLogger) Info(message string) {
	l.write(Information, message)
}

func (l *DefaultLogger) Infof(format string, values ...interface{}) {
	l.write(Information, fmt.Sprintf(format, values...))
}

func (l *DefaultLogger) Warn(message string) {
	l.write(Warning, message)
}

func (l *DefaultLogger) Warnf(format string, values ...interface{}) {
	l.write(Warning, fmt.Sprintf(format, values...))
}

func (l *DefaultLogger) Panic(message string) {
	l.write(Fatal, message)
	if l.triggerPanic {
		panic(message)
	}
}

func (l *DefaultLogger) Panicf(format string, values ...interface{}) {
	message := fmt.Sprintf(format, values...)
	l.write(Fatal, message)
	if l.triggerPanic {
		panic(message)
	}
}
