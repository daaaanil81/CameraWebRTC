package logging

type LogLevel int

const (
	Trace LogLevel = iota
	Debug
	Information
	Warning
	Fatal
	None
)

const (
	colorRed    string = "\033[31m"
	colorGreen         = "\033[32m"
	colorYellow        = "\033[33m"
	colorBlue          = "\033[34m"
	colorPurple        = "\033[35m"
	colorCyan          = "\033[36m"
	colorWhite         = "\033[37m"
	colorReset         = "\033[0m"
)

const (
	traceLabel string = "[" + colorWhite + "TRACE" + colorReset + "] "
	debugLabel        = "[" + colorGreen + "DEBUG" + colorReset + "] "
	infoLabel         = "[" + colorBlue + "INFO" + colorReset + "] "
	warnLabel         = "[" + colorYellow + "WARNING" + colorReset + "] "
	fatalLabel        = "[" + colorRed + "FATAL" + colorReset + "] "
)

type Logger interface {
	Trace(string)
	Tracef(string, ...interface{})

	Debug(string)
	Debugf(string, ...interface{})

	Info(string)
	Infof(string, ...interface{})

	Warn(string)
	Warnf(string, ...interface{})

	Panic(string)
	Panicf(string, ...interface{})
}
