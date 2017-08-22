package helpers

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"os"
)

func NewLogger(c Config) (logger log.Logger, err error){

	fileName,logLevel := c.LogConfig()
	logFile, err := os.Open(fileName)

	logger = log.NewLogfmtLogger(logFile)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	switch logLevel {
	case "DEBUG":
		logger = level.NewFilter(logger, level.AllowDebug())
	case "INFO":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "WARN":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "ERROR":
		logger = level.NewFilter(logger, level.AllowError())
	default:
		logger = level.NewFilter(logger, level.AllowNone())
	}
	return
}