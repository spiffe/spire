package helpers

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"os"
)

func NewLogger(logLevel string, fileName string) (logger log.Logger, err error) {
	logFile, err := os.Create(fileName)

	logger = log.NewLogfmtLogger(logFile)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.Caller(5))

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
