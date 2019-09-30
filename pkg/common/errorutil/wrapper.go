package errorutil

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/logutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// WrapAndLogError logs an error received from a function/method call using the provided logger instance
// and creates a new error in the format: "<newErrStr>: <err>".
// This function is intended to be used to wrap errors and emit ERROR level logs
// when an error is received from calling a function/method inside of a function or private method.
func WrapAndLogError(logger logrus.FieldLogger, err error, newErrStr string) error {
	log := logger.WithField(telemetry.Error, err)
	logutil.LogErrorStr(log, newErrStr)
	return wrapError(err, newErrStr)
}

// WrapAndLogError logs an error received from a function/method call using the provided logger instance
// and creates a new error in the format: "<newErrStr>: <err>".
// This function is intended to be used from plugin code using hclog to wrap errors and emit ERROR level logs
// when an error is received from calling a function/method inside of a function or private method.
func WrapAndLogPluginError(logger hclog.Logger, err error, newErrStr string) error {
	log := logger.With(telemetry.Error, err)
	logutil.LogPluginErrorStr(log, newErrStr)
	return wrapError(err, newErrStr)
}

func wrapError(err error, newErrStr string) error {
	return fmt.Errorf(newErrStr + ": %v", err)
}
