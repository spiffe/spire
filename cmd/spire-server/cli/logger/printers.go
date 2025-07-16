package logger

import (
	"errors"
	"fmt"

	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	serverlogger "github.com/spiffe/spire/pkg/server/api/logger/v1"
)

func PrettyPrintLogger(env *commoncli.Env, results ...any) error {
	apiLogger, ok := results[0].(*apitype.Logger)
	if !ok {
		return fmt.Errorf("internal error: unexpected type %T returned; please report this as a bug", results[0])
	}

	logrusCurrent, found := serverlogger.LogrusLevel[apiLogger.CurrentLevel]
	if !found {
		return errors.New("internal error: returned current log level is undefined; please report this as a bug")
	}
	currentText, err := logrusCurrent.MarshalText()
	if err != nil {
		return fmt.Errorf("internal error: logrus log level %d has no name; please report this as a bug", logrusCurrent)
	}

	logrusLaunch, found := serverlogger.LogrusLevel[apiLogger.LaunchLevel]
	if !found {
		return errors.New("internal error: returned launch log level is undefined; please report this as a bug")
	}
	launchText, err := logrusLaunch.MarshalText()
	if err != nil {
		return fmt.Errorf("internal error: logrus log level %d has no name; please report this as a bug", logrusLaunch)
	}

	return env.Printf("Logger Level : %s\nLaunch Level : %s\n\n", currentText, launchText)
}
