package logger

import (
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

func PrettyPrintLogger(env *commoncli.Env, results ...any) error {
	logger, ok := results[0].(*types.Logger)
	if !ok {
		return errors.New("internal error: logger not found; please report this as a bug")
	}
	if err := env.Printf("Logger Level  : %s\nLogger Default: %s\n\n", logrus.Level(logger.CurrentLevel), logrus.Level(logger.DefaultLevel)); err != nil {
		return err
	}
	return nil
}

