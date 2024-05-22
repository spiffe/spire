package catalog

import (
	"context"

	"github.com/sirupsen/logrus"
)

func ReconfigureOnSignal(ctx context.Context, _ logrus.FieldLogger, _ Reconfigurer) error {
	// TODO: maybe drive this using an event?
	<-ctx.Done()
	return ctx.Err()
}
