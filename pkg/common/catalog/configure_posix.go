//go:build !windows

package catalog

import (
	"context"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func ReconfigureOnSignal(ctx context.Context, log logrus.FieldLogger, reconfigurer Reconfigurer) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGUSR1)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			log.Info("Reconfigure signal received")
			reconfigurer.Reconfigure(ctx)
		}
	}
}
