//go:build windows

package endpoints

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func getCallerKey(ctx context.Context) string {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if !ok {
		return "unknown"
	}

	return fmt.Sprintf("pid:%d", watcher.PID())
}
