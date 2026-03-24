//go:build !windows

package endpoints

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/containerinfo"
	"github.com/spiffe/spire/pkg/common/peertracker"
)

var (
	extractor = &containerinfo.Extractor{
		RootDir: "/",
	}
)

func getCallerKey(ctx context.Context) string {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if !ok {
		return "unknown"
	}

	podUID, _, err := extractor.GetPodUIDAndContainerID(watcher.PID(), hclog.NewNullLogger())
	if err == nil && podUID != "" {
		return fmt.Sprintf("pod-uid:%s", podUID)
	}

	return fmt.Sprintf("pid:%d", watcher.PID())
}
