package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
)

var (
	misconfigLogMtx   sync.Mutex
	misconfigLogTimes = make(map[string]time.Time)
	misconfigClk      = clock.New()
)

const misconfigLogEvery = time.Minute

// LogMisconfiguration logs a misconfiguration for the RPC. It assumes that the
// context has been embellished with the names for the RPC. This method should
// not be called under normal operation and only when there is an
// implementation bug. As such there is no attempt at a time/space efficient
// implementation. In any case, the number of distinct misconfiguration
// messages intersected with the number of RPCs should not produce any amount
// of real memory use. Contention on the global mutex should also be
// reasonable.
func LogMisconfiguration(ctx context.Context, msg string) {
	if shouldLogMisconfiguration(ctx, msg) {
		rpccontext.Logger(ctx).Error(msg)
	}
}

func shouldLogMisconfiguration(ctx context.Context, msg string) bool {
	names, _ := rpccontext.Names(ctx)
	key := names.Service + "|" + names.Method + "|" + msg

	now := misconfigClk.Now()

	misconfigLogMtx.Lock()
	defer misconfigLogMtx.Unlock()
	last, ok := misconfigLogTimes[key]
	if !ok || now.Sub(last) >= misconfigLogEvery {
		misconfigLogTimes[key] = now
		return true
	}
	return false
}
