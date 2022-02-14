package middleware

import (
	"context"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func WithAuditLog(udsTrackerEnabled bool) Middleware {
	return auditLogMiddleware{
		udsTrackerEnabled: udsTrackerEnabled,
	}
}

type auditLogMiddleware struct {
	Middleware

	udsTrackerEnabled bool
}

func (m auditLogMiddleware) Preprocess(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
	log := rpccontext.Logger(ctx)
	if rpccontext.CallerIsLocal(ctx) && m.udsTrackerEnabled {
		fields, err := fieldsFromTracker(ctx)
		if err != nil {
			return nil, err
		}

		log = log.WithFields(fields)
	}

	auditLog := audit.New(log)

	ctx = rpccontext.WithAuditLog(ctx, auditLog)

	return ctx, nil
}

func (m auditLogMiddleware) Postprocess(ctx context.Context, fullMethod string, handlerInvoked bool, rpcErr error) {
	if rpcErr != nil {
		if auditLog, ok := rpccontext.AuditLog(ctx); ok {
			auditLog.AuditWithError(rpcErr)
		}
	}
}

func fieldsFromTracker(ctx context.Context) (logrus.Fields, error) {
	fields := make(logrus.Fields)
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "failed to get peertracker")
	}
	pID := watcher.PID()

	p, err := process.NewProcess(pID)
	if err != nil {
		return nil, err
	}

	uID, err := getUID(p)
	if err != nil {
		return nil, err
	}
	fields[telemetry.CallerUID] = uID

	gID, err := getGID(p)
	if err != nil {
		return nil, err
	}
	fields[telemetry.CallerGID] = gID

	// Addr expected to fail on k8s when "hostPID" is not provided
	addr, _ := getAddr(p)
	if addr != "" {
		fields[telemetry.CallerPath] = addr
	}

	if err := watcher.IsAlive(); err != nil {
		return nil, status.Errorf(codes.Internal, "peertracker fails: %v", err)
	}
	return fields, nil
}

func getUID(proc *process.Process) (int32, error) {
	uids, err := proc.Uids()
	if err != nil {
		return 0, status.Errorf(codes.Internal, "failed UIDs lookup: %v", err)
	}

	switch len(uids) {
	case 0:
		return 0, status.Error(codes.Internal, "failed UIDs lookup: no UIDs for process")
	case 1:
		return uids[0], nil
	default:
		return uids[1], nil
	}
}

func getGID(proc *process.Process) (int32, error) {
	gids, err := proc.Gids()
	if err != nil {
		return 0, status.Errorf(codes.Internal, "failed GIDs lookup: %v", err)
	}

	switch len(gids) {
	case 0:
		return 0, status.Error(codes.Internal, "failed GIDs lookup: no GIDs for process")
	case 1:
		return gids[0], nil
	default:
		return gids[1], nil
	}
}

func getAddr(proc *process.Process) (string, error) {
	path, err := proc.Exe()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed path lookup: %v", err)
	}

	return path, nil
}
