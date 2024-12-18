package middleware

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func WithAuditLog(localTrackerEnabled bool) Middleware {
	return auditLogMiddleware{
		localTrackerEnabled: localTrackerEnabled,
	}
}

type auditLogMiddleware struct {
	Middleware

	localTrackerEnabled bool
}

func (m auditLogMiddleware) Preprocess(ctx context.Context, _ string, _ any) (context.Context, error) {
	log := rpccontext.Logger(ctx)
	if rpccontext.CallerIsLocal(ctx) && m.localTrackerEnabled {
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

func (m auditLogMiddleware) Postprocess(ctx context.Context, _ string, _ bool, rpcErr error) {
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

	if err := setFields(p, fields); err != nil {
		return nil, err
	}

	// Addr is expected to fail on k8s when "hostPID" is not provided
	addr, _ := getAddr(p)
	if addr != "" {
		fields[telemetry.CallerPath] = addr
	}

	if err := watcher.IsAlive(); err != nil {
		return nil, status.Errorf(codes.Internal, "peertracker fails: %v", err)
	}
	return fields, nil
}

func getAddr(proc *process.Process) (string, error) {
	path, err := proc.Exe()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed path lookup: %v", err)
	}

	return path, nil
}
