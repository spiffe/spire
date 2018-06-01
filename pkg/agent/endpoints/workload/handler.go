package workload

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/api/workload"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Handler implements the Workload API interface
type Handler struct {
	Manager manager.Manager
	Catalog catalog.Catalog
	L       logrus.FieldLogger
	T       telemetry.Sink
}

const (
	workloadApi = "workload_api"
	workloadPid = "workload_pid"
)

func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return grpc.Errorf(codes.InvalidArgument, "Security header missing from request")
	}

	pid, err := h.callerPID(ctx)
	if err != nil {
		return grpc.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	tLabels := []telemetry.Label{{workloadPid, string(pid)}}
	h.T.IncrCounterWithLabels([]string{workloadApi, "connection"}, 1, tLabels)
	h.T.IncrCounterWithLabels([]string{workloadApi, "connections"}, 1, tLabels)
	defer h.T.IncrCounterWithLabels([]string{workloadApi, "connections"}, -1, tLabels)

	config := attestor.Config{
		Catalog: h.Catalog,
		L:       h.L,
		T:       h.T,
	}

	selectors := attestor.New(&config).Attest(ctx, pid)

	subscriber := h.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			h.T.IncrCounterWithLabels([]string{workloadApi, "update"}, 1, tLabels)

			start := time.Now()
			err := h.sendResponse(update, stream)
			if err != nil {
				return err
			}

			h.T.MeasureSinceWithLabels([]string{workloadApi, "update_latency"}, start, tLabels)
			if time.Since(start) > (1 * time.Second) {
				h.L.Warnf("Took %v seconds to send update to PID %v", time.Since(start).Seconds, pid)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *Handler) sendResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if len(update.Entries) == 0 {
		return grpc.Errorf(codes.PermissionDenied, "no identity issued")
	}

	resp, err := h.composeResponse(update)
	if err != nil {
		return grpc.Errorf(codes.Unavailable, "Could not serialize response: %v", err)
	}

	return stream.Send(resp)
}

func (h *Handler) composeResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
	resp := new(workload.X509SVIDResponse)
	resp.Svids = []*workload.X509SVID{}

	bundle := []byte{}
	for _, c := range update.Bundle {
		bundle = append(bundle, c.Raw...)
	}

	for _, e := range update.Entries {
		id := e.RegistrationEntry.SpiffeId

		keyData, err := x509.MarshalPKCS8PrivateKey(e.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %v", id, err)
		}

		svid := &workload.X509SVID{
			SpiffeId:    id,
			X509Svid:    e.SVID.Raw,
			X509SvidKey: keyData,
			Bundle:      bundle,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	return resp, nil
}

// callerPID takes a grpc context, and returns the PID of the caller which has issued
// the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the auth package for more information.
func (h *Handler) callerPID(ctx context.Context) (pid int32, err error) {
	info, ok := auth.CallerFromContext(ctx)
	if !ok {
		return 0, errors.New("Unable to fetch credentials from context")
	}

	if info.Err != nil {
		return 0, fmt.Errorf("Unable to resolve caller PID: %s", info.Err)
	}

	// If PID is 0, something is wrong...
	if info.PID == 0 {
		return 0, errors.New("Unable to resolve caller PID")
	}

	return info.PID, nil
}
