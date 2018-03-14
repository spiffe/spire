package workload

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"

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

func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return grpc.Errorf(codes.InvalidArgument, "Security header missing from request")
	}

	pid, err := h.callerPID(stream.Context())
	if err != nil {
		return grpc.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	tLabels := []telemetry.Label{{"workload_pid", string(pid)}}
	h.T.IncrCounterWithLabels([]string{"workload_api", "connection"}, 1, tLabels)
	h.T.IncrCounterWithLabels([]string{"workload_api", "connections"}, 1, tLabels)
	defer h.T.IncrCounterWithLabels([]string{"workload_api", "connections"}, -1, tLabels)

	selectors := h.attest(pid)
	done := make(chan struct{})
	defer close(done)
	subscription := h.Manager.Subscribe(selectors, done)

	for {
		select {
		case update := <-subscription:
			h.T.IncrCounterWithLabels([]string{"workload_api", "update"}, 1, tLabels)

			start := time.Now()
			err := h.sendResponse(update, stream)
			if err != nil {
				return err
			}

			h.T.MeasureSinceWithLabels([]string{"workload_api", "update_latency"}, start, tLabels)
			if time.Since(start) > (1 * time.Second) {
				h.L.Warnf("Took %v seconds to send update to PID %v", time.Since(start).Seconds, pid)
			}
		case <-stream.Context().Done():
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

// attest invokes all workload attestor plugins against the provided PID. If an error
// is encountered, it is logged and selectors from the failing plugin are discarded.
func (h *Handler) attest(pid int32) []*common.Selector {
	tLabels := []telemetry.Label{{"workload_pid", string(pid)}}
	defer h.T.MeasureSinceWithLabels([]string{"workload_api", "attest_duration"}, time.Now(), tLabels)

	plugins := h.Catalog.WorkloadAttestors()
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	for _, p := range plugins {
		go h.invokeAttestor(p, pid, sChan, errChan)
	}

	// Collect the results
	selectors := []*common.Selector{}
	for i := 0; i < len(plugins); i++ {
		select {
		case s := <-sChan:
			selectors = append(selectors, s...)
		case err := <-errChan:
			h.L.Errorf("Failed to collect all selectors for PID %v: %v", pid, err)
		}
	}

	h.T.AddSampleWithLabels([]string{"workload_api", "discovered_selectors"}, float32(len(selectors)), tLabels)
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (h *Handler) invokeAttestor(a workloadattestor.WorkloadAttestor, pid int32, sChan chan []*common.Selector, errChan chan error) {
	attestorName := h.attestorName(a)
	tLabels := []telemetry.Label{{"workload_pid", string(pid)}, {"attestor_name", attestorName}}

	req := &workloadattestor.AttestRequest{
		Pid: pid,
	}

	start := time.Now()
	resp, err := a.Attest(req)
	h.T.MeasureSinceWithLabels([]string{"workload_api", "attestor_latency"}, start, tLabels)
	if err != nil {
		errChan <- fmt.Errorf("call %v workload attestor: %v", attestorName, err)
		return
	}

	sChan <- resp.Selectors
	return
}

// attestorName attempts to find the name of a workload attestor, given the WorkloadAttestor interface.
func (h *Handler) attestorName(a workloadattestor.WorkloadAttestor) string {
	mp := h.Catalog.Find(a)
	if mp == nil {
		return "unknown"
	}

	return mp.Config.PluginName
}
