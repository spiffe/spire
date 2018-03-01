package workload

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"

	context "golang.org/x/net/context"
)

// Handler implements the Workload API interface
type Handler struct {
	CacheMgr manager.Manager
	Catalog  catalog.Catalog
	L        logrus.FieldLogger

	// TTL in SVID response will never
	// be larger than this
	MaxTTL time.Duration

	// TTL in SVID response will never
	// be smaller than this. Prevents
	// hammering towards the end
	MinTTL time.Duration

	// We must store the current server bundle for
	// distrubution to workloads. It is updaetd periodically,
	// protect it with a mutex.
	M      sync.RWMutex
	Bundle []*x509.Certificate
}

// SetBundle exposes a setter for configuring the CA bundle. This
// bundle is passed to the workload.
func (h *Handler) SetBundle(bundle []*x509.Certificate) {
	h.M.Lock()
	defer h.M.Unlock()

	h.Bundle = bundle
	return
}

func (h *Handler) FetchBundles(ctx context.Context, spiffeID *workload.SpiffeID) (*workload.Bundles, error) {
	entries, err := h.fetchAllEntries(ctx)
	if err != nil {
		return nil, err
	}

	var myEntry *cache.Entry
	for _, e := range entries {
		if e.RegistrationEntry.SpiffeId == spiffeID.Id {
			myEntry = &e
			break
		}
	}

	// We didn't find an entry for the requested SPIFFE ID. It either
	// doesn't exist, or the workload is not entitled to it.
	if myEntry == nil {
		return &workload.Bundles{}, fmt.Errorf("SVID for %s not found or not authorized", spiffeID.Id)
	}

	return h.composeResponse([]cache.Entry{*myEntry})
}

func (h *Handler) FetchAllBundles(ctx context.Context, _ *workload.Empty) (*workload.Bundles, error) {
	entries, err := h.fetchAllEntries(ctx)
	if err != nil {
		return nil, err
	}

	return h.composeResponse(entries)
}

// fetchAllEntries ties this whole thing together, and is called by both API endpoints. Given
// a context, it works out all cache entries to which the workload is entitled. Returns the
// set of entries, and an error if one is encountered along the way.
func (h *Handler) fetchAllEntries(ctx context.Context) (entries []cache.Entry, err error) {
	pid, err := h.resolveCaller(ctx)
	if err != nil {
		err = fmt.Errorf("Error encountered while trying to identify the caller: %s", err)
		return entries, err
	}

	// Workload attestor errors are non-fatal
	selectors, err := h.attestCaller(pid)
	if err != nil {
		err = fmt.Errorf("Error encountered while attesting caller: %s", err)
		return entries, err
	}
	//done := make(chan struct{})
	//entriesCh := h.CacheMgr.Subscribe(selectors, done)
	//for e := range entriesCh {
	//	entries = append(entries, e.Entries)
	//}
	return h.CacheMgr.MatchingEntries(selectors), nil
}

// resolveCaller takes a grpc context, and returns the PID of the caller which has issued
// the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the auth package for more information.
func (h *Handler) resolveCaller(ctx context.Context) (pid int32, err error) {
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

// attestCaller takes a PID and invokes attestation plugins against it, and returns the union
// of selectors discovered by the attestors. If a plugin encounters an error, its returned
// selectors are discarded and the error is logged.
func (h *Handler) attestCaller(pid int32) (selectors []*common.Selector, err error) {
	// Call the workload attestors concurrently
	plugins := h.Catalog.WorkloadAttestors()
	selectorChan := make(chan []*common.Selector)
	errorChan := make(chan struct {
		workloadattestor.WorkloadAttestor
		error
	})
	for _, plugin := range plugins {
		go func(p workloadattestor.WorkloadAttestor) {
			s, err := p.Attest(&workloadattestor.AttestRequest{Pid: pid})
			if err != nil {
				errorChan <- struct {
					workloadattestor.WorkloadAttestor
					error
				}{p, err}
				return
			}

			selectorChan <- s.Selectors
			return
		}(plugin)
	}

	// Collect the results
	for i := 0; i < len(plugins); i++ {
		select {
		case selectorSet := <-selectorChan:
			selectors = append(selectors, selectorSet...)
		case pluginError := <-errorChan:
			pluginInfo := h.Catalog.Find(pluginError.WorkloadAttestor.(common_catalog.Plugin))
			pluginName := "UnknownPlugin"
			if pluginInfo != nil {
				pluginName = pluginInfo.Config.PluginName
			}
			h.L.Warnf("Workload attestor %s returned an error: %s", pluginName, pluginError.error)
		}
	}

	return selectors, nil
}

// composeResponse takes a set of cache entries, and packs them into a protobuf response
func (h *Handler) composeResponse(entries []cache.Entry) (response *workload.Bundles, err error) {
	var certs []*x509.Certificate
	var bundles []*workload.WorkloadEntry

	// Grab a copy of the SVID bundle
	h.M.RLock()
	var svidBundle []byte
	for _, b := range h.Bundle {
		svidBundle = append(svidBundle, b.Raw...)
	}
	h.M.RUnlock()

	for _, e := range entries {
		keyData, err := x509.MarshalECPrivateKey(e.PrivateKey)
		if err != nil {
			err = fmt.Errorf("Could not marshall cached private key for %s: %s", e.RegistrationEntry.SpiffeId, err)
			return nil, err
		}

		we := &workload.WorkloadEntry{
			SpiffeId:         e.RegistrationEntry.SpiffeId,
			Svid:             e.SVID.Raw,
			SvidPrivateKey:   keyData,
			SvidBundle:       svidBundle,
			FederatedBundles: e.Bundles,
		}

		certs = append(certs, e.SVID)
		bundles = append(bundles, we)
	}

	ttl := h.calculateTTL(certs).Seconds()
	response = &workload.Bundles{
		Bundles: bundles,
		Ttl:     int32(ttl),
	}
	if len(bundles) == 0 {
		err = fmt.Errorf("Cache is busy. Retry later")
	}
	return response, err
}

// calculateTTL takes a slice of certificates and iterates over them,
// returning a TTL for use in the workload API response. Workload API
// clients should check back for updates after TTL has elapsed
func (h *Handler) calculateTTL(certs []*x509.Certificate) time.Duration {
	ttl := h.MaxTTL
	for _, cert := range certs {
		var t time.Duration

		// set the watermark at half way
		watermark := cert.NotAfter.Sub(cert.NotBefore) / 2
		renewTime := cert.NotBefore.Add(watermark)

		if time.Now().After(renewTime) {
			t = h.MinTTL
		} else {
			t = time.Until(renewTime) + time.Second
		}

		if t < ttl {
			ttl = t
		}
	}

	if ttl < h.MinTTL {
		ttl = h.MinTTL
	}

	return ttl
}
