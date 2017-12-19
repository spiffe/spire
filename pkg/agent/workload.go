package agent

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	context "golang.org/x/net/context"

	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"
)

// workloadServer implements the Workload API interface
type workloadServer struct {
	cacheMrg cache.Manager
	catalog  catalog.Catalog
	l        logrus.FieldLogger

	// TTL in SVID response will never
	// be larger than this
	maxTTL time.Duration

	// TTL in SVID response will never
	// be smaller than this. Prevents
	// hammering towards the end
	minTTL time.Duration

	// We must store the current server bundle for
	// distrubution to workloads. It is updaetd periodically,
	// protect it with a mutex.
	m      sync.RWMutex
	bundle []byte
}

// SetBundle exposes a setter for configuring the CA bundle. This
// bundle is passed to the workload.
func (s *workloadServer) SetBundle(bundle []byte) {
	s.m.Lock()
	defer s.m.Unlock()

	s.bundle = bundle
	return
}

func (s *workloadServer) FetchBundles(ctx context.Context, spiffeID *workload.SpiffeID) (*workload.Bundles, error) {
	entries, err := s.fetchAllEntries(ctx)
	if err != nil {
		return nil, err
	}

	var myEntry *cache.CacheEntry
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

	return s.composeResponse([]cache.CacheEntry{*myEntry})
}

func (s *workloadServer) FetchAllBundles(ctx context.Context, _ *workload.Empty) (*workload.Bundles, error) {
	entries, err := s.fetchAllEntries(ctx)
	if err != nil {
		return nil, err
	}

	return s.composeResponse(entries)
}

// fetchAllEntries ties this whole thing together, and is called by both API endpoints. Given
// a context, it works out all cache entries to which the workload is entitled. Returns the
// set of entries, and an error if one is encountered along the way.
func (s *workloadServer) fetchAllEntries(ctx context.Context) (entries []cache.CacheEntry, err error) {
	pid, err := s.resolveCaller(ctx)
	if err != nil {
		err = fmt.Errorf("Error encountered while trying to identify the caller: %s", err)
		return entries, err
	}

	// Workload attestor errors are non-fatal
	selectors, err := s.attestCaller(pid)
	if err != nil {
		err = fmt.Errorf("Error encountered while attesting caller: %s", err)
		return entries, err
	}

	return s.cacheMrg.Cache().MatchingEntries(selectors), nil
}

// resolveCaller takes a grpc context, and returns the PID of the caller which has issued
// the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the auth package for more information.
func (s *workloadServer) resolveCaller(ctx context.Context) (pid int32, err error) {
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
func (s *workloadServer) attestCaller(pid int32) (selectors []*common.Selector, err error) {
	// Call the workload attestors concurrently
	plugins := s.catalog.WorkloadAttestors()
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
			pluginInfo := s.catalog.Find(pluginError.WorkloadAttestor.(common_catalog.Plugin))
			pluginName := "UnknownPlugin"
			if pluginInfo != nil {
				pluginName = pluginInfo.Config.PluginName
			}
			s.l.Warnf("Workload attestor %s returned an error: %s", pluginName, pluginError.error)
		}
	}

	return selectors, nil
}

// composeResponse takes a set of cache entries, and packs them into a protobuf response
func (s *workloadServer) composeResponse(entries []cache.CacheEntry) (response *workload.Bundles, err error) {
	var certs []*x509.Certificate
	var bundles []*workload.WorkloadEntry

	// TODO: Better way to do this?
	// Grab a copy of the SVID bundle
	s.m.RLock()
	var svidBundle []byte
	for _, b := range s.bundle {
		svidBundle = append(svidBundle, b)
	}
	s.m.RUnlock()

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

	ttl := s.calculateTTL(certs).Seconds()
	response = &workload.Bundles{
		Bundles: bundles,
		Ttl:     int32(ttl),
	}
	if len(bundles) == 0 && s.cacheMrg.Busy() {
		err = fmt.Errorf("Cache is busy. Retry later")
	}
	return response, err
}

// calculateTTL takes a slice of certificates and iterates over them,
// returning a TTL for use in the workload API response. Workload API
// clients should check back for updates after TTL has elapsed
func (s *workloadServer) calculateTTL(certs []*x509.Certificate) time.Duration {
	ttl := s.maxTTL
	for _, cert := range certs {
		var t time.Duration

		// set the watermark at half way
		watermark := cert.NotAfter.Sub(cert.NotBefore) / 2
		renewTime := cert.NotBefore.Add(watermark)

		if time.Now().After(renewTime) {
			t = s.minTTL
		} else {
			t = time.Until(renewTime) + time.Second
		}

		if t < ttl {
			ttl = t
		}
	}

	if ttl < s.minTTL {
		ttl = s.minTTL
	}

	return ttl
}
