package agent

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/helpers"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/agent/workloadattestor"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/selector"

	pb "github.com/spiffe/spire/pkg/api/workload"
	context "golang.org/x/net/context"
)

// workloadServer implements the Workload API interface
type workloadServer struct {
	cache   cache.Cache
	catalog helpers.PluginCatalog
	l       logrus.FieldLogger

	// TTL in SVID response will never
	// be larger than this
	maxTTL time.Duration

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

func (s *workloadServer) FetchBundles(ctx context.Context, spiffeID *pb.SpiffeID) (*pb.Bundles, error) {
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
		return &pb.Bundles{}, fmt.Errorf("SVID for %s not found or not authorized", spiffeID.Id)
	}

	return s.composeResponse([]cache.CacheEntry{*myEntry})
}

func (s *workloadServer) FetchAllBundles(ctx context.Context, _ *pb.Empty) (*pb.Bundles, error) {
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
	selectors, errMap := s.attestCaller(pid)
	for name, err := range errMap {
		s.l.Warnf("Workload attestor %s returned an error: %s", name, err)
	}

	selectorSet := selector.NewSet(selectors)
	return s.findEntries(selectorSet), nil
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
// selectors are discarded and the error is added to the returned error map.
func (s *workloadServer) attestCaller(pid int32) (selectors []*common.Selector, errs map[string]error) {
	var plugins []workloadattestor.WorkloadAttestor
	pluginClients := s.catalog.GetPluginsByType("WorkloadAttestor")
	for _, p := range pluginClients {
		plugins = append(plugins, p.(workloadattestor.WorkloadAttestor))
	}

	// Call the workload attestors concurrently
	selectorChan, errorChan := make(chan []*common.Selector), make(chan error)
	defer close(selectorChan)
	defer close(errorChan)
	for _, p := range plugins {
		go func() {
			s, err := p.Attest(&workloadattestor.AttestRequest{Pid: pid})
			if err != nil {
				errorChan <- err
				return
			}

			selectorChan <- s.Selectors
			return
		}()
	}

	// Collect the results
	for i := 0; i < len(plugins); i++ {
		select {
		case selectorSet := <-selectorChan:
			selectors = append(selectors, selectorSet...)
		case pluginError := <-errorChan:
			// TODO: Ask the plugin for its name
			// Probably need to re-think this channel
			errs["PLUGIN_NAME"] = pluginError
		}
	}

	return selectors, errs
}

// findEntries takes a slice of selectors, and works through all the combinations in order to
// find matching cache entries
func (s *workloadServer) findEntries(selectors selector.Set) (entries []cache.CacheEntry) {
	for combination := range selectors.Power() {
		combinationEntries := s.cache.Entry(combination.Raw())
		if len(combinationEntries) > 0 {
			entries = append(entries, combinationEntries...)
		}
	}

	return entries
}

// composeResponse takes a set of cache entries, and packs them into a protobuf response
func (s *workloadServer) composeResponse(entries []cache.CacheEntry) (response *pb.Bundles, err error) {
	var bundles []*pb.WorkloadEntry
	var expirys []time.Time

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

		we := &pb.WorkloadEntry{
			SpiffeId:         e.RegistrationEntry.SpiffeId,
			Svid:             e.SVID.SvidCert,
			SvidPrivateKey:   keyData,
			SvidBundle:       svidBundle,
			FederatedBundles: e.Bundles,
		}

		expirys = append(expirys, e.Expiry)
		bundles = append(bundles, we)
	}

	// Given all expiration times, determine a
	// TTL for the bundle response. Client should
	// check back after TTL
	minTTL := s.maxTTL
	for _, e := range expirys {
		ttl := time.Until(e) / 2
		if ttl < minTTL {
			minTTL = ttl
		}
	}

	response = &pb.Bundles{
		Bundles: bundles,
		Ttl:     int32(minTTL.Seconds()),
	}
	return response, nil
}
