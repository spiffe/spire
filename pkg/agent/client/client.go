package client

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/backoff"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultRPCTimeout       = 30 * time.Second
	defaultMaxBundleWorkers = 10

	// federatedBundleRefreshAttempts is how many times the agent tries to
	// refresh a federated bundle within its refresh hint, matching how the
	// server schedules updates from federated bundle endpoints.
	federatedBundleRefreshAttempts = 4

	// defaultFederatedBundleRefreshInterval is how long to wait before
	// refreshing a federated bundle that publishes no refresh hint, matching the
	// interval the server uses for the same case.
	defaultFederatedBundleRefreshInterval = 5 * time.Minute
)

var (
	ErrUnableToGetStream = errors.New("unable to get a stream")

	rpcTimeout = defaultRPCTimeout

	// maxBundleWorkers is the maximum number of worker goroutines to use when fetching bundles.
	maxBundleWorkers = defaultMaxBundleWorkers

	entryOutputMask = &types.EntryMask{
		SpiffeId:             true,
		Selectors:            true,
		FederatesWith:        true,
		Admin:                true,
		Downstream:           true,
		RevisionNumber:       true,
		StoreSvid:            true,
		Hint:                 true,
		AdditionalAttributes: true,
		CreatedAt:            true,
	}

	// RPCTimeoutWithCacheHit can be more aggressive with timeouts in cases where a valid SVID
	// exists in the cache but is old enough to try for a new SVID quickly. This is configurable
	// in the Experimental Config of the Agent, and can be set as low as 5 seconds
	RPCTimeoutWithCacheHit = defaultRPCTimeout

	// jwtSVIDRetryInterval is the initial backoff interval used when retrying
	// transient NewJWTSVID failures. It is a var so tests can shorten it.
	jwtSVIDRetryInterval = time.Second
)

func SetRPCTimeout(d time.Duration) {
	rpcTimeout = d
}

func SetMaxBundleWorkers(n int) {
	maxBundleWorkers = n
}

func SetJWTSVIDCacheHitTimeout(d time.Duration) {
	RPCTimeoutWithCacheHit = d
}

type X509SVID struct {
	CertChain []byte
	ExpiresAt int64
}

type JWTSVID struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type WITSVID struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type SyncStats struct {
	Entries SyncEntriesStats
	Bundles SyncBundlesStats
}

type SyncEntriesStats struct {
	Total   int
	Missing int
	Stale   int
	Dropped int
}

type SyncBundlesStats struct {
	Total int
}

type Client interface {
	SyncUpdates(ctx context.Context, cachedEntries map[string]*common.RegistrationEntry, cachedBundles map[string]*common.Bundle) (SyncStats, error)
	RenewSVID(ctx context.Context, csr []byte) (*X509SVID, error)
	NewX509SVIDs(ctx context.Context, csrs map[string][]byte) (map[string]*X509SVID, error)
	NewJWTSVID(ctx context.Context, entryID string, audience []string, hasCacheHit bool) (*JWTSVID, spiffeid.ID, error)
	NewWITSVIDs(ctx context.Context, publicKeys map[string]crypto.PublicKey, signatureAlgorithm string) (map[string]*WITSVID, error)
	PostStatus(ctx context.Context, agentVersion string) error

	// Release releases any resources that were held by this Client, if any.
	Release()
}

// Config holds a client configuration
type Config struct {
	Addr        string
	Log         logrus.FieldLogger
	TrustDomain spiffeid.TrustDomain
	// KeysAndBundle is a callback that must return the keys and bundle used by the client
	// to connect via mTLS to Addr.
	KeysAndBundle func() ([]*x509.Certificate, crypto.Signer, []*x509.Certificate)

	// RotMtx is used to prevent the creation of new connections during SVID rotations
	RotMtx *sync.RWMutex

	// TLSPolicy determines the post-quantum-safe policy to apply to all TLS connections.
	TLSPolicy tlspolicy.Policy

	// LoadBalancingConfig is an optional, opaque payload used as the
	// loadBalancingConfig field of the gRPC service config.
	LoadBalancingConfig string

	// MinFederatedBundleSyncInterval is a lower bound on how often a
	// federated bundle is refreshed from the server. It only applies when a
	// bundle's refresh hint asks to be polled more often than this; a longer
	// refresh hint is always honored.
	MinFederatedBundleSyncInterval time.Duration
}

type client struct {
	c           *Config
	connections *nodeConn
	m           sync.Mutex

	// clk is used for backoff timing when retrying transient failures.
	clk clock.Clock

	// dialOpts optionally sets gRPC dial options
	dialOpts []grpc.DialOption

	// nextFederatedBundleSync is the earliest time each federated trust
	// domain should be fetched again, derived from the refresh hint of the
	// bundle last received for it. A trust domain absent here has not been
	// fetched yet and is always included in the next sync.
	federatedSyncMu         sync.Mutex
	nextFederatedBundleSync map[string]time.Time
	// warnedRefreshHint records the refresh hint each trust domain was last
	// warned about, so the warning is logged once per hint rather than on
	// every refresh.
	warnedRefreshHint map[string]time.Duration
}

// fetchBundleResult contains the result of fetching a federated bundle.
type fetchBundleResult struct {
	bundle *types.Bundle
	err    error
}

// New creates a new client struct with the configuration provided
func New(c *Config) Client {
	return newClient(c)
}

func newClient(c *Config) *client {
	return &client{
		c:   c,
		clk: clock.New(),
	}
}

func (c *client) SyncUpdates(ctx context.Context, cachedEntries map[string]*common.RegistrationEntry, cachedBundles map[string]*common.Bundle) (SyncStats, error) {
	switch {
	case cachedEntries == nil:
		return SyncStats{}, errors.New("non-nil cached entries map is required")
	case cachedBundles == nil:
		return SyncStats{}, errors.New("non-nil cached bundles map is required")
	}

	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	entriesStats, err := c.syncEntries(ctx, cachedEntries)
	if err != nil {
		return SyncStats{}, err
	}

	federatedTrustDomains := make(stringSet)
	for _, entry := range cachedEntries {
		for _, federatesWith := range entry.FederatesWith {
			federatedTrustDomains.Add(federatesWith)
		}
	}

	federatedToFetch := c.federatedBundlesToFetch(federatedTrustDomains)

	protoBundles, err := c.fetchBundles(ctx, federatedToFetch)
	if err != nil {
		return SyncStats{}, err
	}

	// Drop bundles for trust domains the agent no longer federates with, and
	// bundles that were just fetched, so that a trust domain the server no
	// longer has a bundle for stops being served from the cache. Trust domains
	// not due for a refresh keep their cached bundle. The local bundle is
	// refetched on every sync so it is always replaced below.
	for td := range cachedBundles {
		if td == c.c.TrustDomain.IDString() {
			continue
		}
		if _, ok := federatedTrustDomains[td]; !ok {
			delete(cachedBundles, td)
		}
	}
	for _, td := range federatedToFetch {
		delete(cachedBundles, td)
	}

	for _, b := range protoBundles {
		bundle, err := bundleutil.CommonBundleFromProto(b)
		if err != nil {
			c.c.Log.WithError(err).Warn("Received malformed bundle from SPIRE server; are the server and agent versions compatible?")
			continue
		}
		cachedBundles[bundle.TrustDomainId] = bundle
	}

	c.scheduleFederatedBundleRefresh(federatedToFetch, federatedTrustDomains, cachedBundles)

	return SyncStats{
		Entries: entriesStats,
		Bundles: SyncBundlesStats{
			Total: len(cachedBundles),
		},
	}, nil
}

func (c *client) RenewSVID(ctx context.Context, csr []byte) (*X509SVID, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	agentClient, connection, err := c.newAgentClient()
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := agentClient.RenewAgent(ctx, &agentv1.RenewAgentRequest{
		Params: &agentv1.AgentX509SVIDParams{
			Csr: csr,
		},
	})
	if err != nil {
		c.release(connection)
		c.withErrorFields(err).Error("Failed to renew agent")
		return nil, fmt.Errorf("failed to renew agent: %w", err)
	}

	var certChain []byte
	for _, cert := range resp.Svid.CertChain {
		certChain = append(certChain, cert...)
	}
	return &X509SVID{
		CertChain: certChain,
		ExpiresAt: resp.Svid.ExpiresAt,
	}, nil
}

func (c *client) PostStatus(ctx context.Context, agentVersion string) error {
	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	agentClient, connection, err := c.newAgentClient()
	if err != nil {
		return err
	}
	defer connection.Release()

	_, err = agentClient.PostStatus(ctx, &agentv1.PostStatusRequest{
		AgentVersion: agentVersion,
	})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Warn("Failed to post agent status")
		return fmt.Errorf("failed to post agent status: %w", err)
	}

	return nil
}

func (c *client) NewX509SVIDs(ctx context.Context, csrs map[string][]byte) (map[string]*X509SVID, error) {
	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	svids := make(map[string]*X509SVID)
	var params []*svidv1.NewX509SVIDParams
	for entryID, csr := range csrs {
		params = append(params, &svidv1.NewX509SVIDParams{
			EntryId: entryID,
			Csr:     csr,
		})
	}

	protoSVIDs, err := c.fetchSVIDs(ctx, params)
	if err != nil {
		return nil, err
	}

	for i, s := range protoSVIDs {
		entryID := params[i].EntryId
		if s == nil {
			c.c.Log.WithField(telemetry.RegistrationID, entryID).Debug("Entry not found")
			continue
		}
		var certChain []byte
		for _, cert := range s.CertChain {
			certChain = append(certChain, cert...)
		}

		svids[entryID] = &X509SVID{
			CertChain: certChain,
			ExpiresAt: s.ExpiresAt,
		}
	}

	return svids, nil
}

func (c *client) NewJWTSVID(ctx context.Context, entryID string, audience []string, hasCacheHit bool) (*JWTSVID, spiffeid.ID, error) {
	timeout := rpcTimeout
	if hasCacheHit {
		timeout = RPCTimeoutWithCacheHit
	}

	// The timeout bounds the entire retry loop: every attempt shares this single
	// deadline, and retries continue until it (or the caller's context) expires.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	fetchBackoff := backoff.NewBackoff(c.clk, jwtSVIDRetryInterval)
	for {
		svid, err := c.fetchJWTSVID(ctx, entryID, audience)
		if err != nil {
			if !isRetriable(err) {
				c.withErrorFields(err).Error("Failed to fetch JWT SVID")
				return nil, spiffeid.ID{}, fmt.Errorf("failed to fetch JWT SVID: %w", err)
			}

			c.withErrorFields(err).Debug("Failed to fetch JWT SVID; retrying")
			select {
			case <-ctx.Done():
				c.withErrorFields(err).Error("Failed to fetch JWT SVID")
				return nil, spiffeid.ID{}, fmt.Errorf("failed to fetch JWT SVID: %w", err)
			case <-c.clk.After(fetchBackoff.NextBackOff()):
				continue
			}
		}

		// A malformed response indicates a server/agent mismatch rather than a
		// transient failure, so it is not retried.
		switch {
		case svid == nil:
			return nil, spiffeid.ID{}, errors.New("JWTSVID response missing SVID")
		case svid.IssuedAt == 0:
			return nil, spiffeid.ID{}, errors.New("JWTSVID missing issued at")
		case svid.ExpiresAt == 0:
			return nil, spiffeid.ID{}, errors.New("JWTSVID missing expires at")
		case svid.IssuedAt > svid.ExpiresAt:
			return nil, spiffeid.ID{}, errors.New("JWTSVID issued after it has expired")
		}

		spiffeId, err := idutil.IDFromProto(svid.Id)
		if err != nil {
			return nil, spiffeid.ID{}, fmt.Errorf("could not parse JWT-SVID SPIFFE ID: %w", err)
		}

		return &JWTSVID{
			Token:     svid.Token,
			IssuedAt:  time.Unix(svid.IssuedAt, 0).UTC(),
			ExpiresAt: time.Unix(svid.ExpiresAt, 0).UTC(),
		}, spiffeId, nil
	}
}

// fetchJWTSVID performs a single NewJWTSVID RPC. Any returned error is the raw
// error from the connection or gRPC call so the caller can classify it for
// retries.
func (c *client) fetchJWTSVID(ctx context.Context, entryID string, audience []string) (*types.JWTSVID, error) {
	// The rotation lock is taken per attempt (rather than around the whole retry
	// loop) so that a retrying request does not block SVID rotation for the
	// entire timeout window; each attempt uses whatever connection is current.
	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	svidClient, connection, err := c.newSVIDClient()
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.NewJWTSVID(ctx, &svidv1.NewJWTSVIDRequest{
		Audience: audience,
		EntryId:  entryID,
	})
	if err != nil {
		c.release(connection)
		return nil, err
	}

	return resp.Svid, nil
}

func (c *client) NewWITSVIDs(ctx context.Context, publicKeys map[string]crypto.PublicKey, signatureAlgorithm string) (map[string]*WITSVID, error) {
	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	svids := make(map[string]*WITSVID)
	var params []*svidv1.NewWITSVIDParams
	for entryID, publicKey := range publicKeys {
		pkixPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal PKIX public key for entry %q: %w", entryID, err)
		}

		params = append(params, &svidv1.NewWITSVIDParams{
			EntryId:          entryID,
			PublicKey:        pkixPublicKey,
			SigningAlgorithm: signatureAlgorithm,
		})
	}

	protoSVIDs, err := c.fetchWITSVIDs(ctx, params)
	if err != nil {
		return nil, err
	}

	for i, s := range protoSVIDs {
		entryID := params[i].EntryId
		if s == nil {
			continue
		}

		svids[entryID] = &WITSVID{
			Token:     s.Token,
			IssuedAt:  time.Unix(s.IssuedAt, 0).UTC(),
			ExpiresAt: time.Unix(s.ExpiresAt, 0).UTC(),
		}
	}

	return svids, nil
}

// Release the underlying connection.
func (c *client) Release() {
	c.release(nil)
}

func (c *client) release(conn *nodeConn) {
	c.m.Lock()
	defer c.m.Unlock()
	if c.connections != nil && (conn == nil || conn == c.connections) {
		c.connections.Release()
		c.connections = nil
	}
}

func (c *client) newServerGRPCClient() (*grpc.ClientConn, error) {
	return NewServerGRPCClient(ServerClientConfig{
		Address:     c.c.Addr,
		TrustDomain: c.c.TrustDomain,
		GetBundle: func() []*x509.Certificate {
			_, _, bundle := c.c.KeysAndBundle()
			return bundle
		},
		GetAgentCertificate: func() *tls.Certificate {
			chain, key, _ := c.c.KeysAndBundle()
			agentCert := &tls.Certificate{
				PrivateKey: key,
			}
			for _, cert := range chain {
				agentCert.Certificate = append(agentCert.Certificate, cert.Raw)
			}
			return agentCert
		},
		TLSPolicy:           c.c.TLSPolicy,
		LoadBalancingConfig: c.c.LoadBalancingConfig,
		dialOpts:            c.dialOpts,
	})
}

func (c *client) syncEntries(ctx context.Context, cachedEntries map[string]*common.RegistrationEntry) (SyncEntriesStats, error) {
	entryClient, connection, err := c.newEntryClient()
	if err != nil {
		return SyncEntriesStats{}, err
	}
	defer connection.Release()

	stats, err := c.streamAndSyncEntries(ctx, entryClient, cachedEntries)
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to fetch authorized entries")
		return SyncEntriesStats{}, fmt.Errorf("failed to fetch authorized entries: %w", err)
	}

	return stats, nil
}

func entryIsStale(entry *common.RegistrationEntry, revisionNumber, revisionCreatedAt int64) bool {
	if entry.RevisionNumber != revisionNumber {
		return true
	}

	// TODO: remove in SPIRE 1.14
	if revisionCreatedAt == 0 {
		return false
	}

	// Verify that the CreatedAt of the entries match. If they are different, they are
	// completely different entries even if the revision number is the same.
	// This can happen for example if an entry is deleted and recreated with the
	// same entry id.
	if entry.CreatedAt != revisionCreatedAt {
		return true
	}

	return false
}

func (c *client) streamAndSyncEntries(ctx context.Context, entryClient entryv1.EntryClient, cachedEntries map[string]*common.RegistrationEntry) (stats SyncEntriesStats, err error) {
	// Build a set of all the entries to be removed. This set is initialized
	// with all entries currently known. As entries are synced down from the
	// server, they are removed from this set. If the sync is successful,
	// any entry that was not seen during sync, i.e., still remains a member
	// of this set, is removed from the cached entries.
	toRemove := make(map[string]struct{})
	for _, entry := range cachedEntries {
		toRemove[entry.EntryId] = struct{}{}
	}
	defer func() {
		if err == nil {
			stats.Dropped = len(toRemove)
			for id := range toRemove {
				delete(cachedEntries, id)
			}
			stats.Total = len(cachedEntries)
		}
	}()

	// needFull tracks the entry IDs of entries that are either not cached, or
	// that have been determined to be stale (based on revision number
	// comparison)
	var needFull []string

	// processEntryRevisions determines what needs to be synced down based
	// on entry revisions.
	processEntryRevisions := func(entryRevisions []*entryv1.EntryRevision) {
		for _, entryRevision := range entryRevisions {
			if entryRevision.Id == "" || entryRevision.RevisionNumber < 0 {
				c.c.Log.WithFields(logrus.Fields{
					telemetry.RegistrationID: entryRevision.Id,
					telemetry.RevisionNumber: entryRevision.RevisionNumber,
				}).Warn("Received malformed entry revision from SPIRE server; are the server and agent versions compatible?")
				continue
			}

			// The entry is still authorized for this agent. Don't remove it.
			delete(toRemove, entryRevision.Id)

			// If entry is either not cached or is stale, record the ID so
			// the full entry can be requested after syncing down all
			// entry revisions.
			if cachedEntry, ok := cachedEntries[entryRevision.Id]; !ok || entryIsStale(cachedEntry, entryRevision.GetRevisionNumber(), entryRevision.GetCreatedAt()) {
				needFull = append(needFull, entryRevision.Id)
			}
		}
	}

	// processServerEntries updates the cached entries
	processServerEntries := func(serverEntries []*types.Entry) {
		for _, serverEntry := range serverEntries {
			entry, err := slicedEntryFromProto(serverEntry)
			if err != nil {
				c.c.Log.WithFields(logrus.Fields{
					telemetry.RegistrationID: serverEntry.Id,
					telemetry.RevisionNumber: serverEntry.RevisionNumber,
					telemetry.SPIFFEID:       serverEntry.SpiffeId,
					telemetry.Selectors:      serverEntry.Selectors,
					telemetry.Error:          err.Error(),
				}).Warn("Received malformed entry from SPIRE server; are the server and agent versions compatible?")
				continue
			}

			// The entry is still authorized for this agent. Don't remove it.
			delete(toRemove, entry.EntryId)

			cachedEntry, ok := cachedEntries[entry.EntryId]
			switch {
			case !ok:
				stats.Missing++
			case entryIsStale(cachedEntry, entry.GetRevisionNumber(), entry.GetCreatedAt()):
				stats.Stale++
			}

			// Update the cached entry
			cachedEntries[entry.EntryId] = entry
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := entryClient.SyncAuthorizedEntries(ctx)
	if err != nil {
		return SyncEntriesStats{}, err
	}

	if err := stream.Send(&entryv1.SyncAuthorizedEntriesRequest{
		OutputMask: entryOutputMask,
	}); err != nil {
		return SyncEntriesStats{}, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return SyncEntriesStats{}, err
	}

	// If the first response does not contain entry revisions then it contains
	// the complete list of authorized entries.
	if len(resp.EntryRevisions) == 0 {
		processServerEntries(resp.Entries)
		return stats, nil
	}

	// Assume that the page size is the size of the revisions in the first
	// response from the server.
	pageSize := len(resp.EntryRevisions)

	// Receive the rest of the entry revisions
	processEntryRevisions(resp.EntryRevisions)
	for resp.More {
		resp, err = stream.Recv()
		if err != nil {
			return SyncEntriesStats{}, fmt.Errorf("failed to receive entry revision page from server: %w", err)
		}
		if len(resp.Entries) > 0 {
			return SyncEntriesStats{}, errors.New("unexpected entry in response receiving entry revisions")
		}
		processEntryRevisions(resp.EntryRevisions)
	}

	// Presort the IDs. The server sorts the requested IDs as an optimization
	// for memory and CPU efficient lookups. Even though the server will sort
	// them, pre-sorting should reduce server CPU load (Go1.19+ implements
	// sorting via the PDQ algorithm, which performs well on pre-sorted data).
	sort.Strings(needFull)

	// Request the full entries for missing or stale entries one page at a
	// time using the assumed page size.
	for len(needFull) > 0 {
		// Request up to a page full of full entries
		n := min(len(needFull), pageSize)
		if err := stream.Send(&entryv1.SyncAuthorizedEntriesRequest{Ids: needFull[:n]}); err != nil {
			return SyncEntriesStats{}, err
		}
		needFull = needFull[n:]

		// Receive the full entries just requested. Even though the entries
		// SHOULD come back in a single response (since we matched the page
		// size of the server), handle the case where the server decides to
		// break them up into multiple pages.
		for {
			resp, err := stream.Recv()
			if err != nil {
				return SyncEntriesStats{}, fmt.Errorf("failed to receive entry revision page from server: %w", err)
			}
			if len(resp.EntryRevisions) != 0 {
				return SyncEntriesStats{}, errors.New("unexpected entry revisions in response while requesting entries")
			}
			processServerEntries(resp.Entries)
			if !resp.More {
				break
			}
		}
	}
	return stats, nil
}

// federatedBundlesToFetch returns the federated trust domains due to be
// fetched on this sync. A trust domain that has not been fetched yet is always
// included so that new federations take effect immediately.
func (c *client) federatedBundlesToFetch(federatedTrustDomains stringSet) []string {
	c.federatedSyncMu.Lock()
	defer c.federatedSyncMu.Unlock()

	now := c.clk.Now()
	due := make(stringSet)
	for td := range federatedTrustDomains {
		if next, ok := c.nextFederatedBundleSync[td]; !ok || !now.Before(next) {
			due.Add(td)
		}
	}
	return due.Sorted()
}

// scheduleFederatedBundleRefresh records when each fetched trust domain is next
// due, and forgets trust domains the agent no longer federates with. It is only
// called after a successful fetch, so a failed sync leaves the schedule alone
// and the trust domains stay due.
func (c *client) scheduleFederatedBundleRefresh(fetched []string, federatedTrustDomains stringSet, cachedBundles map[string]*common.Bundle) {
	c.federatedSyncMu.Lock()
	defer c.federatedSyncMu.Unlock()

	if c.nextFederatedBundleSync == nil {
		c.nextFederatedBundleSync = make(map[string]time.Time, len(fetched))
	}

	now := c.clk.Now()
	for _, td := range fetched {
		// A trust domain the server has no bundle for is absent from
		// cachedBundles and falls back to the default interval, rather than
		// being retried on every sync.
		c.nextFederatedBundleSync[td] = now.Add(c.federatedBundleRefreshInterval(td, cachedBundles[td]))
	}

	stale := func(td string) bool {
		_, ok := federatedTrustDomains[td]
		return !ok
	}
	maps.DeleteFunc(c.nextFederatedBundleSync, func(td string, _ time.Time) bool { return stale(td) })
	maps.DeleteFunc(c.warnedRefreshHint, func(td string, _ time.Duration) bool { return stale(td) })
}

// federatedBundleRefreshInterval returns how long to wait before refreshing the
// given bundle, from its refresh hint, bounded below by the configured minimum.
// It mirrors how the server schedules its own federated bundle updates: a
// published hint is polled a few times within it, a bundle without one is polled
// at a fixed interval, and having no bundle at all is retried sooner since that
// is what a newly federated trust domain looks like.
//
// Must be called with federatedSyncMu held.
func (c *client) federatedBundleRefreshInterval(trustDomain string, b *common.Bundle) time.Duration {
	var hint, interval time.Duration
	switch {
	case b == nil:
		hint, interval = 0, bundleutil.MinimumRefreshHint
	case b.RefreshHint > 0:
		hint = max(time.Duration(b.RefreshHint)*time.Second, bundleutil.MinimumRefreshHint)
		interval = hint / federatedBundleRefreshAttempts
	default:
		// No hint published. The server polls these at a fixed interval, but
		// still derives a hint from the bundle contents, which is what its
		// consumers are told to check back within.
		if spiffeBundle, err := bundleutil.SPIFFEBundleFromProto(b); err == nil {
			hint = bundleutil.CalculateRefreshHint(spiffeBundle)
		}
		interval = defaultFederatedBundleRefreshInterval
	}

	interval = max(interval, c.c.MinFederatedBundleSyncInterval)
	c.warnIfRefreshHintExceeded(trustDomain, hint, interval)
	return interval
}

// warnIfRefreshHintExceeded warns when the configured minimum pushes the
// refresh interval past the refresh hint the trust domain published, meaning
// the agent refreshes its bundle less often than that trust domain asks for.
//
// Must be called with federatedSyncMu held.
func (c *client) warnIfRefreshHintExceeded(trustDomain string, hint, interval time.Duration) {
	// A zero hint means there is no bundle to derive one from, so there is
	// nothing the trust domain has asked for to fall short of.
	if hint <= 0 || interval <= hint {
		delete(c.warnedRefreshHint, trustDomain)
		return
	}
	if warned, ok := c.warnedRefreshHint[trustDomain]; ok && warned == hint {
		return
	}
	if c.warnedRefreshHint == nil {
		c.warnedRefreshHint = make(map[string]time.Duration)
	}
	c.warnedRefreshHint[trustDomain] = hint

	c.c.Log.WithFields(logrus.Fields{
		telemetry.FederatedBundle:                trustDomain,
		telemetry.RefreshHint:                    hint,
		telemetry.MinFederatedBundleSyncInterval: interval,
	}).Warn("Federated bundle is refreshed less often than its trust domain requests; min_federated_bundle_sync_interval exceeds the bundle refresh hint")
}

func (c *client) fetchBundles(ctx context.Context, federatedBundles []string) ([]*types.Bundle, error) {
	bundleClient, connection, err := c.newBundleClient()
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	bundles := make([]*types.Bundle, 0, len(federatedBundles)+1)

	// Get bundle
	bundle, err := bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		c.release(connection)
		c.withErrorFields(err).Error("Failed to fetch bundle")
		return nil, fmt.Errorf("failed to fetch bundle: %w", err)
	}
	bundles = append(bundles, bundle)

	return c.fetchFederatedBundlesConcurrently(ctx, bundleClient, federatedBundles, bundles)
}

// fetchFederatedBundlesConcurrently fetches federated bundles concurrently.
// This is done to improve sync times when there are many federations. This should ensure that the
// sync does not exceed rpcTimeout.
func (c *client) fetchFederatedBundlesConcurrently(ctx context.Context, bundleClient bundlev1.BundleClient, trustDomains []string, bundles []*types.Bundle) ([]*types.Bundle, error) {
	jobCh := make(chan string)
	resultCh := make(chan fetchBundleResult, len(trustDomains))
	// Start a set of worker goroutines.
	wg := sync.WaitGroup{}
	for range min(maxBundleWorkers, len(trustDomains)) {
		wg.Go(func() {
			for trustDomain := range jobCh {
				bundle, err := c.fetchFederatedBundle(ctx, bundleClient, trustDomain)
				resultCh <- fetchBundleResult{bundle: bundle, err: err}
			}
		})
	}
	// Feed the workers.
	for _, b := range trustDomains {
		jobCh <- b
	}
	close(jobCh)
	// Wait for completion of all jobs.
	wg.Wait()
	close(resultCh)
	// Process the results.
	for r := range resultCh {
		if r.err != nil {
			return nil, r.err
		}
		if r.bundle != nil {
			bundles = append(bundles, r.bundle)
		}
	}
	return bundles, nil
}

// fetchFederatedBundle fetches a single federated bundle from SPIRE server.
func (c *client) fetchFederatedBundle(ctx context.Context, bundleClient bundlev1.BundleClient, trustDomain string) (*types.Bundle, error) {
	federatedTD, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, err
	}
	bundle, err := bundleClient.GetFederatedBundle(ctx, &bundlev1.GetFederatedBundleRequest{
		TrustDomain: federatedTD.Name(),
	})
	log := c.withErrorFields(err)
	switch status.Code(err) {
	case codes.OK:
		return bundle, nil
	case codes.NotFound:
		log.WithField(telemetry.FederatedBundle, trustDomain).Warn("Federated bundle not found")
		return nil, nil
	default:
		log.WithField(telemetry.FederatedBundle, trustDomain).Error("Failed to fetch federated bundle")
		return nil, fmt.Errorf("failed to fetch federated bundle: %w", err)
	}
}

func (c *client) fetchSVIDs(ctx context.Context, params []*svidv1.NewX509SVIDParams) ([]*types.X509SVID, error) {
	svidClient, connection, err := c.newSVIDClient()
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.BatchNewX509SVID(ctx, &svidv1.BatchNewX509SVIDRequest{
		Params: params,
	})
	if err != nil {
		c.release(connection)
		c.withErrorFields(err).Error("Failed to batch new X509 SVID(s)")
		return nil, fmt.Errorf("failed to batch new X509 SVID(s): %w", err)
	}

	okStatus := int32(codes.OK)
	var svids []*types.X509SVID
	for i, r := range resp.Results {
		if r.Status.Code != okStatus {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: params[i].EntryId,
				telemetry.Status:         r.Status.Code,
				telemetry.Error:          r.Status.Message,
			}).Warn("Failed to mint X509 SVID")
		}

		svids = append(svids, r.Svid)
	}

	return svids, nil
}

func (c *client) fetchWITSVIDs(ctx context.Context, params []*svidv1.NewWITSVIDParams) ([]*types.WITSVID, error) {
	svidClient, connection, err := c.newSVIDClient()
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.BatchNewWITSVID(ctx, &svidv1.BatchNewWITSVIDRequest{
		Params: params,
	})
	if err != nil {
		c.release(connection)
		c.withErrorFields(err).Error("Failed to batch new WIT-SVID(s)")
		return nil, fmt.Errorf("failed to batch new WIT-SVID(s): %w", err)
	}

	okStatus := int32(codes.OK)
	var svids []*types.WITSVID
	for i, r := range resp.Results {
		if r.Status.Code != okStatus {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: params[i].EntryId,
				telemetry.Status:         r.Status.Code,
				telemetry.Error:          r.Status.Message,
			}).Warn("Failed to mint WIT-SVID")
			svids = append(svids, nil)
			continue
		}

		svid := r.Svid
		var svidErr error
		switch {
		case svid == nil:
			svidErr = errors.New("WITSVID response missing SVID")
		case svid.IssuedAt == 0:
			svidErr = errors.New("WITSVID missing issued at")
		case svid.ExpiresAt == 0:
			svidErr = errors.New("WITSVID missing expires at")
		case svid.IssuedAt > svid.ExpiresAt:
			svidErr = errors.New("WITSVID issued after it has expired")
		}
		if svidErr != nil {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: params[i].EntryId,
				logrus.ErrorKey:          svidErr.Error(),
			}).Error("Invalid WIT-SVID")
			svids = append(svids, nil)
			continue
		}

		svids = append(svids, svid)
	}

	return svids, nil
}

func (c *client) newEntryClient() (entryv1.EntryClient, *nodeConn, error) {
	conn, err := c.getOrOpenConn()
	if err != nil {
		return nil, nil, err
	}
	return entryv1.NewEntryClient(conn.Conn()), conn, nil
}

func (c *client) newBundleClient() (bundlev1.BundleClient, *nodeConn, error) {
	conn, err := c.getOrOpenConn()
	if err != nil {
		return nil, nil, err
	}
	return bundlev1.NewBundleClient(conn.Conn()), conn, nil
}

func (c *client) newSVIDClient() (svidv1.SVIDClient, *nodeConn, error) {
	conn, err := c.getOrOpenConn()
	if err != nil {
		return nil, nil, err
	}
	return svidv1.NewSVIDClient(conn.Conn()), conn, nil
}

func (c *client) newAgentClient() (agentv1.AgentClient, *nodeConn, error) {
	conn, err := c.getOrOpenConn()
	if err != nil {
		return nil, nil, err
	}
	return agentv1.NewAgentClient(conn.Conn()), conn, nil
}

func (c *client) getOrOpenConn() (*nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.connections == nil {
		conn, err := c.newServerGRPCClient()
		if err != nil {
			return nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.connections, nil
}

type stringSet map[string]struct{}

func (ss stringSet) Add(s string) {
	ss[s] = struct{}{}
}

func (ss stringSet) Sorted() []string {
	sorted := make([]string, 0, len(ss))
	for s := range ss {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	return sorted
}

// withErrorFields add fields of gRPC call status in logger
func (c *client) withErrorFields(err error) logrus.FieldLogger {
	if err == nil {
		return c.c.Log
	}

	logger := c.c.Log.WithError(err)
	if s, ok := status.FromError(err); ok {
		logger = logger.WithFields(logrus.Fields{
			telemetry.StatusCode:    s.Code(),
			telemetry.StatusMessage: s.Message(),
		})
	}

	return logger
}

func isRetriable(err error) bool {
	switch status.Code(err) {
	case codes.Unknown, codes.Canceled, codes.DeadlineExceeded, codes.InvalidArgument, codes.Unimplemented:
		return false
	default:
		return true
	}
}
