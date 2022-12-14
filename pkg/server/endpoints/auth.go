package endpoints

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/spire/common"
)

var (
	misconfigLogMtx   sync.Mutex
	misconfigLogTimes = make(map[string]time.Time)
	misconfigClk      = clock.New()
)

const misconfigLogEvery = time.Minute

// shouldLogFederationMisconfiguration returns true if the last time a misconfiguration
// was logged was more than misconfigLogEvery ago.
func shouldLogFederationMisconfiguration(tdID string) bool {
	misconfigLogMtx.Lock()
	defer misconfigLogMtx.Unlock()

	now := misconfigClk.Now()
	last, ok := misconfigLogTimes[tdID]
	if !ok || now.Sub(last) >= misconfigLogEvery {
		misconfigLogTimes[tdID] = now
		return true
	}
	return false
}

// bundleGetter fetches the bundle for the given trust domain and parse it as x509 certificates.
func (e *Endpoints) bundleGetter(ctx context.Context, td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	commonServerBundle, err := e.DataStore.FetchBundle(dscache.WithCache(ctx), td.IDString())
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %w", err)
	}
	if commonServerBundle == nil {
		if td != e.TrustDomain && shouldLogFederationMisconfiguration(td.IDString()) {
			e.Log.
				WithField(telemetry.TrustDomain, td.String()).
				Warn(
					"No bundle found for foreign admin trust domain; admins from this trust domain will not be able to connect. " +
						"Make sure this trust domain is correctly federated.",
				)
		}
		return nil, fmt.Errorf("no bundle found for trust domain %q", e.TrustDomain)
	}

	serverBundle, err := parseBundle(e.TrustDomain, commonServerBundle)
	if err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	return serverBundle.X509Authorities(), nil
}

// serverSpiffeVerificationFunc returns a function that is used for peer certificate verification on TLS connections.
// The returned function will verify that the peer certificate is valid, and apply a custom authorization with machMemberOrOneOf.
// If the peer certificate is not provided, the function will not make any verification and return nil.
func (e *Endpoints) serverSpiffeVerificationFunc(bundleSource x509bundle.Source) func(_ [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if rawCerts == nil {
			return nil
		}

		return tlsconfig.VerifyPeerCertificate(
			bundleSource,
			tlsconfig.AdaptMatcher(machMemberOrOneOf(e.TrustDomain, e.AdminIDs...)),
		)(rawCerts, nil)
	}
}

// machMemberOrOneOf is a custom spiffeid.Matcher which will validate that the peerSpiffeID belongs to the server
// trust domain or if it is included in the admin_ids configuration permissive list.
func machMemberOrOneOf(trustDomain spiffeid.TrustDomain, adminIds ...spiffeid.ID) spiffeid.Matcher {
	permissiveIDsSet := make(map[spiffeid.ID]struct{})
	for _, adminID := range adminIds {
		permissiveIDsSet[adminID] = struct{}{}
	}

	return func(peerID spiffeid.ID) error {
		if !peerID.MemberOf(trustDomain) {
			if _, ok := permissiveIDsSet[peerID]; !ok {
				return fmt.Errorf("unexpected trust domain in ID %q", peerID)
			}
		}

		return nil
	}
}

// parseBundle parses a *x509bundle.Bundle from a *common.bundle.
func parseBundle(td spiffeid.TrustDomain, commonBundle *common.Bundle) (*x509bundle.Bundle, error) {
	var caCerts []*x509.Certificate
	for _, rootCA := range commonBundle.RootCas {
		rootCACerts, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			return nil, fmt.Errorf("parse bundle: %w", err)
		}
		caCerts = append(caCerts, rootCACerts...)
	}

	return x509bundle.FromX509Authorities(td, caCerts), nil
}

type x509SVIDSource struct {
	getter func() svid.State
}

func newX509SVIDSource(getter func() svid.State) x509svid.Source {
	return &x509SVIDSource{getter: getter}
}

func (xs *x509SVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	svidState := xs.getter()

	if len(svidState.SVID) == 0 {
		return nil, errors.New("no certificates found")
	}

	id, err := x509svid.IDFromCert(svidState.SVID[0])
	if err != nil {
		return nil, err
	}
	return &x509svid.SVID{
		ID:           id,
		Certificates: svidState.SVID,
		PrivateKey:   svidState.Key,
	}, nil
}

type bundleSource struct {
	getter func(spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

func newBundleSource(getter func(spiffeid.TrustDomain) ([]*x509.Certificate, error)) x509bundle.Source {
	return &bundleSource{getter: getter}
}

func (bs *bundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	authorities, err := bs.getter(trustDomain)
	if err != nil {
		return nil, err
	}
	bundle := x509bundle.FromX509Authorities(trustDomain, authorities)
	return bundle.GetX509BundleForTrustDomain(trustDomain)
}
