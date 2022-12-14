package endpoints

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/proto/spire/common"
)

var (
	lastMisconfigLogTime = new(atomic.Int64)
	misconfigClk         = clock.New()
)

const misconfigLogEvery = time.Minute

// shouldLogFederationMisconfiguration returns true if the last time a misconfiguration
// was logged was more than misconfigLogEvery ago.
func shouldLogFederationMisconfiguration() bool {
	now := misconfigClk.Now()

	lastLogTime := lastMisconfigLogTime.Load()
	if now.Sub(time.Unix(lastLogTime, 0)) >= misconfigLogEvery {
		lastMisconfigLogTime.Store(now.Unix())
		return true
	}

	return false
}

// bundleGetter fetches the bundle for the given trust domain and parse it as x509 certificates.
func (e *Endpoints) bundleGetter(ctx context.Context, td *spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	commonServerBundle, err := e.DataStore.FetchBundle(dscache.WithCache(ctx), td.IDString())
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %w", err)
	}
	if commonServerBundle == nil {
		if *td != e.TrustDomain && shouldLogFederationMisconfiguration() {
			e.Log.
				WithField(telemetry.TrustDomain, td.String()).
				Warn(
					"No bundle found for foreign admin trust domain, admins from this trust domain will not be able to connect. " +
						"Make sure this trust domain is correctly federated.",
				)
		}
		return nil, fmt.Errorf("no bundle found for trust domain %s", e.TrustDomain.String())
	}

	serverBundle, err := parseBundle(e.TrustDomain, commonServerBundle)
	if err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	return serverBundle.X509Authorities(), nil
}

// serverSpiffeVerificationFunc returns a function that is used for peer certificate verification on TLS connections.
// The returned function will verify that the peer certificate is valid, and apply a custom authorization with machMemberOrOneOff.
// If the peer certificate is not provided, the function will not make any verification and return nil.
func (e *Endpoints) serverSpiffeVerificationFunc(bundleSource x509bundle.Source) func(_ [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if rawCerts == nil {
			return nil
		}

		return tlsconfig.VerifyPeerCertificate(
			bundleSource,
			tlsconfig.AdaptMatcher(machMemberOrOneOff(e.TrustDomain, e.AdminIDs...)),
		)(rawCerts, nil)
	}
}

// machMemberOrOneOff is a custom spiffeid.Matcher, which will validate that the peerSpiffeID belongs to the server
// trust domain or if it is included in the admin_ids configuration permissive list.
func machMemberOrOneOff(trustDomain spiffeid.TrustDomain, adminIds ...spiffeid.ID) spiffeid.Matcher {
	return func(peerSpiffeID spiffeid.ID) error {
		permissiveIDsSet := make(map[spiffeid.ID]struct{})
		for _, adminID := range adminIds {
			permissiveIDsSet[adminID] = struct{}{}
		}

		if !peerSpiffeID.MemberOf(trustDomain) {
			if _, ok := permissiveIDsSet[peerSpiffeID]; !ok {
				return fmt.Errorf("unexpected ID %q", permissiveIDsSet)
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
	getter func() *tls.Certificate
}

func newX509SVIDSource(getter func() *tls.Certificate) x509svid.Source {
	return &x509SVIDSource{getter: getter}
}

func (xs *x509SVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	tlsCert := xs.getter()

	certificates, err := x509util.RawCertsToCertificates(tlsCert.Certificate)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	id, err := x509svid.IDFromCert(certificates[0])
	if err != nil {
		return nil, err
	}

	privateKey, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("agent certificate private key type %T is unexpectedly not a signer", tlsCert.PrivateKey)
	}

	return &x509svid.SVID{
		ID:           id,
		Certificates: certificates,
		PrivateKey:   privateKey,
	}, nil
}

type bundleSource struct {
	getter func(*spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

func newBundleSource(getter func(*spiffeid.TrustDomain) ([]*x509.Certificate, error)) x509bundle.Source {
	return &bundleSource{getter: getter}
}

func (bs *bundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	authorities, err := bs.getter(&trustDomain)
	if err != nil {
		return nil, err
	}
	bundle := x509bundle.FromX509Authorities(trustDomain, authorities)
	return bundle.GetX509BundleForTrustDomain(trustDomain)
}
