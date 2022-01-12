package attestor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
)

type AttestationResult struct {
	SVID   []*x509.Certificate
	Key    keymanager.Key
	Bundle *bundleutil.Bundle
}

type Attestor interface {
	Attest(ctx context.Context) (*AttestationResult, error)
}

type Config struct {
	Catalog           catalog.Catalog
	Metrics           telemetry.Metrics
	JoinToken         string
	TrustDomain       spiffeid.TrustDomain
	TrustBundle       []*x509.Certificate
	InsecureBootstrap bool
	BundleCachePath   string
	SVIDCachePath     string
	Log               logrus.FieldLogger
	ServerAddress     string
}

type attestor struct {
	c *Config
}

func New(config *Config) Attestor {
	return &attestor{c: config}
}

func (a *attestor) Attest(ctx context.Context) (res *AttestationResult, err error) {
	log := a.c.Log

	bundle, err := a.loadBundle()
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		log.Info("Bundle is not found")
	} else {
		log = log.WithField(telemetry.TrustDomainID, bundle.TrustDomainID())
		log.Info("Bundle loaded")
	}

	svid, key, err := a.loadSVID(ctx)
	if err != nil {
		return nil, err
	}

	switch {
	case svid == nil:
		log.Info("SVID is not found. Starting node attestation")
		svid, bundle, err = a.newSVID(ctx, key, bundle)
		if err != nil {
			return nil, err
		}
		log.WithField(telemetry.SPIFFEID, svid[0].URIs[0].String()).Info("Node attestation was successful")
	case bundle == nil:
		// This is a bizarre case where we have an SVID but were unable to
		// load a bundle from the cache which suggests some tampering with the
		// cache on disk.
		return nil, errs.New("SVID loaded but no bundle in cache")
	default:
		log.WithField(telemetry.SPIFFEID, svid[0].URIs[0].String()).Info("SVID loaded")
	}

	return &AttestationResult{Bundle: bundle, SVID: svid, Key: key}, nil
}

// Load the current SVID and key. The returned SVID is nil to indicate a new SVID should be created.
func (a *attestor) loadSVID(ctx context.Context) ([]*x509.Certificate, keymanager.Key, error) {
	svidKM := keymanager.ForSVID(a.c.Catalog.GetKeyManager())
	allKeys, err := svidKM.GetKeys(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load private key: %w", err)
	}

	svid := a.readSVIDFromDisk()
	svidKey, svidKeyExists := findKeyForSVID(allKeys, svid)
	svidExists := len(svid) > 0
	svidIsExpired := IsSVIDExpired(svid, time.Now)

	switch {
	case svidExists && svidKeyExists && !svidIsExpired:
		return svid, svidKey, nil
	case svidExists && svidKeyExists && svidIsExpired:
		a.c.Log.WithField("expiry", svid[0].NotAfter).Warn("SVID key recovered, but SVID is expired. Generating new keypair")
	case svidExists && !svidKeyExists && len(allKeys) == 0:
		a.c.Log.Warn("SVID recovered, but no keys found. Generating new keypair")
	case svidExists && !svidKeyExists && len(allKeys) > 0:
		a.c.Log.Warn("SVID recovered, but no SVID key found. Generating new keypair")
	case !svidExists && len(allKeys) > 0:
		a.c.Log.Warn("Keys recovered, but no SVID found. Generating new keypair")
	default:
		// Neither private key nor SVID were found.
	}

	svidKey, err = svidKM.GenerateKey(ctx, svidKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate private key: %w", err)
	}
	return nil, svidKey, nil
}

// IsSVIDExpired returns true if the X.509 SVID provided is expired
func IsSVIDExpired(svid []*x509.Certificate, timeNow func() time.Time) bool {
	if len(svid) == 0 {
		return false
	}
	clockSkew := time.Second
	certExpiresAt := svid[0].NotAfter
	return timeNow().Add(clockSkew).Sub(certExpiresAt) >= 0
}

func (a *attestor) loadBundle() (*bundleutil.Bundle, error) {
	bundle, err := manager.ReadBundle(a.c.BundleCachePath)
	if errors.Is(err, manager.ErrNotCached) {
		if a.c.InsecureBootstrap {
			if len(a.c.TrustBundle) > 0 {
				a.c.Log.Warn("Trust bundle will be ignored; performing insecure bootstrap")
			}
			return nil, nil
		}
		bundle = a.c.TrustBundle
	} else if err != nil {
		return nil, fmt.Errorf("load bundle: %w", err)
	}

	if len(bundle) < 1 {
		return nil, errors.New("load bundle: no certs in bundle")
	}

	return bundleutil.BundleFromRootCAs(a.c.TrustDomain, bundle), nil
}

// Read agent SVID from data dir. If an error is encountered, it will be logged and `nil`
// will be returned.
func (a *attestor) readSVIDFromDisk() []*x509.Certificate {
	log := a.c.Log.WithField(telemetry.Path, a.c.SVIDCachePath)

	svid, err := manager.ReadSVID(a.c.SVIDCachePath)
	if errors.Is(err, manager.ErrNotCached) {
		log.Debug("No pre-existing agent SVID found. Will perform node attestation")
		return nil
	} else if err != nil {
		log.WithError(err).Warn("Could not get agent SVID from path")
	}
	return svid
}

// newSVID obtains an agent svid for the given private key by performing node attesatation. The bundle is
// necessary in order to validate the SPIRE server we are attesting to. Returns the SVID and an updated bundle.
func (a *attestor) newSVID(ctx context.Context, key keymanager.Key, bundle *bundleutil.Bundle) (_ []*x509.Certificate, _ *bundleutil.Bundle, err error) {
	counter := telemetry_agent.StartNodeAttestorNewSVIDCall(a.c.Metrics)
	defer counter.Done(&err)

	attestor := nodeattestor.JoinToken(a.c.Log, a.c.JoinToken)
	if a.c.JoinToken == "" {
		attestor = a.c.Catalog.GetNodeAttestor()
	}
	telemetry_common.AddAttestorType(counter, attestor.Name())

	conn, err := a.serverConn(ctx, bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("create attestation client: %w", err)
	}
	defer conn.Close()

	csr, err := util.MakeCSRWithoutURISAN(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CSR for attestation: %w", err)
	}

	newSVID, err := a.getSVID(ctx, conn, csr, attestor)
	if err != nil {
		return nil, nil, err
	}

	newBundle, err := a.getBundle(ctx, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get updated bundle: %w", err)
	}

	return newSVID, newBundle, nil
}

func (a *attestor) serverConn(ctx context.Context, bundle *bundleutil.Bundle) (*grpc.ClientConn, error) {
	if bundle != nil {
		return client.DialServer(ctx, client.DialServerConfig{
			Address:     a.c.ServerAddress,
			TrustDomain: a.c.TrustDomain,
			GetBundle:   bundle.RootCAs,
		})
	}

	if !a.c.InsecureBootstrap {
		// We shouldn't get here since loadBundle() should fail if the bundle
		// is empty, but just in case...
		return nil, errs.New("no bundle and not doing insecure bootstrap")
	}

	// Insecure bootstrapping. Do not verify the server chain but rather do a
	// simple, soft verification that the server URI matches the expected
	// SPIFFE ID. This is not a security feature but rather a check that we've
	// reached what appears to be the right trust domain server.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint: gosec // this is required in order to do non-hostname based verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			a.c.Log.Warn("Insecure bootstrap enabled; skipping server certificate verification")
			if len(rawCerts) == 0 {
				// This is not really possible without a catastrophic bug
				// creeping into the TLS stack.
				return errs.New("server chain is unexpectedly empty")
			}

			expectedServerID, err := idutil.ServerID(a.c.TrustDomain)
			if err != nil {
				return err
			}

			serverCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if len(serverCert.URIs) != 1 || serverCert.URIs[0].String() != expectedServerID.String() {
				return errs.New("expected server SPIFFE ID %q; got %q", expectedServerID, serverCert.URIs)
			}
			return nil
		},
	}

	return grpc.DialContext(ctx, a.c.ServerAddress,
		// TODO: port to non-deprecated option
		grpc.WithBalancerName(roundrobin.Name), //nolint:staticcheck // not ready to port
		grpc.FailOnNonTempDialError(true),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithReturnConnectionError(),
	)
}

func findKeyForSVID(keys []keymanager.Key, svid []*x509.Certificate) (keymanager.Key, bool) {
	if len(svid) == 0 {
		return nil, false
	}
	for _, key := range keys {
		equal, err := cryptoutil.PublicKeyEqual(svid[0].PublicKey, key.Public())
		if err == nil && equal {
			return key, true
		}
	}
	return nil, false
}
