package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
)

const (
	joinTokenType = "join_token"
)

type AttestationResult struct {
	SVID   []*x509.Certificate
	Key    *ecdsa.PrivateKey
	Bundle *bundleutil.Bundle
}

type Attestor interface {
	Attest(ctx context.Context) (*AttestationResult, error)
}

type Config struct {
	Catalog               catalog.Catalog
	Metrics               telemetry.Metrics
	JoinToken             string
	TrustDomain           url.URL
	TrustBundle           []*x509.Certificate
	InsecureBootstrap     bool
	BundleCachePath       string
	SVIDCachePath         string
	Log                   logrus.FieldLogger
	ServerAddress         string
	CreateNewAgentClient  func(grpc.ClientConnInterface) agent.AgentClient
	CreateNewBundleClient func(grpc.ClientConnInterface) bundle.BundleClient
}

type attestor struct {
	c *Config

	// Used for testing purposes.

}

func New(config *Config) Attestor {
	// Defaults for CreateNewAgentClient and CreateNewBundleClient functions
	if config != nil {
		if config.CreateNewAgentClient == nil {
			config.CreateNewAgentClient = agent.NewAgentClient
		}
		if config.CreateNewBundleClient == nil {
			config.CreateNewBundleClient = bundle.NewBundleClient
		}
	}

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
func (a *attestor) loadSVID(ctx context.Context) ([]*x509.Certificate, *ecdsa.PrivateKey, error) {
	km := a.c.Catalog.GetKeyManager()
	fetchRes, err := km.FetchPrivateKey(ctx, &keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %v", err)
	}
	svid := a.readSVIDFromDisk()

	privateKeyExists := len(fetchRes.PrivateKey) > 0
	svidExists := svid != nil
	svidIsExpired := IsSVIDExpired(svid, time.Now)

	switch {
	case privateKeyExists && svidExists && !svidIsExpired:
		key, err := x509.ParseECPrivateKey(fetchRes.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("parse key from keymanager: %v", key)
		}
		return svid, key, nil
	case privateKeyExists && svidExists && svidIsExpired:
		a.c.Log.WithField("expiry", svid[0].NotAfter).Warn("Private key recovered, but SVID is expired. Generating new keypair")
	case privateKeyExists && !svidExists:
		a.c.Log.Warn("Private key recovered, but no SVID found. Generating new keypair")
	case !privateKeyExists && svidExists:
		a.c.Log.Warn("SVID recovered, but no private key found. Generating new keypair")
	default:
		// Neither private key nor SVID were found.
	}

	generateRes, err := km.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %s", err)
	}
	key, err := x509.ParseECPrivateKey(generateRes.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse key from keymanager: %v", key)
	}
	return nil, key, nil
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
	if err == manager.ErrNotCached {
		if a.c.InsecureBootstrap {
			if len(a.c.TrustBundle) > 0 {
				a.c.Log.Warn("Trust bundle will be ignored; performing insecure bootstrap")
			}
			return nil, nil
		}
		bundle = a.c.TrustBundle
	} else if err != nil {
		return nil, fmt.Errorf("load bundle: %v", err)
	}

	if bundle == nil {
		return nil, errors.New("load bundle: no bundle available")
	}

	if len(bundle) < 1 {
		return nil, errors.New("load bundle: no certs in bundle")
	}

	return bundleutil.BundleFromRootCAs(a.c.TrustDomain.String(), bundle), nil
}

func (a *attestor) fetchAttestationData(fetchStream nodeattestor.NodeAttestor_FetchAttestationDataClient, challenge []byte) (*nodeattestor.FetchAttestationDataResponse, error) {
	// the stream should only be nil if this node attestation is via a join
	// token.
	if fetchStream == nil {
		data := &common.AttestationData{
			Type: "join_token",
			Data: []byte(a.c.JoinToken),
		}

		return &nodeattestor.FetchAttestationDataResponse{
			AttestationData: data,
		}, nil
	}

	if challenge != nil {
		fetchReq := &nodeattestor.FetchAttestationDataRequest{
			Challenge: challenge,
		}
		if err := fetchStream.Send(fetchReq); err != nil {
			return nil, fmt.Errorf("requesting attestation data: %v", err)
		}
	}

	fetchResp, err := fetchStream.Recv()
	if err != nil {
		return nil, fmt.Errorf("receiving attestation data: %v", err)
	}

	return fetchResp, nil
}

// Read agent SVID from data dir. If an error is encountered, it will be logged and `nil`
// will be returned.
func (a *attestor) readSVIDFromDisk() []*x509.Certificate {
	log := a.c.Log.WithField(telemetry.Path, a.c.SVIDCachePath)

	svid, err := manager.ReadSVID(a.c.SVIDCachePath)
	if err == manager.ErrNotCached {
		log.Debug("No pre-existing agent SVID found. Will perform node attestation")
		return nil
	} else if err != nil {
		log.WithError(err).Warn("Could not get agent SVID from path")
	}
	return svid
}

// newSVID obtains an agent svid for the given private key by performing node attesatation. The bundle is
// necessary in order to validate the SPIRE server we are attesting to. Returns the SVID and an updated bundle.
func (a *attestor) newSVID(ctx context.Context, key *ecdsa.PrivateKey, bundle *bundleutil.Bundle) (_ []*x509.Certificate, _ *bundleutil.Bundle, err error) {
	counter := telemetry_agent.StartNodeAttestorNewSVIDCall(a.c.Metrics)
	attestorName := ""
	defer func() {
		telemetry_common.AddAttestorType(counter, attestorName)
		counter.Done(&err)
	}()

	// make sure all of the streams are cancelled if something goes awry
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	attestorName = joinTokenType
	var fetchStream nodeattestor.NodeAttestor_FetchAttestationDataClient
	if a.c.JoinToken == "" {
		attestor := a.c.Catalog.GetNodeAttestor()
		attestorName = attestor.Name()
		var err error
		fetchStream, err = attestor.FetchAttestationData(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("opening stream for fetching attestation: %v", err)
		}
	}

	conn, err := a.serverConn(ctx, bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("create attestation client: %v", err)
	}
	defer conn.Close()

	csr, err := util.MakeCSRWithoutURISAN(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CSR for attestation: %v", err)
	}

	newSVID, err := a.getSVID(ctx, conn, csr, fetchStream)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SVID: %v", err)
	}
	newBundle, err := a.getBundle(ctx, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get updated bundle: %v", err)
	}
	return newSVID, newBundle, nil
}

func (a *attestor) serverConn(ctx context.Context, bundle *bundleutil.Bundle) (*grpc.ClientConn, error) {
	if bundle != nil {
		return client.DialServer(ctx, client.DialServerConfig{
			Address:     a.c.ServerAddress,
			TrustDomain: a.c.TrustDomain.Host,
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
		InsecureSkipVerify: true, //nolint: gosec
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			a.c.Log.Warn("Insecure bootstrap enabled; skipping server certificate verification")
			if len(rawCerts) == 0 {
				// This is not really possible without a catastrophic bug
				// creeping into the TLS stack.
				return errs.New("server chain is unexpectedly empty")
			}

			trustDomain, err := spiffeid.TrustDomainFromString(a.c.TrustDomain.Host)
			if err != nil {
				return err
			}
			expectedServerID := idutil.ServerID(trustDomain)
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
		grpc.WithBalancerName(roundrobin.Name), //nolint:staticcheck
		grpc.FailOnNonTempDialError(true),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
}
