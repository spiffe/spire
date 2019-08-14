package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/agent/keymanager"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
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
	Catalog         catalog.Catalog
	Metrics         telemetry.Metrics
	JoinToken       string
	TrustDomain     url.URL
	TrustBundle     []*x509.Certificate
	BundleCachePath string
	SVIDCachePath   string
	Log             logrus.FieldLogger
	ServerAddress   string
}

type attestor struct {
	c *Config
}

func New(config *Config) Attestor {
	return &attestor{c: config}
}

func (a *attestor) Attest(ctx context.Context) (res *AttestationResult, err error) {
	counter := telemetry_agent.StartNodeAttestCall(a.c.Metrics)
	defer counter.Done(&err)

	bundle, err := a.loadBundle()
	if err != nil {
		return nil, err
	}
	svid, key, err := a.loadSVID(ctx)
	if err != nil {
		return nil, err
	}

	if svid == nil {
		svid, bundle, err = a.newSVID(ctx, key, bundle)
		if err != nil {
			return nil, err
		}
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
	svidIsExpired := isSVIDExpired(svid, time.Now)

	switch {
	case privateKeyExists && svidExists && !svidIsExpired:
		key, err := x509.ParseECPrivateKey(fetchRes.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("parse key from keymanager: %v", key)
		}
		return svid, key, nil
	case privateKeyExists && svidExists && svidIsExpired:
		a.c.Log.Warn("Private key recovered, but SVID is expired. Generating new keypair.")
	case privateKeyExists && !svidExists:
		a.c.Log.Warn("Private key recovered, but no SVID found. Generating new keypair.")
	case !privateKeyExists && svidExists:
		a.c.Log.Warn("SVID recovered, but no private key found. Generating new keypair.")
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

func isSVIDExpired(svid []*x509.Certificate, timeNow func() time.Time) bool {
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

func (a *attestor) fetchAttestationData(
	fetchStream nodeattestor.NodeAttestor_FetchAttestationDataClient,
	challenge []byte) (*nodeattestor.FetchAttestationDataResponse, error) {

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
func (a *attestor) newSVID(ctx context.Context, key *ecdsa.PrivateKey, bundle *bundleutil.Bundle) (newSVID []*x509.Certificate, newBundle *bundleutil.Bundle, err error) {
	counter := telemetry_agent.StartNodeAttestorNewSVIDCall(a.c.Metrics)
	defer counter.Done(&err)

	// make sure all of the streams are cancelled if something goes awry
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	attestorName := "join_token"
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

	telemetry_common.AddAttestorType(counter, attestorName)

	conn, err := a.serverConn(ctx, bundle.RootCAs())
	if err != nil {
		return nil, nil, fmt.Errorf("create attestation client: %v", err)
	}
	defer conn.Close()

	nodeClient := node.NewNodeClient(conn)

	attestStream, err := nodeClient.Attest(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opening stream for attestation: %v", err)
	}

	var deprecatedAgentID string
	var csr []byte

	attestResp := new(node.AttestResponse)
	for {
		data, err := a.fetchAttestationData(fetchStream, attestResp.Challenge)
		if err != nil {
			return nil, nil, err
		}

		// Old plugins might still be producing the SPIFFE ID for inclusion
		// in the CSR. We should log when this is the case and ensure the
		// SPIFFE ID remains consistent throughout attestation.
		//
		// TODO: remove support in 0.10
		switch {
		case deprecatedAgentID == "":
			if data.DEPRECATEDSpiffeId != "" {
				a.c.Log.WithFields(logrus.Fields{
					"spiffe_id":     data.DEPRECATEDSpiffeId,
					"node_attestor": attestorName,
				}).Warn("Attestor returned a deprecated SPIFFE ID")
				deprecatedAgentID = data.DEPRECATEDSpiffeId
			}
		// make sure the deprecated SPIFFE ID produced by the plugin (if any)
		// remains consistent throughout the attestation challenge/response.
		case data.DEPRECATEDSpiffeId != deprecatedAgentID:
			return nil, nil, fmt.Errorf("plugin returned inconsistent SPIFFE ID: expected %q; got %q", deprecatedAgentID, data.DEPRECATEDSpiffeId)
		}

		if csr == nil {
			if deprecatedAgentID != "" {
				csr, err = util.MakeCSR(key, deprecatedAgentID)
			} else {
				csr, err = util.MakeCSRWithoutURISAN(key)
			}
			if err != nil {
				return nil, nil, fmt.Errorf("generate CSR for agent SVID: %v", err)
			}
		}

		attestReq := &node.AttestRequest{
			AttestationData: data.AttestationData,
			Csr:             csr,
			Response:        data.Response,
		}

		if err := attestStream.Send(attestReq); err != nil {
			return nil, nil, fmt.Errorf("sending attestation request to SPIRE server: %v", err)
		}

		attestResp, err = attestStream.Recv()
		if err != nil {
			return nil, nil, fmt.Errorf("attesting to SPIRE server: %v", err)
		}

		// if the response has no additional data then break out and parse
		// the response.
		if attestResp.Challenge == nil {
			break
		}
	}

	if fetchStream != nil {
		fetchStream.CloseSend()
		if _, err := fetchStream.Recv(); err != io.EOF {
			a.c.Log.WithError(err).Warn("received unexpected result on trailing recv")
		}
	}
	attestStream.CloseSend()
	if _, err := attestStream.Recv(); err != io.EOF {
		a.c.Log.WithError(err).Warn("received unexpected result on trailing recv")
	}

	agentID, svid, bundle, err := a.parseAttestationResponse(attestResp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attestation response: %v", err)
	}
	telemetry_common.AddSPIFFEID(counter, agentID)

	if deprecatedAgentID != "" && agentID != deprecatedAgentID {
		return nil, nil, fmt.Errorf("server returned inconsistent SPIFFE ID: expected %q; got %q", deprecatedAgentID, agentID)
	}

	return svid, bundle, nil
}

func (a *attestor) serverConn(ctx context.Context, bundle []*x509.Certificate) (*grpc.ClientConn, error) {
	return client.DialServer(ctx, client.DialServerConfig{
		Address:     a.c.ServerAddress,
		TrustDomain: a.c.TrustDomain.Host,
		GetBundle: func() []*x509.Certificate {
			return bundle
		},
	})
}

func (a *attestor) parseAttestationResponse(r *node.AttestResponse) (string, []*x509.Certificate, *bundleutil.Bundle, error) {
	if r.SvidUpdate == nil {
		return "", nil, nil, errors.New("missing svid update")
	}
	if len(r.SvidUpdate.Svids) != 1 {
		return "", nil, nil, fmt.Errorf("expected 1 svid; got %d", len(r.SvidUpdate.Svids))
	}

	var agentID string
	var svidMsg *node.X509SVID
	for agentID, svidMsg = range r.SvidUpdate.Svids {
		break
	}

	svid, err := x509.ParseCertificates(svidMsg.CertChain)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid svid cert chain: %v", err)
	}

	if len(svid) == 0 {
		return "", nil, nil, errors.New("empty svid cert chain")
	}

	bundleProto := r.SvidUpdate.Bundles[a.c.TrustDomain.String()]
	if bundleProto == nil {
		return "", nil, nil, errors.New("missing trust domain bundle")
	}

	bundle, err := bundleutil.BundleFromProto(bundleProto)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid trust domain bundle: %v", err)
	}

	return agentID, svid, bundle, nil
}

func (a *attestor) serverID() *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   a.c.TrustDomain.Host,
		Path:   path.Join("spire", "server"),
	}
}
