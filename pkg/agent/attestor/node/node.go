package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"

	"github.com/sirupsen/logrus"
	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/grpcutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type AttestationResult struct {
	SVID   *x509.Certificate
	Key    *ecdsa.PrivateKey
	Bundle []*x509.Certificate
}

type Attestor interface {
	Attest(ctx context.Context) (*AttestationResult, error)
}

type Config struct {
	Catalog         catalog.Catalog
	JoinToken       string
	TrustDomain     url.URL
	TrustBundle     []*x509.Certificate
	BundleCachePath string
	SVIDCachePath   string
	Log             logrus.FieldLogger
	ServerAddress   *net.TCPAddr
	NodeClient      node.NodeClient
}

type attestor struct {
	c *Config
}

func New(config *Config) Attestor {
	return &attestor{c: config}
}

func (a *attestor) Attest(ctx context.Context) (*AttestationResult, error) {
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

func (a *attestor) loadSVID(ctx context.Context) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	mgrs := a.c.Catalog.KeyManagers()
	if len(mgrs) > 1 {
		return nil, nil, errors.New("more than one key manager configured")
	}

	mgr := mgrs[0]
	fResp, err := mgr.FetchPrivateKey(ctx, &keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %v", err)
	}

	svid := a.readSVIDFromDisk()
	if len(fResp.PrivateKey) > 0 && svid == nil {
		a.c.Log.Warn("Private key recovered, but no SVID found")
	}

	var keyData []byte
	if len(fResp.PrivateKey) > 0 && svid != nil {
		keyData = fResp.PrivateKey
	} else {
		gResp, err := mgr.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
		if err != nil {
			return nil, nil, fmt.Errorf("generate key pair: %s", err)
		}

		svid = nil
		keyData = gResp.PrivateKey
	}

	key, err := x509.ParseECPrivateKey(keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse key from keymanager: %v", key)
	}

	return svid, key, nil
}

func (a *attestor) loadBundle() ([]*x509.Certificate, error) {
	bundle, err := manager.ReadBundle(a.c.BundleCachePath)
	if err == manager.ErrNotCached {
		bundle = a.c.TrustBundle
	} else if err != nil {
		return nil, err
	}

	if bundle == nil {
		return nil, errors.New("load bundle: no bundle provided")
	}

	if len(bundle) < 1 {
		return nil, errors.New("load bundle: no certs in bundle")
	}

	return bundle, nil
}

func (a *attestor) fetchAttestationData(
	fetchStream nodeattestor.FetchAttestationData_Stream,
	challenge []byte) (*nodeattestor.FetchAttestationDataResponse, error) {

	// the stream should only be nil if this node attestation is via a join
	// token.
	if fetchStream == nil {
		data := &common.AttestationData{
			Type: "join_token",
			Data: []byte(a.c.JoinToken),
		}

		id := &url.URL{
			Scheme: "spiffe",
			Host:   a.c.TrustDomain.Host,
			Path:   path.Join("spire", "agent", "join_token", a.c.JoinToken),
		}

		return &nodeattestor.FetchAttestationDataResponse{
			AttestationData: data,
			SpiffeId:        id.String(),
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
func (a *attestor) readSVIDFromDisk() *x509.Certificate {
	cert, err := manager.ReadSVID(a.c.SVIDCachePath)
	if err == manager.ErrNotCached {
		a.c.Log.Debug("No pre-existing agent SVID found. Will perform node attestation")
		return nil
	} else if err != nil {
		a.c.Log.Warnf("Could not get agent SVID from %s: %s", a.c.SVIDCachePath, err)
	}
	return cert
}

// newSVID obtains an agent svid for the given private key by performing node attesatation. The bundle is
// necessary in order to validate the SPIRE server we are attesting to. Returns the SVID and an updated bundle.
func (a *attestor) newSVID(ctx context.Context, key *ecdsa.PrivateKey, bundle []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	// make sure all of the streams are cancelled if something goes awry
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var fetchStream nodeattestor.FetchAttestationData_Stream
	if a.c.JoinToken == "" {
		plugins := a.c.Catalog.NodeAttestors()
		if len(plugins) > 1 {
			return nil, nil, errors.New("more than one node attestor configured")
		}
		attestor := plugins[0]
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
	if a.c.NodeClient == nil {
		a.c.NodeClient = node.NewNodeClient(conn)
	}

	attestStream, err := a.c.NodeClient.Attest(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opening stream for attestation: %v", err)
	}

	var spiffeID string
	var csr []byte
	attestResp := new(node.AttestResponse)
	for {
		data, err := a.fetchAttestationData(fetchStream, attestResp.Challenge)
		if err != nil {
			return nil, nil, err
		}

		// (re)generate the SVID if the spiffeid changes.
		if spiffeID != data.SpiffeId {
			csr, err = util.MakeCSR(key, data.SpiffeId)
			if err != nil {
				return nil, nil, fmt.Errorf("generate CSR for agent SVID: %v", err)
			}
			spiffeID = data.SpiffeId
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
			a.c.Log.Warnf("received unexpected result on trailing recv: %v", err)
		}
	}
	attestStream.CloseSend()
	if _, err := attestStream.Recv(); err != io.EOF {
		a.c.Log.Warnf("received unexpected result on trailing recv: %v", err)
	}

	svid, bundle, err := a.parseAttestationResponse(spiffeID, attestResp)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation response: %v", err)
	}

	return svid, bundle, nil
}

func (a *attestor) serverConn(ctx context.Context, bundle []*x509.Certificate) (*grpc.ClientConn, error) {
	config := grpcutil.GRPCDialerConfig{
		Log:      grpcutil.LoggerFromFieldLogger(a.c.Log),
		CredFunc: a.serverCredFunc(bundle),
	}

	dialer := grpcutil.NewGRPCDialer(config)
	return dialer.Dial(ctx, a.c.ServerAddress)
}

func (a *attestor) serverCredFunc(bundle []*x509.Certificate) func() (credentials.TransportCredentials, error) {
	pool := x509.NewCertPool()
	for _, c := range bundle {
		pool.AddCert(c)
	}

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{a.serverID().String()},
		TrustRoots: pool,
	}

	// Explicitly not mTLS since we don't have an SVID yet
	tlsConfig := spiffePeer.NewTLSConfig([]tls.Certificate{})
	credFunc := func() (credentials.TransportCredentials, error) { return credentials.NewTLS(tlsConfig), nil }
	return credFunc
}

func (a *attestor) parseAttestationResponse(id string, r *node.AttestResponse) (*x509.Certificate, []*x509.Certificate, error) {
	if len(r.Update.Svids) < 1 {
		return nil, nil, errors.New("no svid received")
	}

	svidMsg, ok := r.Update.Svids[id]
	if !ok {
		return nil, nil, fmt.Errorf("incorrect svid: %s", id)
	}

	svid, err := x509.ParseCertificate(svidMsg.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid svid: %v", err)
	}

	bundle, err := x509.ParseCertificates(r.Update.Bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid bundle: %v", bundle)
	}

	return svid, bundle, nil
}

func (a *attestor) serverID() *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   a.c.TrustDomain.Host,
		Path:   path.Join("spire", "server"),
	}
}
