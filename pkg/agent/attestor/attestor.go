package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"

	"github.com/sirupsen/logrus"
	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
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
	Attest() (*AttestationResult, error)
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

func (a *attestor) Attest() (*AttestationResult, error) {
	bundle, err := a.loadBundle()
	if err != nil {
		return nil, err
	}
	svid, key, err := a.loadSVID()
	if err != nil {
		return nil, err
	}

	if svid == nil {
		svid, bundle, err = a.newSVID(key, bundle)
		if err != nil {
			return nil, err
		}
	}
	return &AttestationResult{Bundle: bundle, SVID: svid, Key: key}, nil
}

func (a *attestor) loadSVID() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	mgrs := a.c.Catalog.KeyManagers()
	if len(mgrs) > 1 {
		return nil, nil, errors.New("more than one key manager configured")
	}

	mgr := mgrs[0]
	fResp, err := mgr.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
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
		gResp, err := mgr.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
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

func (a *attestor) attestationData() (*nodeattestor.FetchAttestationDataResponse, error) {

	resp := &nodeattestor.FetchAttestationDataResponse{}

	if a.c.JoinToken != "" {
		data := &common.AttestedData{
			Type: "join_token",
			Data: []byte(a.c.JoinToken),
		}

		id := &url.URL{
			Scheme: "spiffe",
			Host:   a.c.TrustDomain.Host,
			Path:   path.Join("spire", "agent", "join_token", a.c.JoinToken),
		}

		resp.AttestedData = data
		resp.SpiffeId = id.String()
		return resp, nil
	}

	plugins := a.c.Catalog.NodeAttestors()
	if len(plugins) > 1 {
		return nil, errors.New("more then one node attestor configured")
	}
	attestor := plugins[0]

	return attestor.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
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
func (a *attestor) newSVID(key *ecdsa.PrivateKey, bundle []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	data, err := a.attestationData()
	if err != nil {
		return nil, nil, fmt.Errorf("fetch attestable data: %v", err)
	}

	csr, err := util.MakeCSR(key, data.SpiffeId)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CSR for agent SVID: %v", err)
	}

	conn, err := a.serverConn(bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("create attestation client: %v", err)
	}
	defer conn.Close()
	if a.c.NodeClient == nil {
		a.c.NodeClient = node.NewNodeClient(conn)
	}
	req := &node.FetchBaseSVIDRequest{
		AttestedData: data.AttestedData,
		Csr:          csr,
	}
	resp, err := a.c.NodeClient.FetchBaseSVID(context.TODO(), req)
	if err != nil {
		return nil, nil, fmt.Errorf("attesting to SPIRE server: %v", err)
	}

	svid, bundle, err := a.parseAttestationResponse(data.SpiffeId, resp)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation response: %v", err)
	}

	return svid, bundle, nil
}

func (a *attestor) serverConn(bundle []*x509.Certificate) (*grpc.ClientConn, error) {
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
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	return grpc.DialContext(context.TODO(), a.c.ServerAddress.String(), dialCreds)
}

func (a *attestor) parseAttestationResponse(id string, r *node.FetchBaseSVIDResponse) (*x509.Certificate, []*x509.Certificate, error) {
	if len(r.SvidUpdate.Svids) < 1 {
		return nil, nil, errors.New("no svid received")
	}

	svidMsg, ok := r.SvidUpdate.Svids[id]
	if !ok {
		return nil, nil, errors.New("incorrect svid")
	}

	svid, err := x509.ParseCertificate(svidMsg.SvidCert)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid svid: %v", err)
	}

	bundle, err := x509.ParseCertificates(r.SvidUpdate.Bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid bundle: %v", bundle)
	}

	return svid, bundle, nil
}

func (a *attestor) serverID() *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   a.c.TrustDomain.Host,
		Path:   path.Join("spiffe", "cp"),
	}
}
