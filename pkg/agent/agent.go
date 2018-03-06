package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sync"
	"syscall"

	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	tomb "gopkg.in/tomb.v2"
)

type Agent struct {
	c   *Config
	t   *tomb.Tomb
	mtx *sync.RWMutex

	Manager   manager.Manager
	Catalog   catalog.Catalog
	Endpoints endpoints.Endpoints
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	syscall.Umask(a.c.Umask)

	a.t.Go(a.run)
	return a.t.Wait()
}

func (a *Agent) Shutdown() {
	a.t.Kill(nil)
}

func (a *Agent) run() error {
	err := a.startPlugins()
	if err != nil {
		return err
	}

	bundle, err := a.loadBundle()
	if err != nil {
		return err
	}

	svid, key, err := a.loadSVID()
	if err != nil {
		return err
	}

	if svid == nil {
		svid, bundle, err = a.newSVID(key, bundle)
		if err != nil {
			return err
		}
	}

	err = a.startManager(svid, key, bundle)
	if err != nil {
		return err
	}

	a.t.Go(func() error { return a.startEndpoints(bundle) })
	a.t.Go(a.superviseManager)
	return nil
}

func (a *Agent) superviseManager() (err error) {
	// Wait until the agent's tomb is dying or the manager stopped working.
	select {
	case <-a.t.Dying():
	case <-a.Manager.Stopped():
		err = a.Manager.Err()
		a.mtx.Lock()
		a.Manager = nil
		a.mtx.Unlock()
	}
	a.shutdown()
	return err
}

func (a *Agent) shutdown() {
	if a.Endpoints != nil {
		a.Endpoints.Shutdown()
	}

	if a.Manager != nil {
		a.Manager.Shutdown()
	}

	if a.Catalog != nil {
		a.Catalog.Stop()
	}
}

func (a *Agent) startPlugins() error {
	return a.Catalog.Run()
}

// loadBundle tries to recover a cached bundle from previous executions, and falls back
// to the configured trust bundle if an updated bundle isn't found.
func (a *Agent) loadBundle() ([]*x509.Certificate, error) {
	bundle, err := manager.ReadBundle(a.bundleCachePath())
	if err == manager.ErrNotCached {
		bundle = a.c.TrustBundle
	} else if err != nil {
		return nil, err
	}

	if a.c.TrustBundle == nil {
		return nil, errors.New("load bundle: no bundle provided")
	}

	if len(a.c.TrustBundle) < 1 {
		return nil, errors.New("load bundle: no certs in bundle")
	}

	return bundle, nil
}

// loadSVID loads the private key from key manager and the cached SVID from disk. If the key
// manager doesn't have a key loaded, a new one will be created, and the returned SVID will be nil.
func (a *Agent) loadSVID() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	mgrs := a.Catalog.KeyManagers()
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

// newSVID obtains an agent svid for the given private key by performing node attesatation. The bundle is
// necessary in order to validate the SPIRE server we are attesting to. Returns the SVID and an updated bundle.
func (a *Agent) newSVID(key *ecdsa.PrivateKey, bundle []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	data, err := a.attestableData()
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

	c := node.NewNodeClient(conn)
	req := &node.FetchBaseSVIDRequest{
		AttestedData: data.AttestedData,
		Csr:          csr,
	}
	resp, err := c.FetchBaseSVID(context.TODO(), req)

	if err != nil {
		return nil, nil, fmt.Errorf("attesting to SPIRE server: %v", err)
	}

	svid, bundle, err := a.parseAttestationResponse(data.SpiffeId, resp)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation response: %v", err)
	}

	return svid, bundle, nil
}

func (a *Agent) startManager(svid *x509.Certificate, key *ecdsa.PrivateKey, bundle []*x509.Certificate) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.Manager != nil {
		return errors.New("cannot start cache manager, there is a manager instantiated already")
	}

	mgrConfig := &manager.Config{
		SVID:            svid,
		SVIDKey:         key,
		Bundle:          bundle,
		TrustDomain:     a.c.TrustDomain,
		ServerAddr:      a.c.ServerAddress,
		Log:             a.c.Log,
		BundleCachePath: a.bundleCachePath(),
		SVIDCachePath:   a.agentSVIDPath(),
	}

	mgr, err := manager.New(mgrConfig)
	if err != nil {
		return err
	}
	a.Manager = mgr
	return a.Manager.Start()
}

// TODO: Shouldn't need to pass bundle here
func (a *Agent) startEndpoints(bundle []*x509.Certificate) error {
	config := &endpoints.Config{
		Bundle:   bundle,
		BindAddr: a.c.BindAddress,
		Catalog:  a.Catalog,
		Manager:  a.Manager,
		Log:      a.c.Log.WithField("subsystem_name", "endpoints"),
	}

	e := endpoints.New(config)
	err := e.Start()
	if err != nil {
		return err
	}

	a.mtx.Lock()
	a.Endpoints = e
	a.mtx.Unlock()
	return a.Endpoints.Wait()
}

// attestableData examines the agent configuration, and returns attestableData
// for use when joining a trust domain for the first time.
func (a *Agent) attestableData() (*nodeattestor.FetchAttestationDataResponse, error) {
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

	plugins := a.Catalog.NodeAttestors()
	if len(plugins) > 1 {
		return nil, errors.New("more then one node attestor configured")
	}
	attestor := plugins[0]

	return attestor.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
}

func (a *Agent) parseAttestationResponse(id string, r *node.FetchBaseSVIDResponse) (*x509.Certificate, []*x509.Certificate, error) {
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

func (a *Agent) serverConn(bundle []*x509.Certificate) (*grpc.ClientConn, error) {
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

// Read agent SVID from data dir. If an error is encountered, it will be logged and `nil`
// will be returned.
func (a *Agent) readSVIDFromDisk() *x509.Certificate {

	cert, err := manager.ReadSVID(a.agentSVIDPath())
	if err == manager.ErrNotCached {
		a.c.Log.Debug("No pre-existing agent SVID found. Will perform node attestation")
		return nil
	} else if err != nil {
		a.c.Log.Warnf("Could not get agent SVID from %s: %s", a.agentSVIDPath(), err)
	}

	return cert
}

func (a *Agent) serverID() *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   a.c.TrustDomain.Host,
		Path:   path.Join("spiffe", "cp"),
	}
}

func (a *Agent) agentSVIDPath() string {
	return path.Join(a.c.DataDir, "agent_svid.der")
}

func (a *Agent) bundleCachePath() string {
	return path.Join(a.c.DataDir, "bundle.der")
}
