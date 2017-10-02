package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
)

type Config struct {
	// Address to bind the workload api to
	BindAddress *net.UnixAddr

	// Distinguished Name to use for all CSRs
	CertDN *pkix.Name

	// Directory to store runtime data
	DataDir string

	// Directory for plugin configs
	PluginDir string

	Log logrus.FieldLogger

	// Address of SPIRE server
	ServerAddress *net.TCPAddr

	// A channel for receiving errors from agent goroutines
	ErrorCh chan error

	// A channel to trigger agent shutdown
	ShutdownCh chan struct{}

	// Trust domain and associated CA bundle
	TrustDomain url.URL
	TrustBundle *x509.CertPool
}

type Agent struct {
	BaseSVID    []byte
	baseSVIDKey *ecdsa.PrivateKey
	BaseSVIDTTL int32
	config      *Config
	grpcServer  *grpc.Server
	Cache       cache.Cache
	Catalog     catalog.Catalog
	serverCerts []*x509.Certificate
}

func New(c *Config) *Agent {
	config := &catalog.Config{
		ConfigDir: c.PluginDir,
		Log:       c.Log.WithField("subsystem_name", "catalog"),
	}
	return &Agent{config: c, Catalog: catalog.New(config)}
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	a.Cache = cache.NewCache()

	err := a.initPlugins()
	if err != nil {
		return err
	}

	err = a.bootstrap()
	if err != nil {
		return err
	}

	err = a.initEndpoints()
	if err != nil {
		return err
	}

	// Main event loop
	a.config.Log.Info("SPIRE Agent is now running")
	for {
		select {
		case err = <-a.config.ErrorCh:
			return err
		case <-a.config.ShutdownCh:
			return a.Shutdown()
		}
	}
}

func (a *Agent) Shutdown() error {
	if a.Catalog != nil {
		a.Catalog.Stop()
	}

	a.grpcServer.GracefulStop()

	// Drain error channel, last one wins
	var err error
Drain:
	for {
		select {
		case e := <-a.config.ErrorCh:
			err = e
		default:
			break Drain
		}
	}

	return err
}

func (a *Agent) initPlugins() error {
	err := a.Catalog.Run()
	if err != nil {
		return err
	}

	return nil
}

func (a *Agent) initEndpoints() error {
	a.config.Log.Info("Starting the workload API")

	maxWorkloadTTL := time.Duration(a.BaseSVIDTTL/2) * time.Second

	log := a.config.Log.WithField("subsystem_name", "workload")
	ws := &workloadServer{
		bundle:  a.serverCerts[1].Raw, // TODO: Fix handling of serverCerts
		cache:   a.Cache,
		catalog: a.Catalog,
		l:       log,
		maxTTL:  maxWorkloadTTL,
	}

	// Create a gRPC server with our custom "credential" resolver
	a.grpcServer = grpc.NewServer(grpc.Creds(auth.NewCredentials()))
	workload.RegisterWorkloadServer(a.grpcServer, ws)

	addr := a.config.BindAddress
	if addr.Network() == "unix" {
		_ = os.Remove(addr.String())
	}

	listener, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		return fmt.Errorf("Error creating GRPC listener: %s", err)
	}

	go func() {
		a.config.ErrorCh <- a.grpcServer.Serve(listener)
	}()

	return nil
}

func (a *Agent) bootstrap() error {
	a.config.Log.Info("Bootstrapping SPIRE agent")

	plugins := a.Catalog.KeyManagers()
	if len(plugins) != 1 {
		return fmt.Errorf("Expected only one key manager plugin, found %i", len(plugins))
	}
	keyManager := plugins[0]

	// Fetch or generate private key
	res, err := keyManager.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		return err
	}
	if len(res.PrivateKey) > 0 {
		key, err := x509.ParseECPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}

		err = a.loadBaseSVID()
		if err != nil {
			return err
		}
		a.baseSVIDKey = key
	} else {
		if a.BaseSVID != nil {
			a.config.Log.Info("Certificate configured but no private key found!")
		}

		a.config.Log.Info("Generating private key for new base SVID")
		res, err := keyManager.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
		if err != nil {
			return fmt.Errorf("Failed to generate private key: %s", err)
		}
		key, err := x509.ParseECPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}
		a.baseSVIDKey = key

		// If we're here, we need to attest/Re-attest
		regEntryMap, err := a.attest()
		if err != nil {
			return err
		}
		err = a.FetchSVID(regEntryMap, a.BaseSVID, a.baseSVIDKey)
		if err != nil {
			return err
		}
	}

	a.config.Log.Info("Bootstrapping done")
	return nil
}

/* Attest the agent, obtain a new Base SVID
returns a spiffeid->registration entries map
This map is used generated CSR for non-base SVIDs and update the agent cache entries
*/
func (a *Agent) attest() (map[string]*common.RegistrationEntry, error) {
	a.config.Log.Info("Preparing to attest against ", a.config.ServerAddress.String())

	plugins := a.Catalog.NodeAttestors()
	if len(plugins) != 1 {
		return nil, fmt.Errorf("Expected only one node attestor plugin, found %i", len(plugins))
	}
	attestor := plugins[0]

	pluginResponse, err := attestor.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get attestation data from plugin: %s", err)
	}

	// Parse the SPIFFE ID, form a CSR with it
	id, err := url.Parse(pluginResponse.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("Failed to form SPIFFE ID: %s", err)
	}
	csr, err := a.generateCSR(id, a.baseSVIDKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate CSR for attestation: %s", err)
	}

	// Since we are bootstrapping, this is explicitly _not_ mTLS
	conn := a.getNodeAPIClientConn(false, a.BaseSVID, a.baseSVIDKey)
	defer conn.Close()
	nodeClient := node.NewNodeClient(conn)

	// Perform attestation
	req := &node.FetchBaseSVIDRequest{
		AttestedData: pluginResponse.AttestedData,
		Csr:          csr,
	}

	calloptPeer := new(peer.Peer)

	serverResponse, err := nodeClient.FetchBaseSVID(context.Background(), req, grpc.Peer(calloptPeer))
	if err != nil {
		return nil, fmt.Errorf("Failed attestation against spire server: %s", err)
	}

	if tlsInfo, ok := calloptPeer.AuthInfo.(credentials.TLSInfo); ok {
		a.serverCerts = tlsInfo.State.PeerCertificates
	}

	// Pull base SVID out of the response
	svids := serverResponse.SvidUpdate.Svids
	if len(svids) > 1 {
		a.config.Log.Info("More than one SVID received during attestation!")
	}
	svid, ok := svids[id.String()]
	if !ok {
		return nil, fmt.Errorf("Base SVID not found in attestation response")
	}

	var registrationEntryMap = make(map[string]*common.RegistrationEntry)
	for _, entry := range serverResponse.SvidUpdate.RegistrationEntries {
		registrationEntryMap[entry.SpiffeId] = entry
	}

	a.BaseSVID = svid.SvidCert
	a.BaseSVIDTTL = svid.Ttl
	a.storeBaseSVID()
	a.config.Log.Info("Attestation complete")
	return registrationEntryMap, nil
}

// Generate a CSR for the given SPIFFE ID
func (a *Agent) generateCSR(spiffeID *url.URL, key *ecdsa.PrivateKey) ([]byte, error) {
	a.config.Log.Info("Generating a CSR for ", spiffeID.String())

	uriSANs, err := uri.MarshalUriSANs([]string{spiffeID.String()})
	if err != nil {
		return []byte{}, err
	}
	uriSANExtension := []pkix.Extension{{
		Id:       uri.OidExtensionSubjectAltName,
		Value:    uriSANs,
		Critical: true,
	}}

	csrData := &x509.CertificateRequest{
		Subject:            *a.config.CertDN,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    uriSANExtension,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, csrData, key)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// Read base SVID from data dir and load it
func (a *Agent) loadBaseSVID() error {
	a.config.Log.Info("Loading base SVID from disk")

	certPath := path.Join(a.config.DataDir, "base_svid.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		a.config.Log.Info("A base SVID could not be found. A new one will be generated")
		return nil
	}

	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("Could not read Base SVID at path %s: %s", certPath, err)
	}

	// Sanity check
	_, err = x509.ParseCertificate(data)
	if err != nil {
		return fmt.Errorf("Certificate at %s could not be understood: %s", certPath, err)
	}

	a.BaseSVID = data
	return nil
}

// Write base SVID to storage dir
func (a *Agent) storeBaseSVID() {
	certPath := path.Join(a.config.DataDir, "base_svid.crt")
	f, err := os.Create(certPath)
	defer f.Close()
	if err != nil {
		a.config.Log.Info("Unable to store Base SVID at path ", certPath)
		return
	}

	f.Write(a.BaseSVID)
	f.Sync()

	return
}

func (a *Agent) FetchSVID(registrationEntryMap map[string]*common.RegistrationEntry, svidCert []byte,
	key *ecdsa.PrivateKey) (err error) {

	if len(registrationEntryMap) != 0 {
		Csrs, pkeyMap, err := a.generateCSRForRegistrationEntries(registrationEntryMap)
		if err != nil {
			return err
		}

		conn := a.getNodeAPIClientConn(true, svidCert, key)
		defer conn.Close()
		nodeClient := node.NewNodeClient(conn)

		req := &node.FetchSVIDRequest{Csrs: Csrs}

		callOptPeer := new(peer.Peer)
		resp, err := nodeClient.FetchSVID(context.Background(), req, grpc.Peer(callOptPeer))
		if err != nil {
			return err
		}
		if tlsInfo, ok := callOptPeer.AuthInfo.(credentials.TLSInfo); ok {
			a.serverCerts = tlsInfo.State.PeerCertificates
		}

		svidMap := resp.GetSvidUpdate().GetSvids()

		// TODO: Fetch the referenced federated bundles and
		// set them here
		bundles := make(map[string][]byte)
		for spiffeID, entry := range registrationEntryMap {
			svid, svidInMap := svidMap[spiffeID]
			pkey, pkeyInMap := pkeyMap[spiffeID]
			if svidInMap && pkeyInMap {
				svidCert, err := x509.ParseCertificate(svid.SvidCert)
				if err != nil {
					return fmt.Errorf("SVID for ID %s could not be parsed: %s", spiffeID, err)
				}

				entry := cache.CacheEntry{
					RegistrationEntry: entry,
					SVID:              svid,
					PrivateKey:        pkey,
					Bundles:           bundles,
					Expiry:            svidCert.NotAfter,
				}
				a.Cache.SetEntry(entry)
			}
		}

		newRegistrationMap := make(map[string]*common.RegistrationEntry)

		if len(resp.SvidUpdate.RegistrationEntries) != 0 {
			for _, entry := range resp.SvidUpdate.RegistrationEntries {
				if _, ok := registrationEntryMap[entry.SpiffeId]; ok != true {
					newRegistrationMap[entry.SpiffeId] = entry
				}
				a.FetchSVID(newRegistrationMap, svidMap[entry.SpiffeId].SvidCert, pkeyMap[entry.SpiffeId])

			}

		}
	}
	return
}

func (a *Agent) getNodeAPIClientConn(mtls bool, svid []byte, key *ecdsa.PrivateKey) (conn *grpc.ClientConn) {

	serverID := a.config.TrustDomain
	serverID.Path = "spiffe/cp"

	var spiffePeer *spiffe_tls.TLSPeer
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	if !mtls {
		spiffePeer = &spiffe_tls.TLSPeer{
			SpiffeIDs:  []string{serverID.String()},
			TrustRoots: a.config.TrustBundle,
		}
		tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	} else {
		certPool := x509.NewCertPool()
		for _, cert := range a.serverCerts {
			certPool.AddCert(cert)
		}
		spiffePeer = &spiffe_tls.TLSPeer{
			SpiffeIDs:  []string{serverID.String()},
			TrustRoots: certPool,
		}
		tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid}, PrivateKey: key})
		tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	}

	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(a.config.ServerAddress.String(), dialCreds)
	if err != nil {
		return
	}

	return

}

func (a *Agent) generateCSRForRegistrationEntries(
	regEntryMap map[string]*common.RegistrationEntry) (CSRs [][]byte, pkeyMap map[string]*ecdsa.PrivateKey, err error) {

	pkeyMap = make(map[string]*ecdsa.PrivateKey)
	for id, _ := range regEntryMap {

		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		spiffeid, err := url.Parse(id)
		if err != nil {
			return nil, nil, err
		}
		csr, err := a.generateCSR(spiffeid, key)
		if err != nil {
			return nil, nil, err
		}
		CSRs = append(CSRs, csr)
		pkeyMap[id] = key
	}
	return
}
