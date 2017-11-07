package agent

import (
	"context"
	"crypto/ecdsa"
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
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
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

	// Trust domain and associated CA bundle
	TrustDomain url.URL
	TrustBundle *x509.CertPool

	// Join token to use for attestation, if needed
	JoinToken string

	// Umask value to use
	Umask int
}

type Agent struct {
	BaseSVID     *x509.Certificate
	baseSVIDKey  *ecdsa.PrivateKey
	BaseSVIDTTL  int32
	config       *Config
	grpcServer   *grpc.Server
	CacheMgr     cache.Manager
	Catalog      catalog.Catalog
	serverCerts  []*x509.Certificate
	ctx          context.Context
	cancel       context.CancelFunc
	baseSVIDPath string
}

func New(ctx context.Context, c *Config) *Agent {
	config := &catalog.Config{
		ConfigDir: c.PluginDir,
		Log:       c.Log.WithField("subsystem_name", "catalog"),
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Agent{
		config:       c,
		Catalog:      catalog.New(config),
		ctx:          ctx,
		cancel:       cancel,
		baseSVIDPath: path.Join(c.DataDir, "base_svid.crt"),
	}
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	a.prepareUmask()

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
			e := a.Shutdown()
			if e != nil {
				a.config.Log.Debug(e)
			}
			return err
		case <-a.ctx.Done():
			return a.Shutdown()
		}
	}
}

func (a *Agent) prepareUmask() {
	a.config.Log.Debug("Setting umask to ", a.config.Umask)
	syscall.Umask(a.config.Umask)
}

func (a *Agent) Shutdown() error {
	defer a.cancel()
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
		cache:   a.CacheMgr.Cache(),
		catalog: a.Catalog,
		l:       log,
		maxTTL:  maxWorkloadTTL,
		minTTL:  5,
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

	if addr.Network() == "unix" {
		// Any process should be able to use this unix socket
		os.Chmod(addr.String(), os.ModePerm)
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
		regEntries, err := a.attest()
		if err != nil {
			return err
		}
		serverId := url.URL{
			Scheme: "spiffe",
			Host:   a.config.TrustDomain.Host,
			Path:   path.Join("spiffe", "cp"),
		}
		cmgrConfig := &cache.MgrConfig{
			ServerCerts:    a.serverCerts,
			ServerSPIFFEID: serverId.String(),
			ServerAddr:     a.config.ServerAddress.String(),

			BaseSVID:       a.BaseSVID,
			BaseSVIDKey:    a.baseSVIDKey,
			BaseRegEntries: regEntries,
			BaseSVIDPath:   a.baseSVIDPath,
			Logger:         a.config.Log,
		}

		a.CacheMgr, err = cache.NewManager(a.ctx, cmgrConfig)

		a.CacheMgr.Init()
		go func() {
			<-a.CacheMgr.Done()
			a.config.Log.Info("Cache Update Stopped")
			if a.CacheMgr.Err() != nil {
				a.config.Log.Warning(a.CacheMgr.Err())
			}
		}()
	}

	a.config.Log.Info("Bootstrapping done")
	return nil
}

// Attest the agent, obtain a new Base SVID. Returns a spiffeid->registration entries map
// which is used to generate CSRs for non-base SVIDs and update the agent cache entries
//
// TODO: Refactor me for length, testability

func (a *Agent) attest() ([]*common.RegistrationEntry, error) {
	var err error
	a.config.Log.Info("Preparing to attest against ", a.config.ServerAddress.String())

	// Handle the join token seperately, if defined
	pluginResponse := &nodeattestor.FetchAttestationDataResponse{}
	if a.config.JoinToken != "" {
		a.config.Log.Info("Preparing to attest this node against ",
			a.config.ServerAddress.String(), " using strategy 'join-token'")
		data := &common.AttestedData{
			Type: "join_token",
			Data: []byte(a.config.JoinToken),
		}
		id := &url.URL{
			Scheme: "spiffe",
			Host:   a.config.TrustDomain.Host,
			Path:   path.Join("spire", "agent", "join_token", a.config.JoinToken),
		}
		pluginResponse.AttestedData = data
		pluginResponse.SpiffeId = id.String()
	} else {
		plugins := a.Catalog.NodeAttestors()
		if len(plugins) != 1 {
			return nil, fmt.Errorf("Expected only one node attestor plugin, found %i", len(plugins))
		}
		attestor := plugins[0]

		attestorInfo := a.Catalog.Find(attestor.(common_catalog.Plugin))
		a.config.Log.Info("Preparing to attest this node against ", a.config.ServerAddress.String(),
			" using strategy '", attestorInfo.Config.PluginName, "'")

		pluginResponse, err = attestor.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
		if err != nil {
			return nil, fmt.Errorf("Failed to get attestation data from plugin: %s", err)
		}
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
	conn, err := a.getNodeAPIClientConn(false, a.BaseSVID, a.baseSVIDKey)
	if err != nil {
		return nil, err
	}
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

	cert, err := x509.ParseCertificate(svid.SvidCert)
	if err != nil {
		return nil, fmt.Errorf("could not parse base svid: %s", err)
	}

	a.BaseSVID = cert
	a.BaseSVIDTTL = svid.Ttl
	a.storeBaseSVID()
	a.config.Log.Info("Attestation complete")
	return serverResponse.SvidUpdate.RegistrationEntries, nil
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

	if _, err := os.Stat(a.baseSVIDPath); os.IsNotExist(err) {
		a.config.Log.Info("A base SVID could not be found. A new one will be generated")
		return nil
	}

	data, err := ioutil.ReadFile(a.baseSVIDPath)
	if err != nil {
		return fmt.Errorf("Could not read Base SVID at path %s: %s", a.baseSVIDPath, err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return fmt.Errorf("Certificate at %s could not be understood: %s", a.baseSVIDPath, err)
	}

	a.BaseSVID = cert
	return nil
}

// Write base SVID to storage dir
func (a *Agent) storeBaseSVID() {
	f, err := os.Create(a.baseSVIDPath)
	defer f.Close()
	if err != nil {
		a.config.Log.Info("Unable to store Base SVID at path ", a.baseSVIDPath)
		return
	}

	f.Write(a.BaseSVID.Raw)
	f.Sync()

	return
}

func (a *Agent) getNodeAPIClientConn(mtls bool, svid *x509.Certificate, key *ecdsa.PrivateKey) (conn *grpc.ClientConn, err error) {

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
		tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
		tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	}

	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err = grpc.DialContext(a.ctx, a.config.ServerAddress.String(), dialCreds)
	if err != nil {
		return
	}

	return
}
