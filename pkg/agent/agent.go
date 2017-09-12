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

	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/go-spiffe/uri"

	"github.com/spiffe/spire/helpers"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/agent/endpoints/server"
	"github.com/spiffe/spire/pkg/agent/keymanager"
	"github.com/spiffe/spire/pkg/agent/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/workloadattestor"
	"github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common/plugin"

	spire_common "github.com/spiffe/spire/pkg/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	PluginTypeMap = map[string]plugin.Plugin{
		"KeyManager":       &keymanager.KeyManagerPlugin{},
		"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
		"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"KeyManager":       1,
		"NodeAttestor":     1,
		"WorkloadAttestor": 1,
	}
)

type Config struct {
	// Address to bind the workload api to
	BindAddress *net.TCPAddr

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

type AgentConfig struct {
	Config        *Config
	PluginCatalog helpers.PluginCatalog
	NodeClient    node.NodeClient
}

type Agent struct {
	BaseSVID    []byte
	baseSVIDKey *ecdsa.PrivateKey
	BaseSVIDTTL int32
	grpcServer  *grpc.Server
	acc         *AgentConfig
	Cache       cache.Cache
}

func New(ac *AgentConfig) *Agent {
	return &Agent{acc: ac}
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	a.Cache = cache.NewCache()

	err := a.initPlugins()
	defer a.stopPlugins()
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
	a.acc.Config.Log.Info( "SPIRE Agent is now running")
	for {
		select {
		case err = <-a.acc.Config.ErrorCh:
			return err
		case <-a.acc.Config.ShutdownCh:
			a.grpcServer.GracefulStop()
			return <-a.acc.Config.ErrorCh
		}
	}
}

func (a *Agent) initPlugins() error {
	a.acc.Config.Log.Info( "Starting plugins")
	a.acc.PluginCatalog.SetMaxPluginTypeMap(MaxPlugins)
	a.acc.PluginCatalog.SetPluginTypeMap(PluginTypeMap)

	err := a.acc.PluginCatalog.Run()
	if err != nil {
		return err
	}

	return nil
}

func (a *Agent) initEndpoints() error {
	a.acc.Config.Log.Info("Starting the workload API")
	svc := server.NewService(a.acc.PluginCatalog, a.acc.Config.ShutdownCh)

	endpoints := server.Endpoints{
		PluginInfoEndpoint: server.MakePluginInfoEndpoint(svc),
		StopEndpoint:       server.MakeStopEndpoint(svc),
	}

	a.grpcServer = grpc.NewServer()
	handler := server.MakeGRPCServer(endpoints)
	sriplugin.RegisterServerServer(a.grpcServer, handler)

	listener, err := net.Listen(a.acc.Config.BindAddress.Network(), a.acc.Config.BindAddress.String())
	if err != nil {
		return fmt.Errorf("Error creating GRPC listener: %s", err)
	}

	go func() {
		a.acc.Config.ErrorCh <- a.grpcServer.Serve(listener)
	}()

	return nil
}

func (a *Agent) bootstrap() error {
	a.acc.Config.Log.Info( "Bootstrapping SPIRE agent")

	// Look up the key manager plugin
	pluginClients := a.acc.PluginCatalog.GetPluginsByType("KeyManager")
	if len(pluginClients) != 1 {
		return fmt.Errorf("Expected only one key manager plugin, found %i", len(pluginClients))
	}
	keyManager := pluginClients[0].(keymanager.KeyManager)

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
			a.acc.Config.Log.Info("Certificate configured but no private key found!")
		}

		a.acc.Config.Log.Info("Generating private key for new base SVID")
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
		err = a.FetchSVID(regEntryMap)
		if err != nil {
			return err
		}
	}

	a.acc.Config.Log.Info("Bootstrapping done")
	return nil
}

/* Attest the agent, obtain a new Base SVID
returns a spiffeid->registration entries map
This map is used generated CSR for non-base SVIDs and update the agent cache entries
*/
func (a *Agent) attest() (map[string]*spire_common.RegistrationEntry, error) {
	a.acc.Config.Log.Info("Preparing to attest against %s", a.acc.Config.ServerAddress.String())

	// Look up the node attestor plugin
	pluginClients := a.acc.PluginCatalog.GetPluginsByType("NodeAttestor")
	if len(pluginClients) != 1 {
		return nil, fmt.Errorf("Expected only one node attestor plugin, found %i", len(pluginClients))
	}
	attestor := pluginClients[0].(nodeattestor.NodeAttestor)

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
	conn := a.getNodeAPIClientConn(false)
	defer conn.Close()
	nodeClient := node.NewNodeClient(conn)

	// Perform attestation
	req := &node.FetchBaseSVIDRequest{
		AttestedData: pluginResponse.AttestedData,
		Csr:          csr,
	}

	serverResponse, err := nodeClient.FetchBaseSVID(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("Failed attestation against spire server: %s", err)
	}

	// Pull base SVID out of the response
	svids := serverResponse.SvidUpdate.Svids
	if len(svids) > 1 {
		a.acc.Config.Log.Info("More than one SVID received during attestation!")
	}
	svid, ok := svids[id.String()]
	if !ok {
		return nil, fmt.Errorf("Base SVID not found in attestation response")
	}

	var registrationEntryMap = make(map[string]*spire_common.RegistrationEntry)
	for _, entry := range serverResponse.SvidUpdate.RegistrationEntries[1:] {
			registrationEntryMap[entry.SpiffeId] = entry
	}

	a.BaseSVID = svid.SvidCert
	a.BaseSVIDTTL = svid.Ttl
	a.storeBaseSVID()
	a.acc.Config.Log.Info( "Attestation complete")
	return registrationEntryMap, nil
}

// Generate a CSR for the given SPIFFE ID
func (a *Agent) generateCSR(spiffeID *url.URL, key *ecdsa.PrivateKey) ([]byte, error) {
	a.acc.Config.Log.Info( "Generating a CSR for %s", spiffeID.String())

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
		Subject:            *a.acc.Config.CertDN,
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
	a.acc.Config.Log.Info("Loading base SVID from disk")

	certPath := path.Join(a.acc.Config.DataDir, "base_svid.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		a.acc.Config.Log.Info( "A base SVID could not be found. A new one will be generated")
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
	certPath := path.Join(a.acc.Config.DataDir, "base_svid.crt")
	f, err := os.Create(certPath)
	defer f.Close()
	if err != nil {
		a.acc.Config.Log.Info( "Unable to store Base SVID at path %s!", certPath)
		return
	}

	f.Write(a.BaseSVID)
	f.Sync()

	return
}

func (a *Agent) FetchSVID(registrationEntryMap map[string]*spire_common.RegistrationEntry) (err error) {

	if len(registrationEntryMap) != 0 {
		Csrs, pkeyMap, err := a.generateCSRForRegistrationEntries(registrationEntryMap)
		if err != nil {
			return err
		}

		conn := a.getNodeAPIClientConn(true)
		defer conn.Close()
		nodeClient := node.NewNodeClient(conn)

		req := &node.FetchSVIDRequest{Csrs: Csrs}

		resp, err := nodeClient.FetchSVID(context.Background(), req)
		if err != nil {
			return err
		}

		svidMap := resp.GetSvidUpdate().GetSvids()

		for spiffeID, entry := range registrationEntryMap {
			svid, svidInMap := svidMap[spiffeID]
			pkey, pkeyInMap := pkeyMap[spiffeID]
			if svidInMap && pkeyInMap {
				a.Cache.SetEntry(cache.CacheEntry{entry,
					svid, pkey})
			}
		}

		newRegistrationMap := make(map[string]*spire_common.RegistrationEntry)

		if len(resp.SvidUpdate.RegistrationEntries) != len(registrationEntryMap) {
			for _, entry := range resp.SvidUpdate.RegistrationEntries {
				if _, ok := registrationEntryMap[entry.SpiffeId]; ok != true {
					newRegistrationMap[entry.SpiffeId] = entry
				}
			}
			a.FetchSVID(newRegistrationMap)

		}
	}
	return
}

func (a *Agent) getNodeAPIClientConn(mtls bool) (conn *grpc.ClientConn) {

	serverID := a.acc.Config.TrustDomain
	serverID.Path = "spiffe/cp"
	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{serverID.String()},
		TrustRoots: a.acc.Config.TrustBundle,
	}
	var Cert [][]byte
	if mtls {
		Cert = [][]byte{a.BaseSVID}
	}
	tlsConfig := spiffePeer.NewTLSConfig([]tls.Certificate{
		{Certificate: Cert}})

	if !mtls {
		tlsConfig.ClientAuth = tls.NoClientCert
	}
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(a.acc.Config.ServerAddress.String(), dialCreds)
	if err != nil {
		return
	}

	return

}

func (a *Agent) generateCSRForRegistrationEntries(
	regEntryMap map[string]*spire_common.RegistrationEntry) (CSRs [][]byte, pkeyMap map[string]*ecdsa.PrivateKey, err error) {

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

func (a *Agent) stopPlugins() {
	a.acc.Config.Log.Info( "Stopping plugins...")
	if a.acc.PluginCatalog != nil {
		a.acc.PluginCatalog.Stop()
	}
}
