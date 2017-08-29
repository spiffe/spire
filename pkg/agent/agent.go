package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"ioutil"
	"net"
	"net/url"
	"os"
	"path"

	"github.com/go-kit/kit/log"
	"github.com/spiffe/go-spiffe/spiffe"

	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/pkg/agent/endpoints/server"
	"github.com/spiffe/sri/pkg/agent/keymanager"
	"github.com/spiffe/sri/pkg/agent/nodeattestor"
	"github.com/spiffe/sri/pkg/agent/workloadattestor"
	"github.com/spiffe/sri/pkg/api/node"
	"github.com/spiffe/sri/pkg/common/plugin"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)


const (
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
	BindAddress *net.Addr

	// Distinguished Name to use for all CSRs
	CertDN *pkix.Name

	// Directory to store runtime data
	DataDir string

	// Directory for plugin configs
	PluginDir string

	Log *log.Logger

	// Address of SPIRE server
	ServerAddress *net.Addr

	// A channel for receiving errors from agent goroutines
	ErrorCh chan error

	// A channel to trigger agent shutdown
	ShutdownCh chan struct{}

	// Trust domain and associated CA bundle
	TrustDomain string
	TrustBundle *x509.CertPool
}

type Agent struct {
	BaseSVID    *x509.Certificate
	key         *ecdsa.PrivateKey
	BaseSVIDTTL int

	Catalog *helpers.PluginCatalog
	Config  *Config
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	err := a.initPlugins()
	if err != nil {
		return err
	}

	err := a.bootstrap()
	if err != nil {
		return err
	}

	a.initEndpoints()

	// Main event loop
	a.Config.Log.Info("SPIRE Agent is now running")
	for {
		select {
		case err <-a.Config.ErrorCh:
			return err
		case <-a.Config.ShutdownCh:
			return nil
		}
	}
}

func (a *Agent) initPlugins() error {
	a.Config.Log.Info("Starting plugins")
	a.Catalog := &helpers.PluginCatalog{
		PluginConfDirectory: a.Config.PluginDir,
	}

	a.Catalog.SetMaxPluginTypeMap(MaxPlugins)
	a.Catalog.SetPluginTypeMap(PluginTypeMap)

	err := a.Catalog.Run()
	if err != nil {
		return err
	}

	return nil
}

func (a *Agent) initEndpoints() {
	a.Config.Log.Info("Starting the workload API")
	svc := server.NewService(pluginCatalog, a.ErrorCh)

	endpoints := server.Endpoints{
		PluginInfoEndpoint: server.MakePluginInfoEndpoint(svc),
		StopEndpoint:       server.MakeStopEndpoint(svc),
	}

	go func() {
		listener, err := net.Listen("tcp", a.Config.BindAddress)
		if err != nil {
			a.ErrorCh <- err
			return
		}

		gRPCServer := grpc.NewServer()
		handler := server.MakeGRPCServer(endpoints)

		sriplugin.RegisterServerServer(gRPCServer, handler)
		a.ErrorCh <- gRPCServer.Serve(listener)
	}()

	return
}

func (a *Agent) bootstrap() error {
	a.Config.Log.Info("Bootstrapping SPIRE agent")

	keyManager, err := a.Catalog.KeyManager()
	if err != nil {
		return err
	}

	// Fetch or generate private key
	a.Config.Log.Debug("Calling the key manager plugin")
	res, err := keyManager.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		return err
	}
	if len(res.PrivateKey) > 0 {
		a.Config.Log.Debug("Key recovered from the manager")

		key, err := x509.ParseECPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}

		err := a.LoadBaseSVID()
		if err != nil {
			return err
		}
		a.key = key
	} else {
		if a.Certificate != nil {
			a.Config.Log.Warn("Certificate configured but no private key found")
		}

		a.Config.Log.Info("Generating private key for new base SVID")
		res, err := keyManager.GenerateKeyPair(&GenerateKeyPairRequest{})
		if err != nil {
			return fmt.Errorf("Failed to generate private key: %s", err)
		}
		key, err = x509.ParseECPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}
		a.key = key

		// If we're here, we need to Attest/Re-Attest
		return a.Attest()
	}

	a.Config.Log.Info("Bootstrapping done")
	return nil
}

// Attest the agent, obtain a new Base SVID
func (a *Agent) Attest() error {
	a.Config.Log.Info("Preparing to attest against %s", a.Config.ServerAddress)

	attestor, err := a.Catalog.NodeAttestor()
	if err != nil {
		return err
	}

	a.Config.Log.Debug("Calling the node attestor plugin")
	pluginResponse, err := attestor.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	if err != nil {
		return err
	}

	// Parse the SPIFFE ID, form a CSR with it
	id, err := url.Parse(pluginResponse.SpiffeId)
	if err != nil {
		return fmt.Errorf("Failed to form SPIFFE ID: %s", err)
	}
	csr, err := a.GenerateCSR(id)
	if err != nil {
		return fmt.Errorf("Failed to generate CSR for attestation: %s", err)
	}

	// Configure TLS
	// TODO: Pick better options here
	a.Config.Log.Debug("Connecting to the node api")
	tlsConfig := &tls.Config{
		RootCAs: a.Config.TrustBundle
	}
	dialOptions := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial(a.Config.ServerAddress, dialOptions)
	if err != nil {
		return fmt.Errorf("Could not connect to: %v", err)
	}
	defer conn.Close()
	c := node.NewNodeClient(conn)

	// Perform attestation
	req := &node.FetchBaseSVIDRequest{
		AttestedData: pluginResponse.AttestedData,
		Csr:          MarshalCSR(csr),
	}
	serverResponse, err := c.FetchBaseSvid(contex.Background(), req)
	if err != nil {
		return err
	}

	// Pull base SVID out of the response
	svids := serverResponse.SpiffeEntry.SvidMap.Map
	if len(svids) > 1 {
		a.Config.Log.Warn("More than one SVID received during attestation")
	}
	svid, ok := svids[id]
	if !ok {
		return fmt.Errorf("Base SVID not found in attestation response")
	}

	cert, ttl, err := DecodeSVIDEntry(svid)
	if err != nil {
		return err
	}
	a.BaseSVID = cert
	a.BaseSVIDTTL = ttl
	a.StoreBaseSVID()
	a.Config.Log.Info("Attestation complete")
	return nil
}

// Generate a CSR for the given SPIFFE ID
func (a *Agent) GenerateCSR(spiffeID url.URL) (x509.CertificateRequest, error) {
	a.Config.Log.Info("Generating a CSR for %s", spiffeID.String())

	uriSANs := spiffe.MarshalUriSANs([]string{spiffeID.String()})
	uriSANExtension := []pkix.Extension{{
		Id:       spiffe.OidExtensionSubjectAltName,
		Value:    uriSANs,
		Critical: true,
	}}

	csrData := x509.CertificateRequest{
		Subject:            a.Config.CertDN,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    uriSANExtension,
	}

	return x509.CreateCertificateRequest(rand.Reader, csrData, a.key)
}

// Read base SVID from data dir and load it
func (a *Agent) LoadBaseSVID() error {
	a.Config.Log.Debug("Loading base SVID from disk")

	certPath := path.Join(a.Config.DataDir, "base_svid.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		a.Config.Log.Debug("A base SVID could not be found. A new one will be generated")
		return nil
	}

	data, err := ioutil.ReadAll(certPath)
	if err != nil {
		return fmt.Errorf("Could not read Base SVID at path %s: %s", certPath, err)
	}

	pemData, _ := pem.Decode(data)
	if pemData == nil {
		return fmt.Errorf("Unable to parse Base SVID at path %s", certPath)
	}
	cert, err := x509.ParseCertificate(pemData)
	if err != nil {
		return fmt.Errorf("Could not parse Base SVID at path %s: %s", certPath, err)
	}

	a.BaseSVID = cert
	return nil
}

// Write base SVID to storage dir
func (a *Agent) StoreBaseSVID() {
	a.Config.Log.Debug("Writing the base SVID to disk")

	certPath := path.Join(a.Config.DataDir, "base_svid.crt")
	f, err := os.Create(certPath)
	defer f.Close()
	if err != nil {
		a.Config.Log.Warn("Unable to store Base SVID at path %s", certPath)
		return
	}

	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: a.BaseSVID})
	if err != nil {
		a.Config.Log.Warn("Unable to store Base SVID at path %s", certPath)
	}

	return
}

func DecodeSVIDEntry(svid node.Svid) (baseSVID *x509.Certificate, baseSVIDTTL int, err error) {
	block, rest := pem.Decode(baseSVID)
	if len(rest) > 0 {
		return nil, 0, errors.New("Could not decode SVID, extra data encountered")
	}

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, 0, err
	}

	return cert, svid.Ttl, nil
}

func MarshalCSR(csr x509.CertificateRequest) []byte {
	pemBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	return pem.EncodeToMemory(pemBlock)
}
