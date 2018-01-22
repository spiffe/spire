package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"path"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	commonCatalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoint"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Config struct {
	// TTL we will use when creating the Base SVID
	BaseSVIDTtl int32

	// TTL we will use when creating the Server SVID
	ServerSVIDTtl int32

	// Directory for plugin configs
	PluginDir string

	PluginConfigs map[string]map[string]commonCatalog.HclPluginConfig

	Log logrus.FieldLogger

	// Address of SPIRE server
	BindAddress *net.TCPAddr

	// Address of the HTTP SPIRE server
	BindHTTPAddress *net.TCPAddr

	// A channel for receiving errors from server goroutines
	ErrorCh chan error

	// A channel to trigger server shutdown
	ShutdownCh chan struct{}

	// Trust domain
	TrustDomain url.URL

	// Umask value to use
	Umask int
}

type Server struct {
	Catalog    catalog.Catalog
	Config     *Config
	endpoints  endpoint.Endpoint
	privateKey *ecdsa.PrivateKey
	svid       *x509.Certificate
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks on the main event loop.
func (server *Server) Run() error {
	server.prepareUmask()

	err := server.initPlugins()
	if err != nil {
		return err
	}

	err = server.rotateSigningCert()
	if err != nil {
		return err
	}

	server.svid, server.privateKey, err = server.rotateSVID()
	if err != nil {
		return err
	}

	err = server.initEndpoints()
	if err != nil {
		return err
	}

	// Main event loop
	server.Config.Log.Info("SPIRE Server is now running")

	for {
		select {
		case err = <-server.Config.ErrorCh:
			return err
		case <-server.Config.ShutdownCh:
			return server.Shutdown()
		}
	}
}

func (server *Server) Shutdown() error {
	if server.endpoints != nil {
		server.endpoints.Shutdown()
	}

	if server.Catalog != nil {
		server.Catalog.Stop()
	}

	// Unblock closing endpoints
	return <-server.Config.ErrorCh
}

func (server *Server) prepareUmask() {
	server.Config.Log.Debug("Setting umask to ", server.Config.Umask)
	syscall.Umask(server.Config.Umask)
}

func (server *Server) initPlugins() error {
	config := &catalog.Config{
		ConfigDir:     server.Config.PluginDir,
		PluginConfigs: server.Config.PluginConfigs,
		Log:           server.Config.Log.WithField("subsystem_name", "catalog"),
	}

	server.Catalog = catalog.New(config)

	err := server.Catalog.Run()
	if err != nil {
		return err
	}

	server.Config.Log.Info("Starting plugins done")

	return nil
}

func (server *Server) initEndpoints() error {
	ns := &nodeServer{
		l:           server.Config.Log,
		catalog:     server.Catalog,
		trustDomain: server.Config.TrustDomain,
		baseSVIDTtl: server.Config.BaseSVIDTtl,
	}

	rs := &registrationServer{
		l:       server.Config.Log,
		catalog: server.Catalog,
	}

	log := server.Config.Log.WithField("subsystem_name", "endpoint")
	cert, err := server.signingCert()
	if err != nil {
		return err
	}

	c := &endpoint.Config{
		NS:       ns,
		RS:       rs,
		GRPCAddr: server.Config.BindAddress,
		HTTPAddr: server.Config.BindHTTPAddress,
		SVID:     server.svid,
		SVIDKey:  server.privateKey,
		CACert:   cert,
		Log:      log,
	}

	server.endpoints = endpoint.New(c)
	go func() { server.Config.ErrorCh <- server.endpoints.ListenAndServe() }()
	return nil
}

func (server *Server) rotateSVID() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   server.Config.TrustDomain.Host,
		Path:   path.Join("spiffe", "cp"),
	}

	l := server.Config.Log.WithField("SPIFFE_ID", spiffeID.String())
	l.Info("Rotating SPIRE server SVID")

	uriSAN, err := uri.MarshalUriSANs([]string{spiffeID.String()})
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	req := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{{
			Id:       uri.OidExtensionSubjectAltName,
			Value:    uriSAN,
			Critical: false,
		}},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, nil, err
	}

	l.Debug("Sending CSR to the CA plugin")
	serverCA := server.Catalog.CAs()[0]
	res, err := serverCA.SignCsr(
		&ca.SignCsrRequest{Csr: csr, Ttl: server.Config.ServerSVIDTtl})
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(res.SignedCertificate)
	if err != nil {
		return nil, nil, err
	}

	l.Debug("SPIRE server SVID rotation complete")
	return cert, key, nil
}

func (server *Server) rotateSigningCert() error {
	server.Config.Log.Info("Initiating rotation of signing certificate")

	serverCA := server.Catalog.CAs()[0]
	csrRes, err := serverCA.GenerateCsr(&ca.GenerateCsrRequest{})
	if err != nil {
		return err
	}
	upstreamCA := server.Catalog.UpstreamCAs()[0]
	signRes, err := upstreamCA.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return err
	}

	req := &ca.LoadCertificateRequest{SignedIntermediateCert: signRes.Cert}
	_, err = serverCA.LoadCertificate(req)

	return err
}

func (server *Server) signingCert() (*x509.Certificate, error) {
	c := server.Catalog.CAs()[0]
	res, err := c.FetchCertificate(&ca.FetchCertificateRequest{})
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(res.StoredIntermediateCert)
}
