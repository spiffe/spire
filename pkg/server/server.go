package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"net/url"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/upstreamca"

	"gopkg.in/tomb.v2"
)

type Config struct {
	// Directory for plugin configs
	PluginDir string

	Log logrus.FieldLogger

	// Address of SPIRE server
	BindAddress *net.TCPAddr

	// Address of the HTTP SPIRE server
	BindHTTPAddress *net.TCPAddr

	// Trust domain
	TrustDomain url.URL

	// Umask value to use
	Umask int
}

type Server struct {
	Catalog    catalog.Catalog
	Config     *Config
	endpoints  endpoints.Server
	privateKey *ecdsa.PrivateKey
	svid       *x509.Certificate

	m *sync.RWMutex
	t *tomb.Tomb
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks until it's shut down or an error is encountered.
func (server *Server) Run() error {
	if server.t == nil {
		server.t = new(tomb.Tomb)
	}

	server.t.Go(server.run)

	return server.t.Wait()
}

func (server *Server) run() error {
	server.prepareUmask()

	if server.m == nil {
		server.m = new(sync.RWMutex)
	}

	err := server.initPlugins()
	if err != nil {
		return err
	}

	err = server.rotateSigningCert()
	if err != nil {
		server.Catalog.Stop()
		return err
	}

	server.t.Go(server.startEndpoints)

	<-server.t.Dying()
	if server.t.Err() != nil {
		server.Config.Log.Errorf("fatal: %v", server.t.Err())
	}

	server.shutdown()
	return nil
}

func (server *Server) Shutdown() {
	server.t.Kill(nil)
}

func (server *Server) shutdown() {
	if server.endpoints != nil {
		server.endpoints.Shutdown()
	}

	if server.Catalog != nil {
		server.Catalog.Stop()
	}

	return
}

func (server *Server) prepareUmask() {
	server.Config.Log.Debug("Setting umask to ", server.Config.Umask)
	syscall.Umask(server.Config.Umask)
}

func (server *Server) initPlugins() error {
	config := &catalog.Config{
		ConfigDir: server.Config.PluginDir,
		Log:       server.Config.Log.WithField("subsystem_name", "catalog"),
	}

	server.Catalog = catalog.New(config)

	err := server.Catalog.Run()
	if err != nil {
		return err
	}

	server.Config.Log.Info("plugins started")
	return nil
}

func (server *Server) startEndpoints() error {
	server.m.Lock()

	c := &endpoints.Config{
		GRPCAddr:    server.Config.BindAddress,
		HTTPAddr:    server.Config.BindHTTPAddress,
		TrustDomain: server.Config.TrustDomain,
		Catalog:     server.Catalog,
		Log:         server.Config.Log.WithField("subsystem_name", "endpoints"),
	}

	server.endpoints = endpoints.New(c)
	server.m.Unlock()

	server.t.Go(server.endpoints.ListenAndServe)

	<-server.t.Dying()
	server.endpoints.Shutdown()

	return nil
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
