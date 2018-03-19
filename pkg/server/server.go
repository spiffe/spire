package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"net/url"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints"
	tomb "gopkg.in/tomb.v2"
)

type Config struct {
	// Configurations for server plugins
	PluginConfigs common.PluginConfigMap

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
	Endpoints  endpoints.Server
	caManager  ca.Manager
	privateKey *ecdsa.PrivateKey
	svid       *x509.Certificate

	m *sync.RWMutex
	t *tomb.Tomb
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks until it's shut down or an error is encountered.
func (s *Server) Run() error {
	if s.t == nil {
		s.t = new(tomb.Tomb)
	}

	if s.m == nil {
		s.m = new(sync.RWMutex)
	}

	s.t.Go(s.run)

	return s.t.Wait()
}

func (s *Server) run() error {
	s.prepareUmask()

	err := s.initPlugins()
	if err != nil {
		return err
	}

	err = s.startCAManager()
	if err != nil {
		s.Catalog.Stop()
		return err
	}

	s.t.Go(s.caManager.Wait)
	s.t.Go(s.startEndpoints)

	<-s.t.Dying()
	if s.t.Err() != nil {
		s.Config.Log.Errorf("fatal: %v", s.t.Err())
	}

	s.shutdown()
	return nil
}

func (s *Server) Shutdown() {
	s.t.Kill(nil)
}

func (s *Server) shutdown() {
	if s.Endpoints != nil {
		s.Endpoints.Shutdown()
	}

	if s.caManager != nil {
		s.caManager.Shutdown()
	}

	if s.Catalog != nil {
		s.Catalog.Stop()
	}

	return
}

func (s *Server) prepareUmask() {
	s.Config.Log.Debug("Setting umask to ", s.Config.Umask)
	syscall.Umask(s.Config.Umask)
}

func (s *Server) initPlugins() error {
	config := &catalog.Config{
		PluginConfigs: s.Config.PluginConfigs,
		Log:           s.Config.Log.WithField("subsystem_name", "catalog"),
	}

	s.Catalog = catalog.New(config)

	err := s.Catalog.Run()
	if err != nil {
		return err
	}

	s.Config.Log.Info("plugins started")
	return nil
}

func (s *Server) startCAManager() error {
	s.m.Lock()
	defer s.m.Unlock()

	config := &ca.Config{
		Catalog:     s.Catalog,
		TrustDomain: s.Config.TrustDomain,
		Log:         s.Config.Log.WithField("subsystem_name", "ca_manager"),
	}

	s.caManager = ca.New(config)
	return s.caManager.Start()
}

func (s *Server) startEndpoints() error {
	s.m.Lock()

	c := &endpoints.Config{
		GRPCAddr:    s.Config.BindAddress,
		HTTPAddr:    s.Config.BindHTTPAddress,
		TrustDomain: s.Config.TrustDomain,
		Catalog:     s.Catalog,
		Log:         s.Config.Log.WithField("subsystem_name", "endpoints"),
	}

	s.Endpoints = endpoints.New(c)
	s.m.Unlock()

	s.t.Go(s.Endpoints.ListenAndServe)

	<-s.t.Dying()
	s.Endpoints.Shutdown()

	return nil
}
