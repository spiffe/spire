package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"runtime"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints"

	_ "golang.org/x/net/trace"

	"google.golang.org/grpc"

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

	// If true enables profiling.
	ProfilingEnabled bool

	// Port used by the pprof web server when ProfilingEnabled == true
	ProfilingPort int

	// Frequency in seconds by which each profile file will be generated.
	ProfilingFreq int
}

type Server struct {
	Catalog    catalog.Catalog
	Config     *Config
	caManager  ca.Manager
	endpoints  endpoints.Server
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

	if s.Config.ProfilingEnabled {
		s.setupProfiling()
	}

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
	if s.endpoints != nil {
		s.endpoints.Shutdown()
	}

	if s.caManager != nil {
		s.caManager.Shutdown()
	}

	if s.Catalog != nil {
		s.Catalog.Stop()
	}

	return
}

func (s *Server) setupProfiling() {
	if runtime.MemProfileRate == 0 {
		s.Config.Log.Warn("Memory profiles are disabled")
	}
	if s.Config.ProfilingPort > 0 {
		grpc.EnableTracing = true
		go func() {
			addr := fmt.Sprintf("localhost:%d", s.Config.ProfilingPort)
			s.Config.Log.Info(http.ListenAndServe(addr, nil))
		}()
	}
	if s.Config.ProfilingFreq > 0 {
		c := &profiling.Config{
			Tag:                    "server",
			Frequency:              s.Config.ProfilingFreq,
			DebugLevel:             0,
			RunGCBeforeHeapProfile: true,
			Profiles:               []string{"goroutine", "threadcreate", "heap", "block", "mutex", "trace", "cpu"},
		}
		err := profiling.Start(c)
		if err != nil {
			s.Config.Log.Error("Profiler failed to start: %v", err)
			return
		}
		s.t.Go(s.stopProfiling)
	}
}

func (s *Server) stopProfiling() error {
	<-s.t.Dying()
	profiling.Stop()
	return nil
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

	s.endpoints = endpoints.New(c)
	s.m.Unlock()

	s.t.Go(s.endpoints.ListenAndServe)

	<-s.t.Dying()
	s.endpoints.Shutdown()

	return nil
}
