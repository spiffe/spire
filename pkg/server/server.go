package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"runtime"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints"
	"github.com/spiffe/spire/pkg/server/svid"
	"google.golang.org/grpc"

	_ "golang.org/x/net/trace"
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

	// Include upstream CA certificates in the bundle
	UpstreamBundle bool

	// If true enables profiling.
	ProfilingEnabled bool

	// Port used by the pprof web server when ProfilingEnabled == true
	ProfilingPort int

	// Frequency in seconds by which each profile file will be generated.
	ProfilingFreq int

	// Array of profiles names that will be generated on each profiling tick.
	ProfilingNames []string
}

type Server struct {
	config Config
}

func New(config Config) *Server {
	return &Server{
		config: config,
	}
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks until it's shut down or an error is encountered.
func (s *Server) Run(ctx context.Context) error {
	s.prepareUmask()

	if err := s.run(ctx); err != nil {
		s.config.Log.Errorf("fatal: %v", err)
		return err
	}
	return nil
}

func (s *Server) run(ctx context.Context) (err error) {
	if s.config.ProfilingEnabled {
		stopProfiling := s.setupProfiling(ctx)
		defer stopProfiling()
	}

	cat := s.newCatalog()
	defer cat.Stop()

	if err := cat.Run(ctx); err != nil {
		return err
	}
	s.config.Log.Info("plugins started")

	// CA manager needs to be initialized before the rotator, otherwise the
	// server CA plugin won't be able to sign CSRs
	caManager, err := s.newCAManager(ctx, cat)
	if err != nil {
		return err
	}

	svidRotator, err := s.newSVIDRotator(ctx, cat)
	if err != nil {
		return err
	}

	endpointsServer := s.newEndpointsServer(cat, svidRotator)

	err = util.RunTasks(ctx,
		caManager.Run,
		svidRotator.Run,
		endpointsServer.ListenAndServe,
	)
	if err == context.Canceled {
		err = nil
	}
	return err
}

func (s *Server) setupProfiling(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup

	if runtime.MemProfileRate == 0 {
		s.config.Log.Warn("Memory profiles are disabled")
	}
	if s.config.ProfilingPort > 0 {
		grpc.EnableTracing = true

		server := http.Server{
			Addr:    fmt.Sprintf("localhost:%d", s.config.ProfilingPort),
			Handler: http.HandlerFunc(pprof.Index),
		}

		// kick off a goroutine to serve the pprof endpoints and one to
		// gracefully shut down the server when profiling is being torn down
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.ListenAndServe(); err != nil {
				s.config.Log.Warnf("unable to serve profiling server: %v", err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			server.Shutdown(ctx)
		}()
	}
	if s.config.ProfilingFreq > 0 {
		c := &profiling.Config{
			Tag:                    "server",
			Frequency:              s.config.ProfilingFreq,
			DebugLevel:             0,
			RunGCBeforeHeapProfile: true,
			Profiles:               s.config.ProfilingNames,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := profiling.Run(ctx, c); err != nil {
				s.config.Log.Warnf("Failed to run profiling: %v", err)
			}
		}()
	}

	return func() {
		cancel()
		wg.Wait()
	}
}

func (s *Server) prepareUmask() {
	s.config.Log.Debugf("Setting umask to %#o", s.config.Umask)
	syscall.Umask(s.config.Umask)
}

func (s *Server) newCatalog() catalog.Catalog {
	return catalog.New(&catalog.Config{
		PluginConfigs: s.config.PluginConfigs,
		Log:           s.config.Log.WithField("subsystem_name", "catalog"),
	})
}

func (s *Server) newCAManager(ctx context.Context, catalog catalog.Catalog) (ca.Manager, error) {
	caManager := ca.New(&ca.Config{
		Catalog:        catalog,
		TrustDomain:    s.config.TrustDomain,
		Log:            s.config.Log.WithField("subsystem_name", "ca_manager"),
		UpstreamBundle: s.config.UpstreamBundle,
	})
	if err := caManager.Initialize(ctx); err != nil {
		return nil, err
	}
	return caManager, nil
}

func (s *Server) newSVIDRotator(ctx context.Context, catalog catalog.Catalog) (svid.Rotator, error) {
	svidRotator := svid.NewRotator(&svid.RotatorConfig{
		Catalog:     catalog,
		Log:         s.config.Log.WithField("subsystem_name", "svid_rotator"),
		TrustDomain: s.config.TrustDomain,
	})
	if err := svidRotator.Initialize(ctx); err != nil {
		return nil, err
	}
	return svidRotator, nil
}

func (s *Server) newEndpointsServer(catalog catalog.Catalog, svidRotator svid.Rotator) endpoints.Server {
	return endpoints.New(&endpoints.Config{
		GRPCAddr:    s.config.BindAddress,
		HTTPAddr:    s.config.BindHTTPAddress,
		SVIDStream:  svidRotator.Subscribe(),
		TrustDomain: s.config.TrustDomain,
		Catalog:     catalog,
		Log:         s.config.Log.WithField("subsystem_name", "endpoints"),
	})
}
