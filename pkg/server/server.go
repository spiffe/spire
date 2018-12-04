package server

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/server/datastore"
	"google.golang.org/grpc"
)

const (
	invalidTrustDomainAttestedNode = "An attested node with trust domain '%v' has been detected, " +
		"which does not match the configured trust domain of '%v'. Agents may need to be reconfigured to use new trust domain"

	invalidTrustDomainRegistrationEntry = "A registration entry with trust domain '%v' has been detected, " +
		"which does not match the configured trust domain of '%v'. If you want to change the trust domain, " +
		"please delete all existing registration entries"

	pageSize = 10
)

type Config struct {
	// Configurations for server plugins
	PluginConfigs common.PluginConfigMap

	Log logrus.FieldLogger

	// Address of SPIRE server
	BindAddress *net.TCPAddr

	// Address of the UDS SPIRE server
	BindUDSAddress *net.UnixAddr

	// Directory to store runtime data
	DataDir string

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

	// SVIDTTL is default time-to-live for SVIDs
	SVIDTTL time.Duration

	// CATTL is the time-to-live for the server CA. This only applies to
	// self-signed CA certificates, otherwise it is up to the upstream CA.
	CATTL time.Duration

	// CASubject is the subject used in the CA certificate
	CASubject pkix.Name
}

type Server struct {
	config Config
}

func New(config Config) *Server {
	return &Server{
		config: config,
	}
}

func (c *Config) GlobalConfig() *common.GlobalConfig {
	return &common.GlobalConfig{
		TrustDomain: c.TrustDomain.Host,
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
	// create the data directory if needed
	s.config.Log.Infof("data directory: %q", s.config.DataDir)
	if err := os.MkdirAll(s.config.DataDir, 0755); err != nil {
		return err
	}

	if s.config.ProfilingEnabled {
		stopProfiling := s.setupProfiling(ctx)
		defer stopProfiling()
	}

	metrics := telemetry.NewMetrics(&telemetry.MetricsConfig{
		Logger:      s.config.Log.WithField("subsystem_name", "telemetry").Writer(),
		ServiceName: "spire_server",
	})
	defer metrics.Stop()

	cat := s.newCatalog()
	defer cat.Stop()

	if err := cat.Run(ctx); err != nil {
		return err
	}
	s.config.Log.Info("plugins started")

	err = s.validateTrustDomain(ctx, cat.DataStores()[0])
	if err != nil {
		return err
	}

	// CA manager needs to be initialized before the rotator, otherwise the
	// server CA plugin won't be able to sign CSRs
	caManager, err := s.newCAManager(ctx, cat, metrics)
	if err != nil {
		return err
	}

	serverCA := caManager.CA()

	svidRotator, err := s.newSVIDRotator(ctx, serverCA, metrics)
	if err != nil {
		return err
	}

	endpointsServer := s.newEndpointsServer(cat, svidRotator, serverCA, metrics)

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

func (s *Server) newCatalog() *catalog.ServerCatalog {
	return catalog.New(&catalog.Config{
		GlobalConfig:  s.config.GlobalConfig(),
		PluginConfigs: s.config.PluginConfigs,
		Log:           s.config.Log.WithField("subsystem_name", "catalog"),
	})
}

func (s *Server) newCAManager(ctx context.Context, catalog catalog.Catalog, metrics telemetry.Metrics) (ca.Manager, error) {
	caManager := ca.NewManager(&ca.ManagerConfig{
		Catalog:        catalog,
		TrustDomain:    s.config.TrustDomain,
		Log:            s.config.Log.WithField("subsystem_name", "ca_manager"),
		Metrics:        metrics,
		UpstreamBundle: s.config.UpstreamBundle,
		SVIDTTL:        s.config.SVIDTTL,
		CATTL:          s.config.CATTL,
		CASubject:      s.config.CASubject,
		CertsPath:      s.caCertsPath(),
	})
	if err := caManager.Initialize(ctx); err != nil {
		return nil, err
	}
	return caManager, nil
}

func (s *Server) newSVIDRotator(ctx context.Context, serverCA ca.ServerCA, metrics telemetry.Metrics) (svid.Rotator, error) {
	svidRotator := svid.NewRotator(&svid.RotatorConfig{
		ServerCA:    serverCA,
		Log:         s.config.Log.WithField("subsystem_name", "svid_rotator"),
		Metrics:     metrics,
		TrustDomain: s.config.TrustDomain,
	})
	if err := svidRotator.Initialize(ctx); err != nil {
		return nil, err
	}
	return svidRotator, nil
}

func (s *Server) newEndpointsServer(catalog catalog.Catalog, svidRotator svid.Rotator, serverCA ca.ServerCA, metrics telemetry.Metrics) endpoints.Server {
	return endpoints.New(&endpoints.Config{
		GRPCAddr:    s.config.BindAddress,
		UDSAddr:     s.config.BindUDSAddress,
		SVIDStream:  svidRotator.Subscribe(),
		TrustDomain: s.config.TrustDomain,
		Catalog:     catalog,
		ServerCA:    serverCA,
		Log:         s.config.Log.WithField("subsystem_name", "endpoints"),
		Metrics:     metrics,
	})
}

func (s *Server) caCertsPath() string {
	return path.Join(s.config.DataDir, "certs.json")
}

func (s *Server) validateTrustDomain(ctx context.Context, ds datastore.DataStore) error {
	trustDomain := s.config.TrustDomain.Host

	var token uint32
	// Repeat until no more results are returned
	for {
		fetchResponse, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: pageSize,
			}})

		if err != nil {
			return err
		}

		// no entries, finish iteration
		if len(fetchResponse.Entries) == 0 {
			break
		}

		for _, entry := range fetchResponse.Entries {
			id, err := url.Parse(entry.SpiffeId)
			if err != nil {
				return fmt.Errorf("registration entry with id %v is malformed because invalid spiffe id: %v", entry.EntryId, err)
			}

			if id.Host != trustDomain {
				return fmt.Errorf(invalidTrustDomainRegistrationEntry, id.Host, trustDomain)
			}
		}

		token = fetchResponse.Pagination.Token
	}

	nodesResponse, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{})
	if err != nil {
		return err
	}

	for _, node := range nodesResponse.Nodes {
		id, err := url.Parse(node.SpiffeId)
		if err != nil {
			s.config.Log.Warn("could not parse SPIFFE ID from node: %v", err)
			continue
		}

		if id.Host != trustDomain {
			msg := fmt.Sprintf(invalidTrustDomainAttestedNode, id.Host, trustDomain)
			s.config.Log.Warn(msg)
		}
	}
	return nil
}
