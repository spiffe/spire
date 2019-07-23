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
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/hostservices/metricsservice"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	bundle_client "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints"
	"github.com/spiffe/spire/pkg/server/hostservices/agentstore"
	"github.com/spiffe/spire/pkg/server/hostservices/identityprovider"
	"github.com/spiffe/spire/pkg/server/svid"
	common_services "github.com/spiffe/spire/proto/spire/common/hostservices"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"google.golang.org/grpc"
)

const (
	invalidTrustDomainAttestedNode = "An attested node with trust domain '%v' has been detected, " +
		"which does not match the configured trust domain of '%v'. Agents may need to be reconfigured to use new trust domain"
	invalidTrustDomainRegistrationEntry = "A registration entry with trust domain '%v' has been detected, " +
		"which does not match the configured trust domain of '%v'. If you want to change the trust domain, " +
		"please delete all existing registration entries"
	invalidSpiffeIDRegistrationEntry = "registration entry with id %v is malformed because invalid SPIFFE ID: %v"
	invalidSpiffeIDAttestedNode      = "could not parse SPIFFE ID, from attested node"

	pageSize = 1
)

type Config struct {
	// Configurations for server plugins
	PluginConfigs common.HCLPluginConfigMap

	Log logrus.FieldLogger

	// Address of SPIRE server
	BindAddress *net.TCPAddr

	// Address of the UDS SPIRE server
	BindUDSAddress *net.UnixAddr

	// Directory to store runtime data
	DataDir string

	// Trust domain
	TrustDomain url.URL

	UpstreamBundle bool

	Experimental ExperimentalConfig

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

	// Telemetry provides the configuration for metrics exporting
	Telemetry telemetry.FileConfig

	// HealthChecks provides the configuration for health monitoring
	HealthChecks health.Config
}

type ExperimentalConfig struct {
	// Skip agent id validation in node attestation
	AllowAgentlessNodeAttestors bool

	// BundleEndpointEnabled, if true, enables the federation bundle endpoint
	BundleEndpointEnabled bool

	// BundleEndpointAddress is the address on which to serve the federation
	// bundle endpoint.
	BundleEndpointAddress *net.TCPAddr

	// FederatesWith holds the federation configuration for trust domains this
	// server federates with.
	FederatesWith map[string]bundle_client.TrustDomainConfig
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
	if err := s.run(ctx); err != nil {
		s.config.Log.WithError(err).Error("fatal run error")
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

	metrics, err := telemetry.NewMetrics(&telemetry.MetricsConfig{
		FileConfig:  s.config.Telemetry,
		Logger:      s.config.Log.WithField(telemetry.SubsystemName, telemetry.Telemetry),
		ServiceName: "spire_server",
	})
	if err != nil {
		return err
	}
	metricsService := metricsservice.New(metricsservice.Config{
		Metrics: metrics,
	})

	// Create the identity provider host service. It will not be functional
	// until the call to SetDeps() below. There is some tricky initialization
	// stuff going on since the identity provider host service requires plugins
	// to do its job. RPC's from plugins to the identity provider before
	// SetDeps() has been called will fail with a PreCondition status.
	identityProvider := identityprovider.New(identityprovider.Config{
		TrustDomainID: s.config.TrustDomain.String(),
	})

	// Create the agent store host service. It will not be functional
	// until the call to SetDeps() below.
	agentStore := agentstore.New()

	cat, err := s.loadCatalog(ctx, identityProvider, agentStore, metricsService)
	if err != nil {
		return err
	}
	defer cat.Close()

	healthChecks := health.NewChecker(
		s.config.HealthChecks,
		s.config.Log.WithField("subsystem_name", "health"),
	)

	s.config.Log.Info("plugins started")

	err = s.validateTrustDomain(ctx, cat.GetDataStore())
	if err != nil {
		return err
	}

	serverCA := s.newCA(metrics)

	// CA manager needs to be initialized before the rotator, otherwise the
	// server CA plugin won't be able to sign CSRs
	caManager, err := s.newCAManager(ctx, cat, metrics, serverCA)
	if err != nil {
		return err
	}

	svidRotator, err := s.newSVIDRotator(ctx, serverCA, metrics)
	if err != nil {
		return err
	}

	endpointsServer := s.newEndpointsServer(cat, svidRotator, serverCA, metrics)

	// Set the identity provider dependencies
	if err := identityProvider.SetDeps(identityprovider.Deps{
		DataStore: cat.GetDataStore(),
		X509IdentityFetcher: identityprovider.X509IdentityFetcherFunc(func(context.Context) (*identityprovider.X509Identity, error) {
			// Return the server identity itself
			state := svidRotator.State()
			return &identityprovider.X509Identity{
				CertChain:  state.SVID,
				PrivateKey: state.Key,
			}, nil
		}),
	}); err != nil {
		return fmt.Errorf("failed setting IdentityProvider deps: %v", err)
	}

	// Set the agent store dependencies
	if err := agentStore.SetDeps(agentstore.Deps{
		DataStore: cat.GetDataStore(),
	}); err != nil {
		return fmt.Errorf("failed setting AgentStore deps: %v", err)
	}

	bundleManager := s.newBundleManager(cat)

	if err := healthChecks.AddCheck("server", s, time.Minute); err != nil {
		return fmt.Errorf("failed adding healthcheck: %v", err)
	}

	err = util.RunTasks(ctx,
		caManager.Run,
		svidRotator.Run,
		endpointsServer.ListenAndServe,
		metrics.ListenAndServe,
		bundleManager.Run,
		healthChecks.ListenAndServe,
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
				s.config.Log.WithError(err).Warn("unable to serve profiling server")
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
				s.config.Log.WithError(err).Warn("Failed to run profiling")
			}
		}()
	}

	return func() {
		cancel()
		wg.Wait()
	}
}

func (s *Server) loadCatalog(ctx context.Context, identityProvider hostservices.IdentityProvider, agentStore hostservices.AgentStore,
	metricsService common_services.MetricsService) (*catalog.CatalogCloser, error) {
	return catalog.Load(ctx, catalog.Config{
		Log: s.config.Log.WithField(telemetry.SubsystemName, telemetry.Catalog),
		GlobalConfig: catalog.GlobalConfig{
			TrustDomain: s.config.TrustDomain.Host,
		},
		PluginConfig:     s.config.PluginConfigs,
		IdentityProvider: identityProvider,
		AgentStore:       agentStore,
		MetricsService:   metricsService,
	})
}

func (s *Server) newCA(metrics telemetry.Metrics) *ca.CA {
	return ca.NewCA(ca.CAConfig{
		Log:         s.config.Log.WithField(telemetry.SubsystemName, telemetry.CA),
		Metrics:     metrics,
		X509SVIDTTL: s.config.SVIDTTL,
		TrustDomain: s.config.TrustDomain,
		CASubject:   s.config.CASubject,
	})
}

func (s *Server) newCAManager(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics, serverCA *ca.CA) (*ca.Manager, error) {
	caManager := ca.NewManager(ca.ManagerConfig{
		CA:             serverCA,
		Catalog:        cat,
		TrustDomain:    s.config.TrustDomain,
		Log:            s.config.Log.WithField(telemetry.SubsystemName, telemetry.CAManager),
		Metrics:        metrics,
		UpstreamBundle: s.config.UpstreamBundle,
		CATTL:          s.config.CATTL,
		CASubject:      s.config.CASubject,
		Dir:            s.config.DataDir,
	})
	if err := caManager.Initialize(ctx); err != nil {
		return nil, err
	}
	return caManager, nil
}

func (s *Server) newSVIDRotator(ctx context.Context, serverCA ca.ServerCA, metrics telemetry.Metrics) (svid.Rotator, error) {
	svidRotator := svid.NewRotator(&svid.RotatorConfig{
		ServerCA:    serverCA,
		Log:         s.config.Log.WithField(telemetry.SubsystemName, telemetry.SVIDRotator),
		Metrics:     metrics,
		TrustDomain: s.config.TrustDomain,
	})
	if err := svidRotator.Initialize(ctx); err != nil {
		return nil, err
	}
	return svidRotator, nil
}

func (s *Server) newEndpointsServer(catalog catalog.Catalog, svidObserver svid.Observer, serverCA ca.ServerCA, metrics telemetry.Metrics) endpoints.Server {
	config := &endpoints.Config{
		TCPAddr:                     s.config.BindAddress,
		UDSAddr:                     s.config.BindUDSAddress,
		SVIDObserver:                svidObserver,
		TrustDomain:                 s.config.TrustDomain,
		Catalog:                     catalog,
		ServerCA:                    serverCA,
		Log:                         s.config.Log.WithField(telemetry.SubsystemName, telemetry.Endpoints),
		Metrics:                     metrics,
		AllowAgentlessNodeAttestors: s.config.Experimental.AllowAgentlessNodeAttestors,
	}
	if s.config.Experimental.BundleEndpointEnabled {
		config.BundleEndpointAddress = s.config.Experimental.BundleEndpointAddress
	}
	return endpoints.New(config)
}

func (s *Server) newBundleManager(cat catalog.Catalog) *bundle_client.Manager {
	return bundle_client.NewManager(bundle_client.ManagerConfig{
		Log:          s.config.Log.WithField("subsystem_name", "bundle_client"),
		DataStore:    cat.GetDataStore(),
		TrustDomains: s.config.Experimental.FederatesWith,
	})
}

func (s *Server) validateTrustDomain(ctx context.Context, ds datastore.DataStore) error {
	trustDomain := s.config.TrustDomain.Host

	// Get only first page with a single element
	fetchResponse, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "",
			PageSize: pageSize,
		}})

	if err != nil {
		return err
	}

	for _, entry := range fetchResponse.Entries {
		id, err := url.Parse(entry.SpiffeId)
		if err != nil {
			return fmt.Errorf(invalidSpiffeIDRegistrationEntry, entry.EntryId, err)
		}

		if id.Host != trustDomain {
			return fmt.Errorf(invalidTrustDomainRegistrationEntry, id.Host, trustDomain)
		}
	}

	// Get only first page with a single element
	nodesResponse, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		Pagination: &datastore.Pagination{
			Token:    "",
			PageSize: pageSize,
		}})
	if err != nil {
		return err
	}

	for _, node := range nodesResponse.Nodes {
		id, err := url.Parse(node.SpiffeId)
		if err != nil {
			s.config.Log.WithError(err).WithField(telemetry.SPIFFEID, node.SpiffeId).Warn(invalidSpiffeIDAttestedNode)
			continue
		}

		if id.Host != trustDomain {
			msg := fmt.Sprintf(invalidTrustDomainAttestedNode, id.Host, trustDomain)
			s.config.Log.Warn(msg)
		}
	}
	return nil
}

// Status is used as a top-level health check for the Server.
func (s *Server) Status() (interface{}, error) {
	return nil, nil
}
