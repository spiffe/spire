package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint: gosec // import registers routes on DefaultServeMux
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	server_util "github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/uptime"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	bundle_client "github.com/spiffe/spire/pkg/server/bundle/client"
	ds_pubmanager "github.com/spiffe/spire/pkg/server/bundle/datastore"
	"github.com/spiffe/spire/pkg/server/bundle/pubmanager"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/ca/rotator"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/endpoints"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
	"github.com/spiffe/spire/pkg/server/hostservice/identityprovider"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/pkg/server/registration"
	"github.com/spiffe/spire/pkg/server/svid"
	"google.golang.org/grpc"
)

const (
	invalidTrustDomainAttestedNode = "An attested node with trust domain '%v' has been detected, " +
		"which does not match the configured trust domain of '%v'. Agents may need to be reconfigured to use new trust domain"
	invalidTrustDomainRegistrationEntry = "a registration entry with trust domain '%v' has been detected, " +
		"which does not match the configured trust domain of '%v'. If you want to change the trust domain, " +
		"please delete all existing registration entries"
	invalidSpiffeIDRegistrationEntry = "registration entry with id %v is malformed because invalid SPIFFE ID: %v"
	invalidSpiffeIDAttestedNode      = "could not parse SPIFFE ID, from attested node"

	pageSize = 1
)

type Server struct {
	config Config
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks until it's shut down or an error is encountered.
func (s *Server) Run(ctx context.Context) error {
	if err := s.run(ctx); err != nil {
		s.config.Log.WithError(err).Error("Fatal run error")
		return err
	}
	return nil
}

func (s *Server) run(ctx context.Context) (err error) {
	// Log configuration values that are useful for debugging
	s.config.Log.WithFields(logrus.Fields{
		telemetry.AdminIDs:       s.config.AdminIDs,
		telemetry.DataDir:        s.config.DataDir,
		telemetry.LaunchLogLevel: s.config.Log.GetLevel(),
	}).Info("Configured")

	// create the data directory if needed
	if err := diskutil.CreateDataDirectory(s.config.DataDir); err != nil {
		return err
	}

	if s.config.ProfilingEnabled {
		stopProfiling := s.setupProfiling(ctx)
		defer stopProfiling()
	}

	metrics, err := telemetry.NewMetrics(&telemetry.MetricsConfig{
		FileConfig:  s.config.Telemetry,
		Logger:      s.config.Log.WithField(telemetry.SubsystemName, telemetry.Telemetry),
		ServiceName: telemetry.SpireServer,
	})
	if err != nil {
		return err
	}

	telemetry.EmitStarted(metrics, s.config.TrustDomain)
	uptime.ReportMetrics(ctx, metrics)

	// Create the identity provider host service. It will not be functional
	// until the call to SetDeps() below. There is some tricky initialization
	// stuff going on since the identity provider host service requires plugins
	// to do its job. RPC's from plugins to the identity provider before
	// SetDeps() has been called will fail with a PreCondition status.
	identityProvider := identityprovider.New(identityprovider.Config{
		TrustDomain: s.config.TrustDomain,
	})

	healthChecker := health.NewChecker(s.config.HealthChecks, s.config.Log)

	// Create the agent store host service. It will not be functional
	// until the call to SetDeps() below.
	agentStore := agentstore.New()

	cat, err := s.loadCatalog(ctx, metrics, identityProvider, agentStore, healthChecker)
	if err != nil {
		return err
	}
	defer cat.Close()

	bundlePublishingManager, err := s.newBundlePublishingManager(cat.BundlePublishers, cat.DataStore)
	if err != nil {
		return err
	}
	cat.DataStore = ds_pubmanager.WithBundleUpdateCallback(cat.DataStore, bundlePublishingManager.BundleUpdated)

	err = s.validateTrustDomain(ctx, cat.GetDataStore())
	if err != nil {
		return err
	}

	credBuilder, err := s.newCredBuilder(cat)
	if err != nil {
		return err
	}

	credValidator, err := s.newCredValidator()
	if err != nil {
		return err
	}

	serverCA := s.newCA(metrics, credBuilder, credValidator, healthChecker)

	// CA manager needs to be initialized before the rotator, otherwise the
	// server CA plugin won't be able to sign CSRs
	caManager, err := s.newCAManager(ctx, cat, metrics, serverCA, credBuilder, credValidator)
	if err != nil {
		return err
	}
	defer caManager.Close()

	caSync, err := s.newCASync(ctx, healthChecker, caManager)
	if err != nil {
		return err
	}

	svidRotator, err := s.newSVIDRotator(ctx, serverCA, metrics)
	if err != nil {
		return err
	}

	authPolicyEngine, err := authpolicy.NewEngineFromConfigOrDefault(ctx, s.config.AuthOpaPolicyEngineConfig)
	if err != nil {
		return fmt.Errorf("unable to obtain authpolicy engine: %w", err)
	}

	bundleManager := s.newBundleManager(cat, metrics)

	endpointsServer, err := s.newEndpointsServer(ctx, cat, svidRotator, serverCA, metrics, caManager, authPolicyEngine, bundleManager)
	if err != nil {
		return err
	}

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
		return fmt.Errorf("failed setting IdentityProvider deps: %w", err)
	}

	// Set the agent store dependencies
	if err := agentStore.SetDeps(agentstore.Deps{
		DataStore: cat.GetDataStore(),
	}); err != nil {
		return fmt.Errorf("failed setting AgentStore deps: %w", err)
	}

	registrationManager := s.newRegistrationManager(cat, metrics)

	if err := healthChecker.AddCheck("server", s); err != nil {
		return fmt.Errorf("failed adding healthcheck: %w", err)
	}

	tasks := []func(context.Context) error{
		caSync.Run,
		svidRotator.Run,
		endpointsServer.ListenAndServe,
		metrics.ListenAndServe,
		bundleManager.Run,
		registrationManager.Run,
		bundlePublishingManager.Run,
		catalog.ReconfigureTask(s.config.Log.WithField(telemetry.SubsystemName, "reconfigurer"), cat),
		util.SerialRun(s.waitForTestDial, healthChecker.ListenAndServe),
	}

	if s.config.LogReopener != nil {
		tasks = append(tasks, s.config.LogReopener)
	}

	err = util.RunTasks(ctx, tasks...)
	if errors.Is(err, context.Canceled) {
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
			Addr:              fmt.Sprintf("localhost:%d", s.config.ProfilingPort),
			Handler:           http.DefaultServeMux,
			ReadHeaderTimeout: time.Second * 10,
		}

		// kick off a goroutine to serve the pprof endpoints and one to
		// gracefully shut down the server when profiling is being torn down
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.ListenAndServe(); err != nil {
				s.config.Log.WithError(err).Warn("Unable to serve profiling server")
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			if err := server.Shutdown(ctx); err != nil {
				s.config.Log.WithError(err).Warn("Unable to shutdown the server cleanly")
			}
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

func (s *Server) loadCatalog(ctx context.Context, metrics telemetry.Metrics, identityProvider *identityprovider.IdentityProvider, agentStore *agentstore.AgentStore,
	healthChecker health.Checker) (*catalog.Repository, error) {
	return catalog.Load(ctx, catalog.Config{
		Log:              s.config.Log.WithField(telemetry.SubsystemName, telemetry.Catalog),
		Metrics:          metrics,
		TrustDomain:      s.config.TrustDomain,
		PluginConfigs:    s.config.PluginConfigs,
		IdentityProvider: identityProvider,
		AgentStore:       agentStore,
		HealthChecker:    healthChecker,
	})
}

func (s *Server) newCredBuilder(cat catalog.Catalog) (*credtemplate.Builder, error) {
	return credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:            s.config.TrustDomain,
		X509CASubject:          s.config.CASubject,
		X509CATTL:              s.config.CATTL,
		AgentSVIDTTL:           s.config.AgentTTL,
		X509SVIDTTL:            s.config.X509SVIDTTL,
		JWTSVIDTTL:             s.config.JWTSVIDTTL,
		JWTIssuer:              s.config.JWTIssuer,
		ExcludeSNFromCASubject: s.config.ExcludeSNFromCASubject,
		CredentialComposers:    cat.GetCredentialComposers(),
	})
}

func (s *Server) newCredValidator() (*credvalidator.Validator, error) {
	return credvalidator.New(credvalidator.Config{
		TrustDomain: s.config.TrustDomain,
	})
}

func (s *Server) newCA(metrics telemetry.Metrics, credBuilder *credtemplate.Builder, credValidator *credvalidator.Validator, healthChecker health.Checker) *ca.CA {
	return ca.NewCA(ca.Config{
		Log:           s.config.Log.WithField(telemetry.SubsystemName, telemetry.CA),
		Metrics:       metrics,
		TrustDomain:   s.config.TrustDomain,
		CredBuilder:   credBuilder,
		CredValidator: credValidator,
		HealthChecker: healthChecker,
	})
}

func (s *Server) newCAManager(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics, serverCA *ca.CA, credBuilder *credtemplate.Builder, credValidator *credvalidator.Validator) (*manager.Manager, error) {
	caManager, err := manager.NewManager(ctx, manager.Config{
		CA:            serverCA,
		Catalog:       cat,
		TrustDomain:   s.config.TrustDomain,
		Log:           s.config.Log.WithField(telemetry.SubsystemName, telemetry.CAManager),
		Metrics:       metrics,
		CredBuilder:   credBuilder,
		CredValidator: credValidator,
		Dir:           s.config.DataDir,
		X509CAKeyType: s.config.CAKeyType,
		JWTKeyType:    s.config.JWTKeyType,
	})
	if err != nil {
		return nil, err
	}

	return caManager, nil
}

func (s *Server) newCASync(ctx context.Context, healthChecker health.Checker, caManager *manager.Manager) (*rotator.Rotator, error) {
	caSync := rotator.NewRotator(rotator.Config{
		Log:           s.config.Log.WithField(telemetry.SubsystemName, telemetry.CAManager),
		Manager:       caManager,
		HealthChecker: healthChecker,
	})
	if err := caSync.Initialize(ctx); err != nil {
		return nil, err
	}

	return caSync, nil
}

func (s *Server) newRegistrationManager(cat catalog.Catalog, metrics telemetry.Metrics) *registration.Manager {
	registrationManager := registration.NewManager(registration.ManagerConfig{
		DataStore: cat.GetDataStore(),
		Log:       s.config.Log.WithField(telemetry.SubsystemName, telemetry.RegistrationManager),
		Metrics:   metrics,
	})
	return registrationManager
}

func (s *Server) newSVIDRotator(ctx context.Context, serverCA ca.ServerCA, metrics telemetry.Metrics) (*svid.Rotator, error) {
	svidRotator := svid.NewRotator(&svid.RotatorConfig{
		ServerCA: serverCA,
		Log:      s.config.Log.WithField(telemetry.SubsystemName, telemetry.SVIDRotator),
		Metrics:  metrics,
		KeyType:  s.config.CAKeyType,
	})
	if err := svidRotator.Initialize(ctx); err != nil {
		return nil, err
	}
	return svidRotator, nil
}

func (s *Server) newEndpointsServer(ctx context.Context, catalog catalog.Catalog, svidObserver svid.Observer, serverCA ca.ServerCA, metrics telemetry.Metrics, jwtKeyPublisher manager.JwtKeyPublisher, authPolicyEngine *authpolicy.Engine, bundleManager *bundle_client.Manager) (endpoints.Server, error) {
	config := endpoints.Config{
		TCPAddr:              s.config.BindAddress,
		LocalAddr:            s.config.BindLocalAddress,
		SVIDObserver:         svidObserver,
		TrustDomain:          s.config.TrustDomain,
		Catalog:              catalog,
		ServerCA:             serverCA,
		Log:                  s.config.Log.WithField(telemetry.SubsystemName, telemetry.Endpoints),
		RootLog:              s.config.Log,
		Metrics:              metrics,
		JWTKeyPublisher:      jwtKeyPublisher,
		RateLimit:            s.config.RateLimit,
		Uptime:               uptime.Uptime,
		Clock:                clock.New(),
		CacheReloadInterval:  s.config.CacheReloadInterval,
		EventsBasedCache:     s.config.EventsBasedCache,
		PruneEventsOlderThan: s.config.PruneEventsOlderThan,
		AuditLogEnabled:      s.config.AuditLogEnabled,
		AuthPolicyEngine:     authPolicyEngine,
		BundleManager:        bundleManager,
		AdminIDs:             s.config.AdminIDs,
	}
	if s.config.Federation.BundleEndpoint != nil {
		config.BundleEndpoint.Address = s.config.Federation.BundleEndpoint.Address
		config.BundleEndpoint.RefreshHint = s.config.Federation.BundleEndpoint.RefreshHint
		config.BundleEndpoint.ACME = s.config.Federation.BundleEndpoint.ACME
	}
	return endpoints.New(ctx, config)
}

func (s *Server) newBundleManager(cat catalog.Catalog, metrics telemetry.Metrics) *bundle_client.Manager {
	log := s.config.Log.WithField(telemetry.SubsystemName, "bundle_client")
	return bundle_client.NewManager(bundle_client.ManagerConfig{
		Log:       log,
		Metrics:   metrics,
		DataStore: cat.GetDataStore(),
		Source: bundle_client.MergeTrustDomainConfigSources(
			bundle_client.NewTrustDomainConfigSet(s.config.Federation.FederatesWith),
			bundle_client.DataStoreTrustDomainConfigSource(log, cat.GetDataStore()),
		),
	})
}

func (s *Server) newBundlePublishingManager(bundlePublishers []bundlepublisher.BundlePublisher, ds datastore.DataStore) (*pubmanager.Manager, error) {
	log := s.config.Log.WithField(telemetry.SubsystemName, "bundle_publishing")
	return pubmanager.NewManager(&pubmanager.ManagerConfig{
		BundlePublishers: bundlePublishers,
		DataStore:        ds,
		TrustDomain:      s.config.TrustDomain,
		Log:              log,
	})
}

func (s *Server) validateTrustDomain(ctx context.Context, ds datastore.DataStore) error {
	trustDomain := s.config.TrustDomain.Name()

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

// waitForTestDial calls health.WaitForTestDial to wait for a connection to the
// SPIRE Server API socket. This function always returns nil, even if
// health.WaitForTestDial exited due to a timeout.
func (s *Server) waitForTestDial(ctx context.Context) error {
	health.WaitForTestDial(ctx, s.config.BindLocalAddress)
	return nil
}

// CheckHealth is used as a top-level health check for the Server.
func (s *Server) CheckHealth() health.State {
	err := s.tryGetBundle()

	// The API is served only after the server CA has been
	// signed by upstream. Hence, both live and ready checks
	// are determined by whether the bundles are received or not.
	// TODO: Better live check for server.
	return health.State{
		Ready: err == nil,
		Live:  err == nil,
		ReadyDetails: serverHealthDetails{
			GetBundleErr: errString(err),
		},
		LiveDetails: serverHealthDetails{
			GetBundleErr: errString(err),
		},
	}
}

func (s *Server) tryGetBundle() error {
	client, err := server_util.NewServerClient(s.config.BindLocalAddress)
	if err != nil {
		return errors.New("cannot create registration client")
	}
	defer client.Release()

	bundleClient := client.NewBundleClient()

	// Currently using the ability to fetch a bundle as the health check. This
	// **could** be problematic if the Upstream CA signing process is lengthy.
	// As currently coded however, the API isn't served until after
	// the server CA has been signed by upstream.
	if _, err := bundleClient.GetBundle(context.Background(), &bundlev1.GetBundleRequest{}); err != nil {
		return errors.New("unable to fetch bundle")
	}
	return nil
}

type serverHealthDetails struct {
	GetBundleErr string `json:"get_bundle_err,omitempty"`
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
