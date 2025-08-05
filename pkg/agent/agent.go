package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint: gosec // import registers routes on DefaultServeMux
	"runtime"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	admin_api "github.com/spiffe/spire/pkg/agent/api"
	node_attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	workload_attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/svid/store"
	"github.com/spiffe/spire/pkg/common/backoff"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/uptime"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/version"
	"github.com/spiffe/spire/pkg/common/x509util"
	_ "golang.org/x/net/trace" // registers handlers on the DefaultServeMux
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	bootstrapBackoffInterval         = 5 * time.Second
	bootstrapBackoffMaxElapsedTime   = 1 * time.Minute
	startHealthChecksTimeout         = 8 * time.Second
	rebootstrapBackoffMaxElapsedTime = 24 * time.Hour
)

type Agent struct {
	c       *Config
	started bool
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run(ctx context.Context) error {
	a.c.Log.WithFields(logrus.Fields{
		telemetry.DataDir: a.c.DataDir,
		telemetry.Version: version.Version(),
	}).Info("Starting agent")
	if err := diskutil.CreateDataDirectory(a.c.DataDir); err != nil {
		return err
	}

	sto, err := storage.Open(a.c.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	if a.c.ProfilingEnabled {
		stopProfiling := a.setupProfiling(ctx)
		defer stopProfiling()
	}

	metrics, err := telemetry.NewMetrics(&telemetry.MetricsConfig{
		FileConfig:  a.c.Telemetry,
		Logger:      a.c.Log.WithField(telemetry.SubsystemName, telemetry.Telemetry),
		ServiceName: telemetry.SpireAgent,
		TrustDomain: a.c.TrustDomain.Name(),
	})
	if err != nil {
		return err
	}
	telemetry.EmitStarted(metrics, a.c.TrustDomain)
	uptime.ReportMetrics(ctx, metrics)

	cat, err := catalog.Load(ctx, catalog.Config{
		Log:           a.c.Log.WithField(telemetry.SubsystemName, telemetry.Catalog),
		Metrics:       metrics,
		TrustDomain:   a.c.TrustDomain,
		PluginConfigs: a.c.PluginConfigs,
	})
	if err != nil {
		return err
	}
	defer cat.Close()

	healthChecker := health.NewChecker(a.c.HealthChecks, a.c.Log)
	if err := healthChecker.AddCheck("agent", a); err != nil {
		return fmt.Errorf("failed adding healthcheck: %w", err)
	}

	taskRunner := util.NewTaskRunner(ctx, cancel)
	taskRunner.StartTasks(metrics.ListenAndServe)

	nodeAttestor := nodeattestor.JoinToken(a.c.Log, a.c.JoinToken)
	if a.c.JoinToken == "" {
		nodeAttestor = cat.GetNodeAttestor()
	}

	var as *node_attestor.AttestationResult

	readyForHealthChecks := make(chan struct{})
	go func() {
		a.startHealthChecks(readyForHealthChecks, taskRunner, healthChecker)
	}()

	a.c.TrustBundleSources.SetMetrics(metrics)
	err = a.c.TrustBundleSources.SetStorage(sto)
	if err != nil {
		return err
	}

	if a.c.RebootstrapMode != RebootstrapNever {
		_, reattestable, err := sto.LoadSVID()
		if err == nil && !reattestable {
			if a.c.RebootstrapMode == RebootstrapAlways {
				return errors.New("you have requested rebootstrap support but the NodeAttestor plugin or the spire server configuration is not allowing it")
			} else {
				a.c.Log.Warn("you have requested rebootstrap support but the NodeAttestor plugin or the spire server configuration is not allowing it. Disabling")
				a.c.RebootstrapMode = RebootstrapNever
			}
		}
	}

	if a.c.RetryBootstrap {
		attBackoffClock := clock.New()
		backoffTime := bootstrapBackoffMaxElapsedTime
		if a.c.RebootstrapMode != RebootstrapNever {
			backoffTime = rebootstrapBackoffMaxElapsedTime
		}
		attBackoff := backoff.NewBackoff(
			attBackoffClock,
			bootstrapBackoffInterval,
			backoff.WithMaxElapsedTime(backoffTime),
		)

		for {
			insecureBootstrap := false
			bootstrapTrustBundle, err := sto.LoadBundle()
			if errors.Is(err, storage.ErrNotCached) {
				bootstrapTrustBundle, insecureBootstrap, err = a.c.TrustBundleSources.GetBundle()
			}
			if err == nil {
				as, err = a.attest(ctx, sto, cat, metrics, nodeAttestor, bootstrapTrustBundle, insecureBootstrap)
				if err == nil {
					err = a.c.TrustBundleSources.SetSuccess()
					if err != nil {
						return err
					}
					if a.c.RebootstrapMode != RebootstrapNever {
						_, reattestable, err := sto.LoadSVID()
						if err == nil && !reattestable {
							if a.c.RebootstrapMode == RebootstrapAlways {
								return errors.New("you have requested rebootstrap support but the NodeAttestor plugin or the spire server configuration is not allowing it")
							} else {
								a.c.Log.Warn("you have requested rebootstrap support but the NodeAttestor plugin or the spire server configuration is not allowing it. Disabling")
								a.c.RebootstrapMode = RebootstrapNever
							}
						}
					}
					break
				}

				if x509util.IsUnknownAuthorityError(err) {
					if a.c.TrustBundleSources.IsBootstrap() {
						a.c.Log.Info("Trust Bandle and Server dont agree.... bootstrapping again")
					} else if a.c.RebootstrapMode != RebootstrapNever {
						startTime, err := a.c.TrustBundleSources.GetStartTime()
						if err != nil {
							return nil
						}
						seconds := time.Since(startTime)
						if seconds < a.c.RebootstrapDelay {
							a.c.Log.WithFields(logrus.Fields{
								"time left": a.c.RebootstrapDelay - seconds,
							}).Info("Trust Bandle and Server dont agree.... Ignoring for now.")
						} else {
							a.c.Log.Warn("Trust Bandle and Server dont agree.... rebootstrapping")
							err = sto.StoreBundle(nil)
							if err != nil {
								return err
							}
						}
					}
				}

				if status.Code(err) == codes.PermissionDenied {
					return err
				}
			}

			nextDuration := attBackoff.NextBackOff()
			if nextDuration == backoff.Stop {
				return err
			}

			a.c.Log.WithFields(logrus.Fields{
				telemetry.Error:         err,
				telemetry.RetryInterval: nextDuration,
			}).Warn("Failed to retrieve attestation result")

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-attBackoffClock.After(nextDuration):
				continue
			}
		}
	} else {
		insecureBootstrap := false
		bootstrapTrustBundle, err := sto.LoadBundle()
		if errors.Is(err, storage.ErrNotCached) {
			bootstrapTrustBundle, insecureBootstrap, err = a.c.TrustBundleSources.GetBundle()
		}
		if err != nil {
			return err
		}
		as, err = a.attest(ctx, sto, cat, metrics, nodeAttestor, bootstrapTrustBundle, insecureBootstrap)
		if err != nil {
			return err
		}
	}

	svidStoreCache := a.newSVIDStoreCache(metrics)

	manager, err := a.newManager(ctx, sto, cat, metrics, as, svidStoreCache, nodeAttestor)
	if err != nil {
		return err
	}

	storeService := a.newSVIDStoreService(svidStoreCache, cat, metrics)
	workloadAttestor := workload_attestor.New(&workload_attestor.Config{
		Catalog: cat,
		Log:     a.c.Log.WithField(telemetry.SubsystemName, telemetry.WorkloadAttestor),
		Metrics: metrics,
	})

	agentEndpoints := a.newEndpoints(metrics, manager, workloadAttestor)
	go func() {
		agentEndpoints.WaitForListening(readyForHealthChecks)
		a.started = true
	}()

	tasks := []func(context.Context) error{
		manager.Run,
		storeService.Run,
		agentEndpoints.ListenAndServe,
		catalog.ReconfigureTask(a.c.Log.WithField(telemetry.SubsystemName, "reconfigurer"), cat),
	}

	if a.c.AdminBindAddress != nil {
		adminEndpoints := a.newAdminEndpoints(metrics, manager, workloadAttestor, a.c.AuthorizedDelegates)
		tasks = append(tasks, adminEndpoints.ListenAndServe)
	}

	if a.c.LogReopener != nil {
		tasks = append(tasks, a.c.LogReopener)
	}

	taskRunner.StartTasks(tasks...)
	err = taskRunner.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (a *Agent) setupProfiling(ctx context.Context) (stop func()) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)

	if runtime.MemProfileRate == 0 {
		a.c.Log.Warn("Memory profiles are disabled")
	}
	if a.c.ProfilingPort > 0 {
		grpc.EnableTracing = true

		server := http.Server{
			Addr:              fmt.Sprintf("localhost:%d", a.c.ProfilingPort),
			Handler:           http.DefaultServeMux,
			ReadHeaderTimeout: time.Second * 10,
		}

		// kick off a goroutine to serve the pprof endpoints and one to
		// gracefully shut down the server when profiling is being torn down
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.ListenAndServe(); err != nil {
				a.c.Log.WithError(err).Warn("Unable to serve profiling server")
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			if err := server.Shutdown(ctx); err != nil {
				a.c.Log.WithError(err).Warn("Unable to shut down cleanly")
			}
		}()
	}
	if a.c.ProfilingFreq > 0 {
		c := &profiling.Config{
			Tag:                    "agent",
			Frequency:              a.c.ProfilingFreq,
			DebugLevel:             0,
			RunGCBeforeHeapProfile: true,
			Profiles:               a.c.ProfilingNames,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := profiling.Run(ctx, c); err != nil {
				a.c.Log.WithError(err).Warn("Failed to run profiling")
			}
		}()
	}

	return func() {
		cancel()
		wg.Wait()
	}
}

func (a *Agent) attest(ctx context.Context, sto storage.Storage, cat catalog.Catalog, metrics telemetry.Metrics, na nodeattestor.NodeAttestor, bootstrapTrustBundle []*x509.Certificate, insecureBootstrap bool) (*node_attestor.AttestationResult, error) {
	config := node_attestor.Config{
		Catalog:              cat,
		Metrics:              metrics,
		JoinToken:            a.c.JoinToken,
		TrustDomain:          a.c.TrustDomain,
		BootstrapTrustBundle: bootstrapTrustBundle,
		InsecureBootstrap:    insecureBootstrap,
		Storage:              sto,
		Log:                  a.c.Log.WithField(telemetry.SubsystemName, telemetry.Attestor),
		ServerAddress:        a.c.ServerAddress,
		NodeAttestor:         na,
		TLSPolicy:            a.c.TLSPolicy,
	}
	return node_attestor.New(&config).Attest(ctx)
}

func (a *Agent) newManager(ctx context.Context, sto storage.Storage, cat catalog.Catalog, metrics telemetry.Metrics, as *node_attestor.AttestationResult, cache *storecache.Cache, na nodeattestor.NodeAttestor) (manager.Manager, error) {
	config := &manager.Config{
		SVID:                     as.SVID,
		SVIDKey:                  as.Key,
		Bundle:                   as.Bundle,
		Reattestable:             as.Reattestable,
		Catalog:                  cat,
		TrustDomain:              a.c.TrustDomain,
		ServerAddr:               a.c.ServerAddress,
		Log:                      a.c.Log.WithField(telemetry.SubsystemName, telemetry.Manager),
		Metrics:                  metrics,
		WorkloadKeyType:          a.c.WorkloadKeyType,
		Storage:                  sto,
		TrustBundleSources:       a.c.TrustBundleSources,
		RebootstrapMode:          a.c.RebootstrapMode,
		RebootstrapDelay:         a.c.RebootstrapDelay,
		SyncInterval:             a.c.SyncInterval,
		UseSyncAuthorizedEntries: a.c.UseSyncAuthorizedEntries,
		X509SVIDCacheMaxSize:     a.c.X509SVIDCacheMaxSize,
		JWTSVIDCacheMaxSize:      a.c.JWTSVIDCacheMaxSize,
		SVIDStoreCache:           cache,
		NodeAttestor:             na,
		RotationStrategy:         rotationutil.NewRotationStrategy(a.c.AvailabilityTarget),
		TLSPolicy:                a.c.TLSPolicy,
	}

	mgr := manager.New(config)
	if a.c.RetryBootstrap {
		initBackoffClock := clock.New()
		backoffTime := bootstrapBackoffMaxElapsedTime
		if a.c.RebootstrapMode != RebootstrapNever {
			backoffTime = rebootstrapBackoffMaxElapsedTime
		}
		initBackoff := backoff.NewBackoff(
			initBackoffClock,
			bootstrapBackoffInterval,
			backoff.WithMaxElapsedTime(backoffTime),
		)

		for {
			err := mgr.Initialize(ctx)
			if err == nil {
				err = a.c.TrustBundleSources.SetSuccessIfRunning()
				if err != nil {
					return nil, err
				}
				return mgr, nil
			}
			if x509util.IsUnknownAuthorityError(err) && a.c.RebootstrapMode != RebootstrapNever {
				startTime, err := a.c.TrustBundleSources.GetStartTime()
				if err != nil {
					return nil, err
				}
				seconds := time.Since(startTime)
				if seconds < a.c.RebootstrapDelay {
					a.c.Log.WithFields(logrus.Fields{
						"time left": a.c.RebootstrapDelay - seconds,
					}).Info("Trust Bandle and Server dont agree.... Ignoring for now.")
				} else {
					a.c.Log.Info("Trust Bandle and Server dont agree.... rebootstrapping")
					err = a.c.TrustBundleSources.SetForceRebootstrap()
					if err != nil {
						return nil, err
					}
					return nil, errors.New("Agent needs to rebootstrap. shutting down")
				}
			}

			if nodeutil.ShouldAgentReattest(err) || nodeutil.ShouldAgentShutdown(err) {
				return nil, err
			}

			nextDuration := initBackoff.NextBackOff()
			if nextDuration == backoff.Stop {
				return nil, err
			}

			a.c.Log.WithFields(logrus.Fields{
				telemetry.Error:         err,
				telemetry.RetryInterval: nextDuration,
			}).Warn("Failed to initialize manager")

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-initBackoffClock.After(nextDuration):
				continue
			}
		}
	} else {
		if err := mgr.Initialize(ctx); err != nil {
			return nil, err
		}
		return mgr, nil
	}
}

func (a *Agent) newSVIDStoreCache(metrics telemetry.Metrics) *storecache.Cache {
	config := &storecache.Config{
		Log:         a.c.Log.WithField(telemetry.SubsystemName, "svid_store_cache"),
		TrustDomain: a.c.TrustDomain,
		Metrics:     metrics,
	}

	return storecache.New(config)
}

func (a *Agent) newSVIDStoreService(cache *storecache.Cache, cat catalog.Catalog, metrics telemetry.Metrics) *store.SVIDStoreService {
	config := &store.Config{
		Log:         a.c.Log.WithField(telemetry.SubsystemName, "svid_store_service"),
		TrustDomain: a.c.TrustDomain,
		Cache:       cache,
		Catalog:     cat,
		Metrics:     metrics,
	}

	return store.New(config)
}

func (a *Agent) newEndpoints(metrics telemetry.Metrics, mgr manager.Manager, attestor workload_attestor.Attestor) endpoints.Server {
	return endpoints.New(endpoints.Config{
		BindAddr:                      a.c.BindAddress,
		Attestor:                      attestor,
		Manager:                       mgr,
		Log:                           a.c.Log.WithField(telemetry.SubsystemName, telemetry.Endpoints),
		Metrics:                       metrics,
		DefaultSVIDName:               a.c.DefaultSVIDName,
		DefaultBundleName:             a.c.DefaultBundleName,
		DefaultAllBundlesName:         a.c.DefaultAllBundlesName,
		DisableSPIFFECertValidation:   a.c.DisableSPIFFECertValidation,
		AllowUnauthenticatedVerifiers: a.c.AllowUnauthenticatedVerifiers,
		AllowedForeignJWTClaims:       a.c.AllowedForeignJWTClaims,
		TrustDomain:                   a.c.TrustDomain,
	})
}

func (a *Agent) newAdminEndpoints(metrics telemetry.Metrics, mgr manager.Manager, attestor workload_attestor.Attestor, authorizedDelegates []string) admin_api.Server {
	config := &admin_api.Config{
		BindAddr:            a.c.AdminBindAddress,
		Manager:             mgr,
		Log:                 a.c.Log,
		Metrics:             metrics,
		TrustDomain:         a.c.TrustDomain,
		Uptime:              uptime.Uptime,
		Attestor:            attestor,
		AuthorizedDelegates: authorizedDelegates,
	}

	return admin_api.New(config)
}

// CheckHealth is used as a top-level health check for the agent.
func (a *Agent) CheckHealth() health.State {
	err := a.checkWorkloadAPI()

	// Both liveness and readiness checks are done by
	// agents ability to create new Workload API client
	// for the X509SVID service.
	// TODO: Better live check for agent.
	return health.State{
		Started: &a.started,
		Ready:   err == nil,
		Live:    (!a.started || err == nil),
		ReadyDetails: agentHealthDetails{
			WorkloadAPIErr: errString(false, err),
		},
		LiveDetails: agentHealthDetails{
			WorkloadAPIErr: errString(!a.started, err),
		},
	}
}

func (a *Agent) checkWorkloadAPI() error {
	clientOption, err := util.GetWorkloadAPIClientOption(a.c.BindAddress)
	if err != nil {
		a.c.Log.WithError(err).Error("Failed to get Workload API client options for health check")
		return err
	}

	_, err = workloadapi.FetchX509Bundles(context.TODO(), clientOption)
	if status.Code(err) == codes.Unavailable {
		// Only an unavailable status fails the health check.
		return errors.New("workload api is unavailable")
	}
	return nil
}

type agentHealthDetails struct {
	WorkloadAPIErr string `json:"make_new_x509_err,omitempty"`
}

func errString(suppress bool, err error) string {
	if suppress {
		return ""
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func (a *Agent) startHealthChecks(readyForHealthChecks chan struct{}, taskRunner *util.TaskRunner, healthChecker health.ServableChecker) {
	select {
	case <-readyForHealthChecks:
		// Endpoints are ready for health checks, proceed with health checks.
	case <-time.After(startHealthChecksTimeout):
		// Timeout waiting for endpoints to start listening.
	}
	taskRunner.StartTasks(healthChecker.ListenAndServe)
}
