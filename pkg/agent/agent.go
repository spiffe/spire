package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint: gosec // import registers routes on DefaultServeMux
	"os"
	"path"
	"runtime"
	"sync"

	api_workload "github.com/spiffe/spire/api/workload"
	admin_api "github.com/spiffe/spire/pkg/agent/api"
	node_attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	workload_attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/hostservices/metricsservice"
	common_services "github.com/spiffe/spire/pkg/common/plugin/hostservices"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/uptime"
	"github.com/spiffe/spire/pkg/common/util"
	_ "golang.org/x/net/trace" // registers handlers on the DefaultServeMux
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Agent struct {
	c *Config
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run(ctx context.Context) error {
	a.c.Log.Infof("Starting agent with data directory: %q", a.c.DataDir)
	if err := os.MkdirAll(a.c.DataDir, 0755); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if a.c.ProfilingEnabled {
		stopProfiling := a.setupProfiling(ctx)
		defer stopProfiling()
	}

	metrics, err := telemetry.NewMetrics(&telemetry.MetricsConfig{
		FileConfig:  a.c.Telemetry,
		Logger:      a.c.Log.WithField(telemetry.SubsystemName, telemetry.Telemetry),
		ServiceName: telemetry.SpireAgent,
	})
	if err != nil {
		return err
	}
	metricsService := metricsservice.New(metricsservice.Config{
		Metrics: metrics,
	})

	telemetry.EmitVersion(metrics)
	uptime.ReportMetrics(ctx, metrics)

	cat, err := catalog.Load(ctx, catalog.Config{
		Log: a.c.Log.WithField(telemetry.SubsystemName, telemetry.Catalog),
		GlobalConfig: &catalog.GlobalConfig{
			TrustDomain: a.c.TrustDomain.String(),
		},
		PluginConfig: a.c.PluginConfigs,
		HostServices: []common_catalog.HostServiceServer{
			common_services.MetricsServiceHostServiceServer(metricsService),
		},
		Metrics: metrics,
	})
	if err != nil {
		return err
	}
	defer cat.Close()

	healthChecks := health.NewChecker(a.c.HealthChecks, a.c.Log)

	as, err := a.attest(ctx, cat, metrics)
	if err != nil {
		return err
	}

	manager, err := a.newManager(ctx, cat, metrics, as)
	if err != nil {
		return err
	}

	endpoints := a.newEndpoints(cat, metrics, manager)

	if err := healthChecks.AddCheck("agent", a); err != nil {
		return fmt.Errorf("failed adding healthcheck: %v", err)
	}

	tasks := []func(context.Context) error{
		manager.Run,
		endpoints.ListenAndServe,
		metrics.ListenAndServe,
		util.SerialRun(a.waitForTestDial, healthChecks.ListenAndServe),
	}

	if a.c.AdminBindAddress != nil {
		adminEndpoints := a.newAdminEndpoints(manager)
		tasks = append(tasks, adminEndpoints.ListenAndServe)
	}

	err = util.RunTasks(ctx, tasks...)
	if err == context.Canceled {
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
			Addr:    fmt.Sprintf("localhost:%d", a.c.ProfilingPort),
			Handler: http.DefaultServeMux,
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

func (a *Agent) attest(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics) (*node_attestor.AttestationResult, error) {
	config := node_attestor.Config{
		Catalog:           cat,
		Metrics:           metrics,
		JoinToken:         a.c.JoinToken,
		TrustDomain:       a.c.TrustDomain,
		TrustBundle:       a.c.TrustBundle,
		InsecureBootstrap: a.c.InsecureBootstrap,
		BundleCachePath:   a.bundleCachePath(),
		SVIDCachePath:     a.agentSVIDPath(),
		Log:               a.c.Log.WithField(telemetry.SubsystemName, telemetry.Attestor),
		ServerAddress:     a.c.ServerAddress,
	}
	return node_attestor.New(&config).Attest(ctx)
}

func (a *Agent) newManager(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics, as *node_attestor.AttestationResult) (manager.Manager, error) {
	config := &manager.Config{
		SVID:            as.SVID,
		SVIDKey:         as.Key,
		Bundle:          as.Bundle,
		Catalog:         cat,
		TrustDomain:     a.c.TrustDomain,
		ServerAddr:      a.c.ServerAddress,
		Log:             a.c.Log.WithField(telemetry.SubsystemName, telemetry.Manager),
		Metrics:         metrics,
		BundleCachePath: a.bundleCachePath(),
		SVIDCachePath:   a.agentSVIDPath(),
		SyncInterval:    a.c.SyncInterval,
	}

	mgr := manager.New(config)
	if err := mgr.Initialize(ctx); err != nil {
		return nil, err
	}

	return mgr, nil
}

func (a *Agent) newEndpoints(cat catalog.Catalog, metrics telemetry.Metrics, mgr manager.Manager) endpoints.Server {
	return endpoints.New(endpoints.Config{
		BindAddr: a.c.BindAddress,
		Attestor: workload_attestor.New(&workload_attestor.Config{
			Catalog: cat,
			Log:     a.c.Log.WithField(telemetry.SubsystemName, telemetry.WorkloadAttestor),
			Metrics: metrics,
		}),
		Manager:                       mgr,
		Log:                           a.c.Log.WithField(telemetry.SubsystemName, telemetry.Endpoints),
		Metrics:                       metrics,
		DefaultSVIDName:               a.c.DefaultSVIDName,
		DefaultBundleName:             a.c.DefaultBundleName,
		AllowUnauthenticatedVerifiers: a.c.AllowUnauthenticatedVerifiers,
	})
}

func (a *Agent) newAdminEndpoints(mgr manager.Manager) admin_api.Server {
	config := &admin_api.Config{
		BindAddr:    a.c.AdminBindAddress,
		Manager:     mgr,
		Log:         a.c.Log.WithField(telemetry.SubsystemName, telemetry.DebugAPI),
		TrustDomain: a.c.TrustDomain,
		Uptime:      uptime.Uptime,
	}

	return admin_api.New(config)
}
func (a *Agent) bundleCachePath() string {
	return path.Join(a.c.DataDir, "bundle.der")
}

func (a *Agent) agentSVIDPath() string {
	return path.Join(a.c.DataDir, "agent_svid.der")
}

// waitForTestDial calls health.WaitForTestDial to wait for a connection to the
// SPIRE Agent API socket. This function always returns nil, even if
// health.WaitForTestDial exited due to a timeout.
func (a *Agent) waitForTestDial(ctx context.Context) error {
	health.WaitForTestDial(ctx, a.c.BindAddress)
	return nil
}

// Status is used as a top-level health check for the Agent.
func (a *Agent) Status() (interface{}, error) {
	client := api_workload.NewX509Client(&api_workload.X509ClientConfig{
		Addr:        a.c.BindAddress,
		FailOnError: true,
	})
	defer client.Stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Start()
	}()

	err := <-errCh
	if status.Code(err) == codes.Unavailable {
		return nil, errors.New("workload api is unavailable") //nolint: golint // error is (ab)used for CLI output
	}

	return health.Details{
		Message: "successfully created a workload api client to fetch x509 svid",
	}, nil
}
