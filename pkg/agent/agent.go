package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"path"
	"runtime"
	"sync"

	attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	_ "golang.org/x/net/trace"
	"google.golang.org/grpc"
)

type Agent struct {
	c *Config
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run(ctx context.Context) error {
	a.c.Log.Infof("data directory: %q", a.c.DataDir)
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
		Logger:      a.c.Log.WithField("subsystem_name", "telemetry"),
		ServiceName: "spire_agent",
	})
	if err != nil {
		return err
	}

	cat, err := catalog.Load(ctx, catalog.Config{
		Log: a.c.Log.WithField("subsystem_name", "catalog"),
		GlobalConfig: catalog.GlobalConfig{
			TrustDomain: a.c.TrustDomain.Host,
		},
		PluginConfig: a.c.PluginConfigs,
	})
	if err != nil {
		return err
	}
	defer cat.Close()

	as, err := a.attest(ctx, cat, metrics)
	if err != nil {
		return err
	}

	manager, err := a.newManager(ctx, cat, metrics, as)
	if err != nil {
		return err
	}

	endpoints := a.newEndpoints(ctx, cat, metrics, manager)

	err = util.RunTasks(ctx,
		manager.Run,
		endpoints.ListenAndServe,
		metrics.ListenAndServe,
	)
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
			Handler: http.HandlerFunc(pprof.Index),
		}

		// kick off a goroutine to serve the pprof endpoints and one to
		// gracefully shut down the server when profiling is being torn down
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.ListenAndServe(); err != nil {
				a.c.Log.Warnf("unable to serve profiling server: %v", err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			server.Shutdown(ctx)
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
				a.c.Log.Warnf("Failed to run profiling: %v", err)
			}
		}()
	}

	return func() {
		cancel()
		wg.Wait()
	}
}

func (a *Agent) attest(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics) (*attestor.AttestationResult, error) {
	config := attestor.Config{
		Catalog:         cat,
		Metrics:         metrics,
		JoinToken:       a.c.JoinToken,
		TrustDomain:     a.c.TrustDomain,
		TrustBundle:     a.c.TrustBundle,
		BundleCachePath: a.bundleCachePath(),
		SVIDCachePath:   a.agentSVIDPath(),
		Log:             a.c.Log.WithField("subsystem_name", "attestor"),
		ServerAddress:   a.c.ServerAddress,
	}
	return attestor.New(&config).Attest(ctx)
}

func (a *Agent) newManager(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics, as *attestor.AttestationResult) (manager.Manager, error) {
	config := &manager.Config{
		SVID:            as.SVID,
		SVIDKey:         as.Key,
		Bundle:          as.Bundle,
		Catalog:         cat,
		TrustDomain:     a.c.TrustDomain,
		ServerAddr:      a.c.ServerAddress,
		Log:             a.c.Log.WithField("subsystem_name", "manager"),
		Metrics:         metrics,
		BundleCachePath: a.bundleCachePath(),
		SVIDCachePath:   a.agentSVIDPath(),
	}

	mgr, err := manager.New(config)
	if err != nil {
		return nil, err
	}

	if err := mgr.Initialize(ctx); err != nil {
		return nil, err
	}

	return mgr, nil
}

func (a *Agent) newEndpoints(ctx context.Context, cat catalog.Catalog, metrics telemetry.Metrics, mgr manager.Manager) endpoints.Server {
	config := &endpoints.Config{
		BindAddr:  a.c.BindAddress,
		Catalog:   cat,
		Manager:   mgr,
		Log:       a.c.Log.WithField("subsystem_name", "endpoints"),
		Metrics:   metrics,
		EnableSDS: a.c.EnableSDS,
	}

	return endpoints.New(config)
}

func (a *Agent) bundleCachePath() string {
	return path.Join(a.c.DataDir, "bundle.der")
}

func (a *Agent) agentSVIDPath() string {
	return path.Join(a.c.DataDir, "agent_svid.der")
}
