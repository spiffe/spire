package agent

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"path"
	"runtime"
	"sync"
	"syscall"

	"github.com/spiffe/spire/pkg/agent/attestor"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/profiling"
	"github.com/spiffe/spire/pkg/common/telemetry"
	_ "golang.org/x/net/trace"
	"google.golang.org/grpc"
	tomb "gopkg.in/tomb.v2"
)

type Agent struct {
	c   *Config
	t   *tomb.Tomb
	mtx *sync.RWMutex
	tel telemetry.Sink

	Catalog   catalog.Catalog
	Manager   manager.Manager
	Endpoints endpoints.Endpoints
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	syscall.Umask(a.c.Umask)

	a.t.Go(a.run)
	return a.t.Wait()
}

func (a *Agent) Shutdown() {
	a.t.Kill(nil)
}

func (a *Agent) run() error {
	if a.c.ProfilingEnabled {
		a.setupProfiling()
	}

	err := a.startPlugins()
	if err != nil {
		return err
	}

	as, err := a.attest()
	if err != nil {
		return err
	}

	err = a.startManager(as.SVID, as.Key, as.Bundle)
	if err != nil {
		return err
	}

	a.t.Go(a.startEndpoints)
	a.t.Go(a.superviseManager)

	<-a.t.Dying()
	a.shutdown()
	return nil
}

func (a *Agent) startPlugins() error {
	return a.Catalog.Run()
}

func (a *Agent) attest() (*attestor.AttestationResult, error) {
	config := attestor.Config{
		Catalog:         a.Catalog,
		JoinToken:       a.c.JoinToken,
		TrustDomain:     a.c.TrustDomain,
		TrustBundle:     a.c.TrustBundle,
		BundleCachePath: a.bundleCachePath(),
		SVIDCachePath:   a.agentSVIDPath(),
		Log:             a.c.Log.WithField("subsystem_name", "attestor"),
		ServerAddress:   a.c.ServerAddress,
	}
	return attestor.New(&config).Attest()
}

func (a *Agent) superviseManager() error {
	// Wait until the manager stopped working.
	<-a.Manager.Stopped()
	err := a.Manager.Err()
	a.mtx.Lock()
	a.Manager = nil
	a.mtx.Unlock()
	return err
}

func (a *Agent) shutdown() {
	if a.Endpoints != nil {
		a.Endpoints.Shutdown()
	}

	if a.Manager != nil {
		a.Manager.Shutdown()
	}

	if a.Catalog != nil {
		a.Catalog.Stop()
	}
}

func (a *Agent) setupProfiling() {
	if runtime.MemProfileRate == 0 {
		a.c.Log.Warn("Memory profiles are disabled")
	}
	if a.c.ProfilingPort > 0 {
		grpc.EnableTracing = true
		go func() {
			addr := fmt.Sprintf("localhost:%d", a.c.ProfilingPort)
			a.c.Log.Info(http.ListenAndServe(addr, nil))
		}()
	}
	if a.c.ProfilingFreq > 0 {
		c := &profiling.Config{
			Tag:        "agent",
			Frequency:  a.c.ProfilingFreq,
			DebugLevel: 0,
			Profiles:   a.c.ProfilingNames,
		}
		err := profiling.Start(c)
		if err != nil {
			a.c.Log.Error("Profiler failed to start: %v", err)
			return
		}
		a.t.Go(a.stopProfiling)
	}
}

func (a *Agent) stopProfiling() error {
	<-a.t.Dying()
	profiling.Stop()
	return nil
}

func (a *Agent) startManager(svid *x509.Certificate, key *ecdsa.PrivateKey, bundle []*x509.Certificate) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.Manager != nil {
		return errors.New("cannot start cache manager, there is a manager instantiated already")
	}

	mgrConfig := &manager.Config{
		SVID:            svid,
		SVIDKey:         key,
		Bundle:          bundle,
		TrustDomain:     a.c.TrustDomain,
		ServerAddr:      a.c.ServerAddress,
		Log:             a.c.Log,
		Tel:             a.tel,
		BundleCachePath: a.bundleCachePath(),
		SVIDCachePath:   a.agentSVIDPath(),
	}

	mgr, err := manager.New(mgrConfig)
	if err != nil {
		return err
	}
	a.Manager = mgr
	return a.Manager.Start()
}

func (a *Agent) startEndpoints() error {
	config := &endpoints.Config{
		BindAddr: a.c.BindAddress,
		Catalog:  a.Catalog,
		Manager:  a.Manager,
		Log:      a.c.Log.WithField("subsystem_name", "endpoints"),
		Tel:      a.tel,
	}

	e := endpoints.New(config)
	err := e.Start()
	if err != nil {
		return err
	}

	a.mtx.Lock()
	a.Endpoints = e
	a.mtx.Unlock()
	return a.Endpoints.Wait()
}

func (a *Agent) bundleCachePath() string {
	return path.Join(a.c.DataDir, "bundle.der")
}

func (a *Agent) agentSVIDPath() string {
	return path.Join(a.c.DataDir, "agent_svid.der")
}
