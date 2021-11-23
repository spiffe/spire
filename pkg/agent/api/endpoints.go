package api

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/agent/api/debug/v1"
	"github.com/spiffe/spire/pkg/agent/api/delegatedidentity/v1"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"

	"google.golang.org/grpc"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	c            *Config
	unixListener *peertracker.ListenerFactory
}

func (e *Endpoints) ListenAndServe(ctx context.Context) error {
	unaryInterceptor, streamInterceptor := middleware.Interceptors(
		middleware.WithLogger(e.c.Log),
	)

	server := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	e.registerDebugAPI(server)
	e.registerDelegatedIdentityAPI(server)

	l, err := e.createUDSListener()
	if err != nil {
		return err
	}
	defer l.Close()

	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping debug API")
		server.Stop()
		<-errChan
		return nil
	}
}

func (e *Endpoints) registerDebugAPI(server *grpc.Server) {
	clk := clock.New()
	service := debug.New(debug.Config{
		Clock:       clk,
		Log:         e.c.Log.WithField(telemetry.SubsystemName, telemetry.DebugAPI),
		Manager:     e.c.Manager,
		Uptime:      e.c.Uptime,
		TrustDomain: e.c.TrustDomain,
	})

	debug.RegisterService(server, service)
}

func (e *Endpoints) registerDelegatedIdentityAPI(server *grpc.Server) {
	service := delegatedidentity.New(delegatedidentity.Config{
		Manager:             e.c.Manager,
		Attestor:            e.c.Attestor,
		AuthorizedDelegates: e.c.AuthorizedDelegates,
		Log:                 e.c.Log.WithField(telemetry.SubsystemName, telemetry.DelegatedIdentityAPI),
	})

	delegatedidentity.RegisterService(server, service)
}

func (e *Endpoints) createUDSListener() (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(e.c.BindAddr.String())

	l, err := e.unixListener.ListenUnix(e.c.BindAddr.Network(), e.c.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %w", err)
	}
	if err := os.Chmod(e.c.BindAddr.String(), 0770); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}
