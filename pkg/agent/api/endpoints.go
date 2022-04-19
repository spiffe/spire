package api

import (
	"context"

	"github.com/andres-erbsen/clock"
	debugv1 "github.com/spiffe/spire/pkg/agent/api/debug/v1"
	delegatedidentityv1 "github.com/spiffe/spire/pkg/agent/api/delegatedidentity/v1"
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

	l, err := e.createListener()
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
	service := debugv1.New(debugv1.Config{
		Clock:       clk,
		Log:         e.c.Log.WithField(telemetry.SubsystemName, telemetry.DebugAPI),
		Manager:     e.c.Manager,
		Uptime:      e.c.Uptime,
		TrustDomain: e.c.TrustDomain,
	})

	debugv1.RegisterService(server, service)
}

func (e *Endpoints) registerDelegatedIdentityAPI(server *grpc.Server) {
	service := delegatedidentityv1.New(delegatedidentityv1.Config{
		Manager:             e.c.Manager,
		Attestor:            e.c.Attestor,
		AuthorizedDelegates: e.c.AuthorizedDelegates,
		Log:                 e.c.Log.WithField(telemetry.SubsystemName, telemetry.DelegatedIdentityAPI),
	})

	delegatedidentityv1.RegisterService(server, service)
}
