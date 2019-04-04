package endpoints

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	sds_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints/sds"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/auth"

	"google.golang.org/grpc"

	workload_pb "github.com/spiffe/spire/proto/api/workload"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

type endpoints struct {
	c *Config
}

func (e *endpoints) ListenAndServe(ctx context.Context) error {
	server := grpc.NewServer(grpc.Creds(auth.NewCredentials()))

	e.registerWorkloadAPI(server)
	if e.c.EnableSDS {
		e.registerSecretDiscoveryService(server)
	}

	l, err := e.createUDSListener()
	if err != nil {
		return err
	}
	defer l.Close()

	if e.c.GRPCHook != nil {
		err = e.c.GRPCHook(server)
		if err != nil {
			return fmt.Errorf("call grpc hook: %v", err)
		}
	}

	e.c.Log.Info("Starting workload API")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping workload API")
		server.Stop()
		<-errChan
		return nil
	}
}

func (e *endpoints) registerWorkloadAPI(server *grpc.Server) {
	w := &workload.Handler{
		Manager: e.c.Manager,
		Catalog: e.c.Catalog,
		L:       e.c.Log.WithField("subsystem_name", "workload_api"),
		M:       e.c.Metrics,
	}

	workload_pb.RegisterSpiffeWorkloadAPIServer(server, w)
}

func (e *endpoints) registerSecretDiscoveryService(server *grpc.Server) {
	attestor := attestor.New(&attestor.Config{
		Catalog: e.c.Catalog,
		L:       e.c.Log,
		M:       e.c.Metrics,
	})

	h := sds.NewHandler(sds.HandlerConfig{
		Attestor: attestor,
		Manager:  e.c.Manager,
		Log:      e.c.Log.WithField("subsystem_name", "sds_api"),
		Metrics:  e.c.Metrics,
	})
	sds_v2.RegisterSecretDiscoveryServiceServer(server, h)
}

func (e *endpoints) createUDSListener() (net.Listener, error) {
	// Create uds dir and parents if not exists
	dir := filepath.Dir(e.c.BindAddr.String())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Remove uds if already exists
	os.Remove(e.c.BindAddr.String())

	l, err := net.Listen(e.c.BindAddr.Network(), e.c.BindAddr.String())
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %s", err)
	}

	os.Chmod(e.c.BindAddr.String(), os.ModePerm)
	return l, nil
}
