package endpoints

import (
	"context"
	"fmt"
	"net"
	"os"

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
		l.Close()
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

func (e *endpoints) createUDSListener() (net.Listener, error) {
	os.Remove(e.c.BindAddr.String())

	l, err := net.Listen(e.c.BindAddr.Network(), e.c.BindAddr.String())
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %s", err)
	}

	os.Chmod(e.c.BindAddr.String(), os.ModePerm)
	return l, nil
}
