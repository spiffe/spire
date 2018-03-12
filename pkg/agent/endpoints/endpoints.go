package endpoints

import (
	"fmt"
	"net"
	"os"

	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"

	"google.golang.org/grpc"

	workload_pb "github.com/spiffe/spire/proto/api/workload"
	tomb "gopkg.in/tomb.v2"
)

type Endpoints interface {
	Start() error
	Wait() error
	Shutdown()
}

type endpoints struct {
	c *Config
	t *tomb.Tomb

	grpc *grpc.Server
}

func (e *endpoints) Start() error {
	e.grpc = grpc.NewServer(grpc.Creds(auth.NewCredentials()))

	e.registerWorkloadAPI()

	l, err := e.createUDSListener()
	if err != nil {
		return err
	}

	e.t.Go(func() error { return e.start(l) })
	return nil
}

func (e *endpoints) Wait() error {
	return e.t.Wait()
}

func (e *endpoints) Shutdown() {
	e.t.Kill(nil)
}

func (e *endpoints) start(l net.Listener) error {
	e.t.Go(func() error { return e.startGRPCServer(l) })

	<-e.t.Dying()
	e.grpc.Stop()
	return tomb.ErrDying
}

func (e *endpoints) registerWorkloadAPI() {
	w := &workload.Handler{
		Manager: e.c.Manager,
		Catalog: e.c.Catalog,
		L:       e.c.Log.WithField("subsystem_name", "workload_api"),
	}

	workload_pb.RegisterSpiffeWorkloadAPIServer(e.grpc, w)
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

func (e *endpoints) startGRPCServer(l net.Listener) error {
	return e.grpc.Serve(l)
}
