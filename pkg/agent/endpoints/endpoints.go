package endpoints

import (
	"context"
	"fmt"
	"net"
	"os"

	discovery_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv2"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"

	"google.golang.org/grpc"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	addr              *net.UnixAddr
	log               logrus.FieldLogger
	metrics           telemetry.Metrics
	workloadAPIServer workload_pb.SpiffeWorkloadAPIServer
	sdsv2Server       discovery_v2.SecretDiscoveryServiceServer
	sdsv3Server       secret_v3.SecretDiscoveryServiceServer
}

func New(c Config) *Endpoints {
	attestor := peerTrackerAttestor{Attestor: c.Attestor}

	if c.newWorkloadAPIHandler == nil {
		c.newWorkloadAPIHandler = func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return workload.New(c)
		}
	}
	if c.newSDSv2Handler == nil {
		c.newSDSv2Handler = func(c sdsv2.Config) discovery_v2.SecretDiscoveryServiceServer {
			return sdsv2.New(c)
		}
	}
	if c.newSDSv3Handler == nil {
		c.newSDSv3Handler = func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
			return sdsv3.New(c)
		}
	}

	workloadAPIServer := c.newWorkloadAPIHandler(workload.Config{
		Manager:  c.Manager,
		Attestor: attestor,
	})

	sdsv2Server := c.newSDSv2Handler(sdsv2.Config{
		Attestor:          attestor,
		Manager:           c.Manager,
		DefaultSVIDName:   c.DefaultSVIDName,
		DefaultBundleName: c.DefaultBundleName,
	})

	sdsv3Server := c.newSDSv3Handler(sdsv3.Config{
		Attestor:          attestor,
		Manager:           c.Manager,
		DefaultSVIDName:   c.DefaultSVIDName,
		DefaultBundleName: c.DefaultBundleName,
	})

	return &Endpoints{
		addr:              c.BindAddr,
		log:               c.Log,
		metrics:           c.Metrics,
		workloadAPIServer: workloadAPIServer,
		sdsv2Server:       sdsv2Server,
		sdsv3Server:       sdsv3Server,
	}
}

func (e *Endpoints) ListenAndServe(ctx context.Context) error {
	unaryInterceptor, streamInterceptor := middleware.Interceptors(
		Middleware(e.log, e.metrics),
	)

	server := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	workload_pb.RegisterSpiffeWorkloadAPIServer(server, e.workloadAPIServer)
	discovery_v2.RegisterSecretDiscoveryServiceServer(server, e.sdsv2Server)
	secret_v3.RegisterSecretDiscoveryServiceServer(server, e.sdsv3Server)

	l, err := e.createUDSListener()
	if err != nil {
		return err
	}
	defer l.Close()

	e.log.Info("Starting Workload and SDS APIs")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
	case <-ctx.Done():
		e.log.Info("Stopping Workload and SDS APIs")
		server.Stop()
		err = <-errChan
		if err == grpc.ErrServerStopped {
			err = nil
		}
	}
	return err
}

func (e *Endpoints) createUDSListener() (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(e.addr.String())

	unixListener := &peertracker.ListenerFactory{
		Log: e.log,
	}

	l, err := unixListener.ListenUnix(e.addr.Network(), e.addr)
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %s", err)
	}

	if err := os.Chmod(e.addr.String(), os.ModePerm); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %v", err)
	}
	return l, nil
}
