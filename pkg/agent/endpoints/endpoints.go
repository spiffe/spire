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
	healthv1 "github.com/spiffe/spire/pkg/agent/api/health/v1"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv2"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
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
	healthServer      grpc_health_v1.HealthServer
}

func New(c Config) *Endpoints {
	attestor := peerTrackerAttestor{Attestor: c.Attestor}

	if c.newWorkloadAPIServer == nil {
		c.newWorkloadAPIServer = func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return workload.New(c)
		}
	}
	if c.newSDSv2Server == nil {
		c.newSDSv2Server = func(c sdsv2.Config) discovery_v2.SecretDiscoveryServiceServer {
			return sdsv2.New(c)
		}
	}
	if c.newSDSv3Server == nil {
		c.newSDSv3Server = func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
			return sdsv3.New(c)
		}
	}
	if c.newHealthServer == nil {
		c.newHealthServer = func(c healthv1.Config) grpc_health_v1.HealthServer {
			return healthv1.New(c)
		}
	}

	workloadAPIServer := c.newWorkloadAPIServer(workload.Config{
		Manager:  c.Manager,
		Attestor: attestor,
	})

	sdsv2Server := c.newSDSv2Server(sdsv2.Config{
		Attestor:          attestor,
		Manager:           c.Manager,
		DefaultSVIDName:   c.DefaultSVIDName,
		DefaultBundleName: c.DefaultBundleName,
	})

	sdsv3Server := c.newSDSv3Server(sdsv3.Config{
		Attestor:          attestor,
		Manager:           c.Manager,
		DefaultSVIDName:   c.DefaultSVIDName,
		DefaultBundleName: c.DefaultBundleName,
	})

	healthServer := c.newHealthServer(healthv1.Config{
		SocketPath: c.BindAddr.String(),
	})

	return &Endpoints{
		addr:              c.BindAddr,
		log:               c.Log,
		metrics:           c.Metrics,
		workloadAPIServer: workloadAPIServer,
		sdsv2Server:       sdsv2Server,
		sdsv3Server:       sdsv3Server,
		healthServer:      healthServer,
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
	grpc_health_v1.RegisterHealthServer(server, e.healthServer)

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
