package endpoints

import (
	"context"
	"errors"
	"net"

	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	healthv1 "github.com/spiffe/spire/pkg/agent/api/health/v1"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	readBufferSize = 4096
)

type Server interface {
	ListenAndServe(ctx context.Context) error
	WaitForListening(listening chan struct{})
}

type Endpoints struct {
	addr              net.Addr
	log               logrus.FieldLogger
	metrics           telemetry.Metrics
	workloadAPIServer workload_pb.SpiffeWorkloadAPIServer
	sdsv3Server       secret_v3.SecretDiscoveryServiceServer
	healthServer      grpc_health_v1.HealthServer
	apiNames          string

	hooks struct {
		listening chan struct{} // Hook to signal when the server starts listening
	}
}

func New(c Config) *Endpoints {
	attestor := PeerTrackerAttestor{Attestor: c.Attestor}

	if !c.DisableWorkloadAPI && c.newWorkloadAPIServer == nil {
		c.newWorkloadAPIServer = func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return workload.New(c)
		}
	}
	if !c.DisableSDSAPI && c.newSDSv3Server == nil {
		c.newSDSv3Server = func(c sdsv3.Config) secret_v3.SecretDiscoveryServiceServer {
			return sdsv3.New(c)
		}
	}
	if c.newHealthServer == nil {
		c.newHealthServer = func(c healthv1.Config) grpc_health_v1.HealthServer {
			return healthv1.New(c)
		}
	}

	allowedClaims := make(map[string]struct{}, len(c.AllowedForeignJWTClaims))
	for _, claim := range c.AllowedForeignJWTClaims {
		allowedClaims[claim] = struct{}{}
	}

	workloadRateLimiter := NewWorkloadRateLimiter(c.WorkloadAPIRateLimit, c.Log, c.Metrics)

	var workloadAPIServer workload_pb.SpiffeWorkloadAPIServer
	if !c.DisableWorkloadAPI {
		workloadAPIServer = c.newWorkloadAPIServer(workload.Config{
			Manager:                       c.Manager,
			Attestor:                      attestor,
			RateLimiter:                   workloadRateLimiter,
			AllowUnauthenticatedVerifiers: c.AllowUnauthenticatedVerifiers,
			AllowedForeignJWTClaims:       allowedClaims,
			LogSelectors:                  c.LogSelectors,
			TrustDomain:                   c.TrustDomain,
		})
	}

	var sdsv3Server secret_v3.SecretDiscoveryServiceServer
	if !c.DisableSDSAPI {
		sdsv3Server = c.newSDSv3Server(sdsv3.Config{
			Attestor:                    attestor,
			Manager:                     c.Manager,
			RateLimiter:                 workloadRateLimiter,
			DefaultSVIDName:             c.DefaultSVIDName,
			DefaultBundleName:           c.DefaultBundleName,
			DefaultAllBundlesName:       c.DefaultAllBundlesName,
			DisableSPIFFECertValidation: c.DisableSPIFFECertValidation,
		})
	}

	healthServer := c.newHealthServer(healthv1.Config{
		Addr:               c.BindAddr,
		DisableWorkloadAPI: c.DisableWorkloadAPI,
	})

	return &Endpoints{
		addr:              c.BindAddr,
		log:               c.Log,
		metrics:           c.Metrics,
		workloadAPIServer: workloadAPIServer,
		sdsv3Server:       sdsv3Server,
		healthServer:      healthServer,
		apiNames:          apiNames(c.DisableWorkloadAPI, c.DisableSDSAPI),
		hooks: struct {
			listening chan struct{}
		}{
			listening: make(chan struct{}),
		},
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
		grpc.ReadBufferSize(readBufferSize),
	)

	if e.workloadAPIServer != nil {
		workload_pb.RegisterSpiffeWorkloadAPIServer(server, e.workloadAPIServer)
	}
	if e.sdsv3Server != nil {
		secret_v3.RegisterSecretDiscoveryServiceServer(server, e.sdsv3Server)
	}
	grpc_health_v1.RegisterHealthServer(server, e.healthServer)

	reflection.Register(server)

	l, err := e.createListener()
	if err != nil {
		return err
	}
	defer l.Close()

	// Update the listening address with the actual address.
	// If a TCP address was specified with port 0, this will
	// update the address with the actual port that is used
	// to listen.
	e.addr = l.Addr()
	e.log.WithFields(logrus.Fields{
		telemetry.Network: e.addr.Network(),
		telemetry.Address: e.addr,
	}).Infof("Starting %s", e.apiNames)
	e.triggerListeningHook()
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
	case <-ctx.Done():
		e.log.Infof("Stopping %s", e.apiNames)
		server.Stop()
		err = <-errChan
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
	}
	return err
}

func apiNames(disableWorkloadAPI, disableSDSAPI bool) string {
	switch {
	case !disableWorkloadAPI && !disableSDSAPI:
		return "Workload and SDS APIs"
	case disableWorkloadAPI && !disableSDSAPI:
		return "SDS API"
	case !disableWorkloadAPI && disableSDSAPI:
		return "Workload API"
	default:
		return "no APIs"
	}
}

func (e *Endpoints) triggerListeningHook() {
	if e.hooks.listening != nil {
		e.hooks.listening <- struct{}{}
	}
}

func (e *Endpoints) WaitForListening(listening chan struct{}) {
	if e.hooks.listening == nil {
		e.log.Warn("Listening hook not initialized, cannot wait for listening")
		return
	}

	<-e.hooks.listening
	listening <- struct{}{}
}
