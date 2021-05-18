package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	debugv1_pb "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
	registration_pb "github.com/spiffe/spire/proto/spire/api/registration"
)

const (
	// This is the maximum amount of time an agent connection may exist before
	// the server sends a hangup request. This enables agents to more dynamically
	// route to the server in the case of a change in DNS membership.
	defaultMaxConnectionAge = 3 * time.Minute

	// This is the default amount of time between two reloads of the in-memory
	// entry cache.
	defaultCacheReloadInterval = 5 * time.Second
)

// Server manages gRPC and HTTP endpoint lifecycle
type Server interface {
	// ListenAndServe starts all endpoint servers and blocks until the context
	// is canceled or any of the servers fails to run. If the context is
	// canceled, the function returns nil. Otherwise, the error from the failed
	// server is returned.
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	OldAPIServers

	TCPAddr                      *net.TCPAddr
	UDSAddr                      *net.UnixAddr
	SVIDObserver                 svid.Observer
	TrustDomain                  spiffeid.TrustDomain
	DataStore                    datastore.DataStore
	APIServers                   APIServers
	BundleEndpointServer         Server
	Log                          logrus.FieldLogger
	Metrics                      telemetry.Metrics
	RateLimit                    RateLimitConfig
	EntryFetcherCacheRebuildTask func(context.Context) error
}

type OldAPIServers struct {
	RegistrationServer registration_pb.RegistrationServer
}

type APIServers struct {
	AgentServer  agentv1.AgentServer
	BundleServer bundlev1.BundleServer
	DebugServer  debugv1_pb.DebugServer
	EntryServer  entryv1.EntryServer
	HealthServer grpc_health_v1.HealthServer
	SVIDServer   svidv1.SVIDServer
}

// RateLimitConfig holds rate limiting configurations.
type RateLimitConfig struct {
	// Attestation, if true, rate limits attestation
	Attestation bool

	// Signing, if true, rate limits JWT and X509 signing requests
	Signing bool
}

// New creates new endpoints struct
func New(ctx context.Context, c Config) (*Endpoints, error) {
	if err := os.MkdirAll(c.UDSAddr.String(), 0750); err != nil {
		return nil, fmt.Errorf("unable to create socket directory: %w", err)
	}

	oldAPIServers := c.makeOldAPIServers()

	buildCacheFn := func(ctx context.Context) (_ entrycache.Cache, err error) {
		call := telemetry.StartCall(c.Metrics, telemetry.Entry, telemetry.Cache, telemetry.Reload)
		defer call.Done(&err)
		return entrycache.BuildFromDataStore(ctx, c.Catalog.GetDataStore())
	}

	if c.CacheReloadInterval == 0 {
		c.CacheReloadInterval = defaultCacheReloadInterval
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCacheFn, c.Log, c.Clock, c.CacheReloadInterval)
	if err != nil {
		return nil, err
	}

	return &Endpoints{
		OldAPIServers:                oldAPIServers,
		TCPAddr:                      c.TCPAddr,
		UDSAddr:                      c.UDSAddr,
		SVIDObserver:                 c.SVIDObserver,
		TrustDomain:                  c.TrustDomain,
		DataStore:                    c.Catalog.GetDataStore(),
		APIServers:                   c.makeAPIServers(ef),
		BundleEndpointServer:         c.maybeMakeBundleEndpointServer(),
		Log:                          c.Log,
		Metrics:                      c.Metrics,
		RateLimit:                    c.RateLimit,
		EntryFetcherCacheRebuildTask: ef.RunRebuildCacheTask,
	}, nil
}

// ListenAndServe starts all endpoint servers and blocks until the context
// is canceled or any of the servers fails to run. If the context is
// canceled, the function returns nil. Otherwise, the error from the failed
// server is returned.
func (e *Endpoints) ListenAndServe(ctx context.Context) error {
	e.Log.Debug("Initializing API endpoints")

	unaryInterceptor, streamInterceptor := e.makeInterceptors()

	tcpServer := e.createTCPServer(ctx, unaryInterceptor, streamInterceptor)
	udsServer := e.createUDSServer(unaryInterceptor, streamInterceptor)

	// Old APIs
	registration_pb.RegisterRegistrationServer(tcpServer, e.OldAPIServers.RegistrationServer)
	registration_pb.RegisterRegistrationServer(udsServer, e.OldAPIServers.RegistrationServer)

	// New APIs
	agentv1.RegisterAgentServer(tcpServer, e.APIServers.AgentServer)
	agentv1.RegisterAgentServer(udsServer, e.APIServers.AgentServer)
	bundlev1.RegisterBundleServer(tcpServer, e.APIServers.BundleServer)
	bundlev1.RegisterBundleServer(udsServer, e.APIServers.BundleServer)
	entryv1.RegisterEntryServer(tcpServer, e.APIServers.EntryServer)
	entryv1.RegisterEntryServer(udsServer, e.APIServers.EntryServer)
	svidv1.RegisterSVIDServer(tcpServer, e.APIServers.SVIDServer)
	svidv1.RegisterSVIDServer(udsServer, e.APIServers.SVIDServer)

	// Register Health and Debug only on UDS server
	grpc_health_v1.RegisterHealthServer(udsServer, e.APIServers.HealthServer)
	debugv1_pb.RegisterDebugServer(udsServer, e.APIServers.DebugServer)

	tasks := []func(context.Context) error{
		func(ctx context.Context) error {
			return e.runTCPServer(ctx, tcpServer)
		},
		func(ctx context.Context) error {
			return e.runUDSServer(ctx, udsServer)
		},
		e.EntryFetcherCacheRebuildTask,
	}

	if e.BundleEndpointServer != nil {
		tasks = append(tasks, e.BundleEndpointServer.ListenAndServe)
	}

	err := util.RunTasks(ctx, tasks...)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (e *Endpoints) createTCPServer(ctx context.Context, unaryInterceptor grpc.UnaryServerInterceptor, streamInterceptor grpc.StreamServerInterceptor) *grpc.Server {
	tlsConfig := &tls.Config{ //nolint: gosec // False positive, getTLSConfig is setting MinVersion
		GetConfigForClient: e.getTLSConfig(ctx),
	}

	return grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge: defaultMaxConnectionAge,
		}),
	)
}

func (e *Endpoints) createUDSServer(unaryInterceptor grpc.UnaryServerInterceptor, streamInterceptor grpc.StreamServerInterceptor) *grpc.Server {
	return grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
		grpc.Creds(auth.UntrackedUDSCredentials()))
}

// runTCPServer will start the server and block until it exits or we are dying.
func (e *Endpoints) runTCPServer(ctx context.Context, server *grpc.Server) error {
	l, err := net.Listen(e.TCPAddr.Network(), e.TCPAddr.String())
	if err != nil {
		return err
	}
	defer l.Close()

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.Log.WithField(telemetry.Address, l.Addr().String()).Info("Starting TCP server")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		e.Log.WithError(err).Error("TCP server stopped prematurely")
		return err
	case <-ctx.Done():
		e.Log.Info("Stopping TCP server")
		server.Stop()
		<-errChan
		e.Log.Info("TCP server has stopped")
		return nil
	}
}

// runUDSServer  will start the server and block until it exits or we are dying.
func (e *Endpoints) runUDSServer(ctx context.Context, server *grpc.Server) error {
	os.Remove(e.UDSAddr.String())
	l, err := net.ListenUnix(e.UDSAddr.Network(), e.UDSAddr)
	if err != nil {
		return err
	}
	defer l.Close()

	// Restrict access to the UDS to processes running as the same user or
	// group as the server.
	if err := os.Chmod(e.UDSAddr.String(), 0770); err != nil {
		return err
	}

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.Log.WithField(telemetry.Address, l.Addr().String()).Info("Starting UDS server")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err := <-errChan:
		e.Log.WithError(err).Error("UDS server stopped prematurely")
		return err
	case <-ctx.Done():
		e.Log.Info("Stopping UDS server")
		server.Stop()
		<-errChan
		e.Log.Info("UDS server has stopped")
		return nil
	}
}

// getTLSConfig returns a TLS Config hook for the gRPC server
func (e *Endpoints) getTLSConfig(ctx context.Context) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		certs, roots, err := e.getCerts(ctx)
		if err != nil {
			e.Log.WithError(err).WithField(telemetry.Address, hello.Conn.RemoteAddr().String()).Error("Could not generate TLS config for gRPC client")
			return nil, err
		}

		return &tls.Config{
			// Not all server APIs required a client certificate. Though if one
			// is presented, verify it.
			ClientAuth: tls.VerifyClientCertIfGiven,

			Certificates: certs,
			ClientCAs:    roots,

			MinVersion: tls.VersionTLS12,

			NextProtos: []string{http2.NextProtoTLS},
		}, nil
	}
}

// getCerts queries the datastore and returns a TLS serving certificate(s) plus
// the current CA root bundle.
func (e *Endpoints) getCerts(ctx context.Context) ([]tls.Certificate, *x509.CertPool, error) {
	bundle, err := e.DataStore.FetchBundle(dscache.WithCache(ctx), e.TrustDomain.IDString())
	if err != nil {
		return nil, nil, fmt.Errorf("get bundle from datastore: %w", err)
	}
	if bundle == nil {
		return nil, nil, errors.New("bundle not found")
	}

	var caCerts []*x509.Certificate
	for _, rootCA := range bundle.RootCas {
		rootCACerts, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse bundle: %w", err)
		}
		caCerts = append(caCerts, rootCACerts...)
	}

	caPool := x509.NewCertPool()
	for _, c := range caCerts {
		caPool.AddCert(c)
	}

	svidState := e.SVIDObserver.State()

	certChain := [][]byte{}
	for _, cert := range svidState.SVID {
		certChain = append(certChain, cert.Raw)
	}

	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  svidState.Key,
	}

	return []tls.Certificate{tlsCert}, caPool, nil
}

func (e *Endpoints) makeInterceptors() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	log := e.Log.WithField(telemetry.SubsystemName, "api")

	oldUnary, oldStream := wrapWithDeprecationLogging(log, auth.UnaryAuthorizeCall, auth.StreamAuthorizeCall)

	newUnary, newStream := middleware.Interceptors(Middleware(log, e.Metrics, e.DataStore, clock.New(), e.RateLimit))

	return unaryInterceptorMux(oldUnary, newUnary), streamInterceptorMux(oldStream, newStream)
}
