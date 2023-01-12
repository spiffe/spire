package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
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
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
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
	TCPAddr                      *net.TCPAddr
	LocalAddr                    net.Addr
	SVIDObserver                 svid.Observer
	TrustDomain                  spiffeid.TrustDomain
	DataStore                    datastore.DataStore
	BundleCache                  *bundle.Cache
	APIServers                   APIServers
	BundleEndpointServer         Server
	Log                          logrus.FieldLogger
	Metrics                      telemetry.Metrics
	RateLimit                    RateLimitConfig
	EntryFetcherCacheRebuildTask func(context.Context) error
	AuditLogEnabled              bool
	AuthPolicyEngine             *authpolicy.Engine
	AdminIDs                     []spiffeid.ID
}

type APIServers struct {
	AgentServer       agentv1.AgentServer
	BundleServer      bundlev1.BundleServer
	DebugServer       debugv1_pb.DebugServer
	EntryServer       entryv1.EntryServer
	HealthServer      grpc_health_v1.HealthServer
	SVIDServer        svidv1.SVIDServer
	TrustDomainServer trustdomainv1.TrustDomainServer
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
	if err := prepareLocalAddr(c.LocalAddr); err != nil {
		return nil, err
	}

	if c.AuthPolicyEngine == nil {
		return nil, errors.New("policy engine not provided for new endpoint")
	}

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

	ds := c.Catalog.GetDataStore()

	return &Endpoints{
		TCPAddr:                      c.TCPAddr,
		LocalAddr:                    c.LocalAddr,
		SVIDObserver:                 c.SVIDObserver,
		TrustDomain:                  c.TrustDomain,
		DataStore:                    ds,
		BundleCache:                  bundle.NewCache(ds, c.Clock),
		APIServers:                   c.makeAPIServers(ef),
		BundleEndpointServer:         c.maybeMakeBundleEndpointServer(),
		Log:                          c.Log,
		Metrics:                      c.Metrics,
		RateLimit:                    c.RateLimit,
		EntryFetcherCacheRebuildTask: ef.RunRebuildCacheTask,
		AuditLogEnabled:              c.AuditLogEnabled,
		AuthPolicyEngine:             c.AuthPolicyEngine,
		AdminIDs:                     c.AdminIDs,
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

	// New APIs
	agentv1.RegisterAgentServer(tcpServer, e.APIServers.AgentServer)
	agentv1.RegisterAgentServer(udsServer, e.APIServers.AgentServer)
	bundlev1.RegisterBundleServer(tcpServer, e.APIServers.BundleServer)
	bundlev1.RegisterBundleServer(udsServer, e.APIServers.BundleServer)
	entryv1.RegisterEntryServer(tcpServer, e.APIServers.EntryServer)
	entryv1.RegisterEntryServer(udsServer, e.APIServers.EntryServer)
	svidv1.RegisterSVIDServer(tcpServer, e.APIServers.SVIDServer)
	svidv1.RegisterSVIDServer(udsServer, e.APIServers.SVIDServer)
	trustdomainv1.RegisterTrustDomainServer(tcpServer, e.APIServers.TrustDomainServer)
	trustdomainv1.RegisterTrustDomainServer(udsServer, e.APIServers.TrustDomainServer)

	// Register Health and Debug only on UDS server
	grpc_health_v1.RegisterHealthServer(udsServer, e.APIServers.HealthServer)
	debugv1_pb.RegisterDebugServer(udsServer, e.APIServers.DebugServer)

	tasks := []func(context.Context) error{
		func(ctx context.Context) error {
			return e.runTCPServer(ctx, tcpServer)
		},
		func(ctx context.Context) error {
			return e.runLocalAccess(ctx, udsServer)
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
	options := []grpc.ServerOption{
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	}

	if e.AuditLogEnabled {
		options = append(options, grpc.Creds(peertracker.NewCredentials()))
	} else {
		options = append(options, grpc.Creds(auth.UntrackedUDSCredentials()))
	}

	return grpc.NewServer(options...)
}

// runTCPServer will start the server and block until it exits or we are dying.
func (e *Endpoints) runTCPServer(ctx context.Context, server *grpc.Server) error {
	l, err := net.Listen(e.TCPAddr.Network(), e.TCPAddr.String())
	if err != nil {
		return err
	}
	defer l.Close()
	log := e.Log.WithFields(logrus.Fields{
		telemetry.Network: l.Addr().Network(),
		telemetry.Address: l.Addr().String()})

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	log.Info("Starting Server APIs")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		log.WithError(err).Error("Server APIs stopped prematurely")
		return err
	case <-ctx.Done():
		log.Info("Stopping Server APIs")
		server.Stop()
		<-errChan
		log.Info("Server APIs have stopped")
		return nil
	}
}

// runLocalAccess will start a grpc server to be accessed locally
// and block until it exits or we are dying.
func (e *Endpoints) runLocalAccess(ctx context.Context, server *grpc.Server) error {
	os.Remove(e.LocalAddr.String())
	var l net.Listener
	var err error
	if e.AuditLogEnabled {
		l, err = e.listenWithAuditLog()
	} else {
		l, err = e.listen()
	}

	if err != nil {
		return err
	}
	defer l.Close()

	if err := e.restrictLocalAddr(); err != nil {
		return err
	}

	log := e.Log.WithFields(logrus.Fields{
		telemetry.Network: l.Addr().Network(),
		telemetry.Address: l.Addr().String()})

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	log.Info("Starting Server APIs")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err := <-errChan:
		log.WithError(err).Error("Server APIs stopped prematurely")
		return err
	case <-ctx.Done():
		log.Info("Stopping Server APIs")
		server.Stop()
		<-errChan
		log.Info("Server APIs have stopped")
		return nil
	}
}

// getTLSConfig returns a TLS Config hook for the gRPC server
func (e *Endpoints) getTLSConfig(ctx context.Context) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		svidSrc := newX509SVIDSource(func() svid.State {
			return e.SVIDObserver.State()
		})
		bundleSrc := newBundleSource(func(td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
			return e.bundleGetter(ctx, td)
		})

		spiffeTLSConfig := tlsconfig.MTLSServerConfig(svidSrc, bundleSrc, nil)
		// provided client certificates will be validated using the custom VerifyPeerCertificate hook
		spiffeTLSConfig.ClientAuth = tls.RequestClientCert
		spiffeTLSConfig.MinVersion = tls.VersionTLS12
		spiffeTLSConfig.NextProtos = []string{http2.NextProtoTLS}
		spiffeTLSConfig.VerifyPeerCertificate = e.serverSpiffeVerificationFunc(bundleSrc)

		return spiffeTLSConfig, nil
	}
}

func (e *Endpoints) makeInterceptors() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	log := e.Log.WithField(telemetry.SubsystemName, "api")

	return middleware.Interceptors(Middleware(log, e.Metrics, e.DataStore, clock.New(), e.RateLimit, e.AuthPolicyEngine, e.AuditLogEnabled, e.AdminIDs))
}
