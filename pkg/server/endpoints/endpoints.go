package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	datastore_pb "github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
	agentv1_pb "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	bundlev1_pb "github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	entryv1_pb "github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	svidv1_pb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	node_pb "github.com/spiffe/spire/proto/spire/api/node"
	registration_pb "github.com/spiffe/spire/proto/spire/api/registration"
)

// This is the maximum amount of time an agent connection may exist before
// the server sends a hangup request. This enables agents to more dynamically
// route to the server in the case of a change in DNS membership.
const defaultMaxConnectionAge = 3 * time.Minute

// Server manages gRPC and HTTP endpoint lifecycle
type Server interface {
	// ListenAndServe starts all endpoint servers and blocks until the context
	// is canceled or any of the servers fails to run. If the context is
	// canceled, the function returns nil. Otherwise, the error from the failed
	// server is returned.
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	TCPAddr             *net.TCPAddr
	UDSAddr             *net.UnixAddr
	SVIDObserver        svid.Observer
	TrustDomain         spiffeid.TrustDomain
	DataStore           datastore.DataStore
	RegistrationServer  registration_pb.RegistrationServer
	NodeServer          node_pb.NodeServer
	BundleServer        Server
	ExperimentalServers *ExperimentalServers
	Log                 logrus.FieldLogger
	Metrics             telemetry.Metrics
}

type ExperimentalServers struct {
	AgentServer  agentv1_pb.AgentServer
	BundleServer bundlev1_pb.BundleServer
	EntryServer  entryv1_pb.EntryServer
	SVIDServer   svidv1_pb.SVIDServer
}

// New creates new endpoints struct
func New(c Config) (*Endpoints, error) {
	nodeHandler, err := c.makeNodeHandler()
	if err != nil {
		return nil, err
	}

	return &Endpoints{
		TCPAddr:             c.TCPAddr,
		UDSAddr:             c.UDSAddr,
		SVIDObserver:        c.SVIDObserver,
		TrustDomain:         c.TrustDomain,
		DataStore:           c.Catalog.GetDataStore(),
		RegistrationServer:  c.makeRegistrationHandler(),
		NodeServer:          nodeHandler,
		BundleServer:        c.maybeMakeBundleServer(),
		ExperimentalServers: c.maybeMakeExperimentalServers(),
		Log:                 c.Log,
		Metrics:             c.Metrics,
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

	node_pb.RegisterNodeServer(tcpServer, e.NodeServer)
	registration_pb.RegisterRegistrationServer(tcpServer, e.RegistrationServer)
	registration_pb.RegisterRegistrationServer(udsServer, e.RegistrationServer)

	if ss := e.ExperimentalServers; ss != nil {
		agentv1_pb.RegisterAgentServer(tcpServer, ss.AgentServer)
		agentv1_pb.RegisterAgentServer(udsServer, ss.AgentServer)
		bundlev1_pb.RegisterBundleServer(tcpServer, ss.BundleServer)
		bundlev1_pb.RegisterBundleServer(udsServer, ss.BundleServer)
		entryv1_pb.RegisterEntryServer(tcpServer, ss.EntryServer)
		entryv1_pb.RegisterEntryServer(udsServer, ss.EntryServer)
		svidv1_pb.RegisterSVIDServer(tcpServer, ss.SVIDServer)
		svidv1_pb.RegisterSVIDServer(udsServer, ss.SVIDServer)
	}

	tasks := []func(context.Context) error{
		func(ctx context.Context) error {
			return e.runTCPServer(ctx, tcpServer)
		},
		func(ctx context.Context) error {
			return e.runUDSServer(ctx, udsServer)
		},
	}

	if e.BundleServer != nil {
		tasks = append(tasks, e.BundleServer.ListenAndServe)
	}

	err := util.RunTasks(ctx, tasks...)
	if err == context.Canceled {
		err = nil
	}
	return err
}

func (e *Endpoints) createTCPServer(ctx context.Context, unaryInterceptor grpc.UnaryServerInterceptor, streamInterceptor grpc.StreamServerInterceptor) *grpc.Server {
	tlsConfig := &tls.Config{
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
		e.Log.Info("TCP server has stopped.")
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
		e.Log.Info("UDS server has stopped.")
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
			// When bootstrapping, the agent does not yet have
			// an SVID. In order to include the bootstrap endpoint
			// in the same server as the rest of the Node API,
			// request but don't require a client certificate
			ClientAuth: tls.VerifyClientCertIfGiven,

			Certificates: certs,
			ClientCAs:    roots,

			MinVersion: tls.VersionTLS12,
		}, nil
	}
}

// getCerts queries the datastore and returns a TLS serving certificate(s) plus
// the current CA root bundle.
func (e *Endpoints) getCerts(ctx context.Context) ([]tls.Certificate, *x509.CertPool, error) {
	resp, err := e.DataStore.FetchBundle(ctx, &datastore_pb.FetchBundleRequest{
		TrustDomainId: e.TrustDomain.IDString(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("get bundle from datastore: %v", err)
	}
	if resp.Bundle == nil {
		return nil, nil, errors.New("bundle not found")
	}

	var caCerts []*x509.Certificate
	for _, rootCA := range resp.Bundle.RootCas {
		rootCACerts, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse bundle: %v", err)
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
	oldUnary, oldStream := auth.UnaryAuthorizeCall, auth.StreamAuthorizeCall
	if e.ExperimentalServers == nil {
		return oldUnary, oldStream
	}

	log := e.Log.WithField(telemetry.SubsystemName, "api")

	newUnary, newStream := middleware.Interceptors(Middleware(log, e.Metrics, e.DataStore))

	return unaryInterceptorMux(oldUnary, newUnary), streamInterceptorMux(oldStream, newStream)
}
