package endpoints

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/endpoints/node"
	"github.com/spiffe/spire/pkg/server/endpoints/registration"
	"github.com/spiffe/spire/pkg/server/svid"

	node_pb "github.com/spiffe/spire/proto/api/node"
	registration_pb "github.com/spiffe/spire/proto/api/registration"
	datastore_pb "github.com/spiffe/spire/proto/server/datastore"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server manages gRPC and HTTP endpoint lifecycle
type Server interface {
	// ListenAndServe starts all endpoints, and blocks for as long as the
	// underlying servers are still running. Returns an error if any of the
	// endpoints encounter one. ListenAndServe will return an
	ListenAndServe(ctx context.Context) error
}

type endpoints struct {
	c   *Config
	mtx *sync.RWMutex

	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey
}

// ListenAndServe starts all maintenance routines and endpoints, then blocks
// until the context is cancelled or there is an error encountered listening
// on one of the servers.
func (e *endpoints) ListenAndServe(ctx context.Context) error {
	// Certs must be ready before anything else
	e.updateSVID()

	e.c.Log.Debug("Initializing API endpoints")
	gs := e.createGRPCServer(ctx)
	hs := e.createHTTPServer(ctx)

	e.registerNodeAPI(gs)
	if err := e.registerRegistrationAPI(ctx, gs, hs); err != nil {
		return err
	}

	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return e.runGRPCServer(ctx, gs)
		},
		func(ctx context.Context) error {
			return e.runHTTPServer(ctx, hs)
		},
		e.runSVIDObserver,
	)
	if err == context.Canceled {
		err = nil
	}
	return err
}

func (e *endpoints) createGRPCServer(ctx context.Context) *grpc.Server {
	tlsConfig := &tls.Config{
		GetConfigForClient: e.getGRPCServerConfig(ctx),
	}

	opts := grpc.Creds(credentials.NewTLS(tlsConfig))
	return grpc.NewServer(opts)
}

func (e *endpoints) createHTTPServer(ctx context.Context) *http.Server {
	tlsConfig := &tls.Config{
		GetConfigForClient: e.getHTTPServerConfig(ctx),
	}

	s := &http.Server{
		TLSConfig: tlsConfig,
		Handler:   runtime.NewServeMux(),
	}

	return s
}

// registerNodeAPI creates a Node API handler and registers it against
// the provided gRPC server.
func (e *endpoints) registerNodeAPI(gs *grpc.Server) {
	n := node.NewHandler(node.HandlerConfig{
		Log:         e.c.Log.WithField("subsystem_name", "node_api"),
		Catalog:     e.c.Catalog,
		TrustDomain: e.c.TrustDomain,
	})
	node_pb.RegisterNodeServer(gs, n)
}

// registerRegistrationAPI creates a Registration API handler and registers
// it against the provided gRPC and HTTP servers.
func (e *endpoints) registerRegistrationAPI(ctx context.Context, gs *grpc.Server, hs *http.Server) error {
	// gRPC client config for HTTP-to-gRPC gateway
	// Configure WithInsecure because 1) it's assumed to be local, and 2) because
	// TLS config can't be hooked here to support root rotation
	grpcOpts := []grpc.DialOption{grpc.WithInsecure()}

	// This should never really fail since we have initially set it as this
	// type in createHTTPServer()
	httpMux, ok := hs.Handler.(*runtime.ServeMux)
	if !ok {
		return fmt.Errorf("error creating http gateway")
	}

	r := &registration.Handler{
		Log:         e.c.Log.WithField("subsystem_name", "registration_api"),
		Catalog:     e.c.Catalog,
		TrustDomain: e.c.TrustDomain,
	}

	// Register the handler with gRPC first
	registration_pb.RegisterRegistrationServer(gs, r)
	err := registration_pb.RegisterRegistrationHandlerFromEndpoint(ctx, httpMux, e.c.GRPCAddr.String(), grpcOpts)
	if err != nil {
		return fmt.Errorf("error creating http gateway: %s", err.Error())
	}

	return nil
}

// runGRPCServer will start the server and block until it exits or we are dying.
func (e *endpoints) runGRPCServer(ctx context.Context, server *grpc.Server) error {
	l, err := net.Listen(e.c.GRPCAddr.Network(), e.c.GRPCAddr.String())
	if err != nil {
		return err
	}
	defer l.Close()

	if e.c.GRPCHook != nil {
		err := e.c.GRPCHook(server)
		if err != nil {
			return fmt.Errorf("call grpc hook: %v", err)
		}
	}

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.c.Log.Info("Starting gRPC server")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping gRPC server")
		server.Stop()
		<-errChan
		return nil
	}
}

// runHTTPServer will start the server and block until it exits or we are dying.
func (e *endpoints) runHTTPServer(ctx context.Context, server *http.Server) error {
	l, err := net.Listen(e.c.HTTPAddr.Network(), e.c.HTTPAddr.String())
	if err != nil {
		return err
	}
	defer l.Close()

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.c.Log.Info("Starting HTTP server")
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping HTTP server")
		server.Close()
		l.Close()
		<-errChan
		return nil
	}

	return nil
}

func (e *endpoints) runSVIDObserver(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-e.c.SVIDStream.Changes():
			e.c.SVIDStream.Next()
			e.updateSVID()
		}
	}
}

// getGRPCServerConfig returns a TLS Config hook for the gRPC server
func (e *endpoints) getGRPCServerConfig(ctx context.Context) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		certs, roots, err := e.getCerts(ctx)
		if err != nil {
			e.c.Log.Errorf("Could not generate TLS config for gRPC client %v: %v", hello.Conn.RemoteAddr(), err)
			return nil, err
		}

		c := &tls.Config{
			// When bootstrapping, the agent does not yet have
			// an SVID. In order to include the bootstrap endpoint
			// in the same server as the rest of the Node API,
			// request but don't require a client certificate
			ClientAuth: tls.RequestClientCert,

			Certificates: certs,
			ClientCAs:    roots,
		}
		return c, nil
	}
}

// getHTTPConfig returns a TLS Config hook for the HTTP server.
func (e *endpoints) getHTTPServerConfig(ctx context.Context) func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		certs, _, err := e.getCerts(ctx)
		if err != nil {
			e.c.Log.Errorf("Could not generate TLS config for HTTP client %v: %v", hello.Conn.RemoteAddr(), err)
			return nil, err
		}

		c := &tls.Config{
			Certificates: certs,
		}

		return c, nil
	}
}

// getCerts queries the datastore and returns a TLS serving certificate(s) plus
// the current CA root bundle.
func (e *endpoints) getCerts(ctx context.Context) ([]tls.Certificate, *x509.CertPool, error) {
	ds := e.c.Catalog.DataStores()[0]
	req := &datastore_pb.Bundle{
		TrustDomain: e.c.TrustDomain.String(),
	}
	b, err := ds.FetchBundle(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("get bundle from datastore: %v", err)
	}

	caCerts, err := x509.ParseCertificates(b.CaCerts)
	if err != nil {
		return nil, nil, fmt.Errorf("parse bundle: %v", err)
	}

	caPool := x509.NewCertPool()
	for _, c := range caCerts {
		caPool.AddCert(c)
	}

	e.mtx.RLock()
	defer e.mtx.RUnlock()

	servingCA, err := e.findServingCA(e.svid, caCerts)
	if err != nil {
		return nil, nil, fmt.Errorf("find serving CA: %v", err)
	}

	certChain := [][]byte{e.svid.Raw, servingCA.Raw}
	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  e.svidKey,
	}

	return []tls.Certificate{tlsCert}, caPool, nil
}

// findServingCA attempts to identify which CA certificate issued our current serving SVID.
func (e *endpoints) findServingCA(svid *x509.Certificate, caCerts []*x509.Certificate) (*x509.Certificate, error) {
	var servingCA *x509.Certificate
	for _, ca := range caCerts {
		result := bytes.Compare(svid.AuthorityKeyId, ca.SubjectKeyId)

		if result == 0 {
			servingCA = ca
			break
		}
	}

	if servingCA == nil {
		return nil, errors.New("no match found")
	}

	return servingCA, nil
}

func (e *endpoints) updateSVID() {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	state := e.c.SVIDStream.Value().(svid.State)
	e.svid = state.SVID
	e.svidKey = state.Key
}
