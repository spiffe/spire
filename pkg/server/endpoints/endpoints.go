package endpoints

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/endpoints/node"
	"github.com/spiffe/spire/pkg/server/endpoints/registration"
	"github.com/spiffe/spire/pkg/server/svid"

	node_pb "github.com/spiffe/spire/proto/api/node"
	registration_pb "github.com/spiffe/spire/proto/api/registration"
	datastore_pb "github.com/spiffe/spire/proto/server/datastore"

	"golang.org/x/net/context"

	"os"

	"github.com/spiffe/spire/pkg/agent/auth"
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

	svid    []*x509.Certificate
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
	hs := e.createUDSServer(ctx)

	e.registerNodeAPI(gs)
	e.registerRegistrationAPI(hs)

	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return e.runGRPCServer(ctx, gs)
		},
		func(ctx context.Context) error {
			return e.runUDSServer(ctx, hs)
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

func (e *endpoints) createUDSServer(ctx context.Context) *grpc.Server {
	return grpc.NewServer(grpc.Creds(auth.NewCredentials()))
}

// registerNodeAPI creates a Node API handler and registers it against
// the provided gRPC server.
func (e *endpoints) registerNodeAPI(gs *grpc.Server) {
	n := node.NewHandler(node.HandlerConfig{
		Log:         e.c.Log.WithField("subsystem_name", "node_api"),
		Metrics:     e.c.Metrics,
		Catalog:     e.c.Catalog,
		TrustDomain: e.c.TrustDomain,
		ServerCA:    e.c.ServerCA,
	})
	node_pb.RegisterNodeServer(gs, n)
}

// registerRegistrationAPI creates a Registration API handler and registers
// it against the provided gRPC.
func (e *endpoints) registerRegistrationAPI(hs *grpc.Server) {
	r := &registration.Handler{
		Log:         e.c.Log.WithField("subsystem_name", "registration_api"),
		Metrics:     e.c.Metrics,
		Catalog:     e.c.Catalog,
		TrustDomain: e.c.TrustDomain,
	}

	registration_pb.RegisterRegistrationServer(hs, r)
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
	e.c.Log.Infof("Starting gRPC server on %s", l.Addr())
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping gRPC server")
		l.Close()
		server.Stop()
		<-errChan
		e.c.Log.Info("gRPC server has stopped.")
		return nil
	}
}

// runUDSServer  will start the server and block until it exits or we are dying.
func (e *endpoints) runUDSServer(ctx context.Context, server *grpc.Server) error {
	os.Remove(e.c.UDSAddr.String())
	l, err := net.Listen(e.c.UDSAddr.Network(), e.c.UDSAddr.String())
	if err != nil {
		return err
	}
	os.Chmod(e.c.UDSAddr.String(), 0770)
	defer l.Close()

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.c.Log.Infof("Starting UDS server %s", l.Addr())
	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		e.c.Log.Info("Stopping UDS server")
		l.Close()
		server.Stop()
		<-errChan
		e.c.Log.Info("UDS server has stopped.")
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

// getCerts queries the datastore and returns a TLS serving certificate(s) plus
// the current CA root bundle.
func (e *endpoints) getCerts(ctx context.Context) ([]tls.Certificate, *x509.CertPool, error) {
	ds := e.c.Catalog.DataStores()[0]

	resp, err := ds.FetchBundle(ctx, &datastore_pb.FetchBundleRequest{
		TrustDomainId: e.c.TrustDomain.String(),
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

	e.mtx.RLock()
	defer e.mtx.RUnlock()

	certChain := [][]byte{}
	for i, cert := range e.svid {
		certChain = append(certChain, cert.Raw)
		// add the intermediates into the root CA pool since we need to
		// validate old agents that don't present intermediates with the
		// certificate request.
		// TODO: remove this hack in 0.8
		if i > 0 {
			caPool.AddCert(cert)
		}
	}

	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  e.svidKey,
	}

	return []tls.Certificate{tlsCert}, caPool, nil
}

func (e *endpoints) updateSVID() {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	state := e.c.SVIDStream.Value().(svid.State)
	e.svid = state.SVID
	e.svidKey = state.Key
}

func (e *endpoints) getSVIDState() svid.State {
	e.mtx.RLock()
	defer e.mtx.RUnlock()
	return svid.State{
		SVID: e.svid,
		Key:  e.svidKey,
	}
}
