package endpoints

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/endpoints/node"
	"github.com/spiffe/spire/pkg/server/endpoints/registration"

	node_pb "github.com/spiffe/spire/proto/api/node"
	registration_pb "github.com/spiffe/spire/proto/api/registration"
	ca_pb "github.com/spiffe/spire/proto/server/ca"
	datastore_pb "github.com/spiffe/spire/proto/server/datastore"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"gopkg.in/tomb.v2"
)

// Server manages gRPC and HTTP endpoint lifecycle
type Server interface {
	// ListenAndServe starts all endpoints, and blocks for as long as the
	// underlying servers are still running. Returns an error if any of the
	// endpoints encounter one.
	ListenAndServe() error

	// Shutdown gracefully closes all underlying endpoint servers.
	// ListenAndServe will unblock with `nil` if/when shutdown completes
	// cleanly
	Shutdown()
}

type endpoints struct {
	c   *Config
	mtx *sync.RWMutex
	t   *tomb.Tomb

	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey

	svidCheck *time.Ticker

	grpcServer *grpc.Server
	httpServer *http.Server

	runOnce *sync.Once
}

// ListenAndServe starts all maintenance routines and endpoints, then blocks
// for as long as the underlying servers are still running. Returns an error
// if any of the endpoints encounter one.
func (e *endpoints) ListenAndServe() error {
	run := func() { e.t.Go(e.listenAndServe) }
	e.runOnce.Do(run)

	return e.t.Wait()
}

// Shutdown gracefully closes all underlying endpoint servers.
func (e *endpoints) Shutdown() {
	e.t.Kill(nil)
	return
}

// listenAndServe creates listeners and starts all servers. It serves
// as the top-most tomb routine.
func (e *endpoints) listenAndServe() error {
	// Certs must be ready before anything else
	err := e.rotateSVID()
	if err != nil {
		return err
	}

	e.c.Log.Debug("Initializing API endpoints")
	gs := e.createGRPCServer()
	hs := e.createHTTPServer()

	e.registerNodeAPI(gs)
	err = e.registerRegistrationAPI(gs, hs)
	if err != nil {
		return err
	}

	e.grpcServer = gs
	e.httpServer = hs

	e.t.Go(e.startGRPCServer)
	e.t.Go(e.startHTTPServer)
	e.t.Go(e.startRotator)

	return nil
}

func (e *endpoints) createGRPCServer() *grpc.Server {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	tlsConfig := &tls.Config{
		GetConfigForClient: e.getGRPCServerConfig,
	}

	opts := grpc.Creds(credentials.NewTLS(tlsConfig))
	return grpc.NewServer(opts)
}

func (e *endpoints) createHTTPServer() *http.Server {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	tlsConfig := &tls.Config{
		GetConfigForClient: e.getHTTPServerConfig,
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
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	n := &node.Handler{
		Log:         e.c.Log.WithField("subsystem_name", "node_api"),
		Catalog:     e.c.Catalog,
		TrustDomain: e.c.TrustDomain,
	}

	node_pb.RegisterNodeServer(gs, n)
}

// registerRegistrationAPI creates a Registration API handler and registers
// it against the provided gRPC and HTTP servers.
func (e *endpoints) registerRegistrationAPI(gs *grpc.Server, hs *http.Server) error {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

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
		Log:     e.c.Log.WithField("subsystem_name", "registration_api"),
		Catalog: e.c.Catalog,
	}

	// Register the handler with gRPC first
	registration_pb.RegisterRegistrationServer(gs, r)
	err := registration_pb.RegisterRegistrationHandlerFromEndpoint(context.TODO(), httpMux, e.c.GRPCAddr.String(), grpcOpts)
	if err != nil {
		return fmt.Errorf("error creating http gateway: %s", err.Error())
	}

	return nil
}

// startGRPCServer will start the server and block until it exits or we are dying.
func (e *endpoints) startGRPCServer() error {
	l, err := net.Listen(e.c.GRPCAddr.Network(), e.c.GRPCAddr.String())
	if err != nil {
		return err
	}

	if e.c.GRPCHook != nil {
		err := e.c.GRPCHook(e.grpcServer)
		if err != nil {
			return fmt.Errorf("call grpc hook: %v", err)
		}
	}

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.c.Log.Info("Starting gRPC server")
	errChan := make(chan error)
	go func() { errChan <- e.grpcServer.Serve(l) }()

	select {
	case err = <-errChan:
		return err
	case <-e.t.Dying():
		e.c.Log.Info("Stopping gRPC server")
		e.grpcServer.Stop()
		l.Close()
		<-errChan
		return nil
	}

	return nil
}

// startHTTPServer will start the server and block until it exits or we are dying.
func (e *endpoints) startHTTPServer() error {
	l, err := net.Listen(e.c.HTTPAddr.Network(), e.c.HTTPAddr.String())
	if err != nil {
		return err
	}

	// Skip use of tomb here so we don't pollute a clean shutdown with errors
	e.c.Log.Info("Starting HTTP server")
	errChan := make(chan error)
	go func() { errChan <- e.httpServer.Serve(l) }()

	select {
	case err := <-errChan:
		return err
	case <-e.t.Dying():
		e.c.Log.Info("Stopping HTTP server")
		e.httpServer.Close()
		l.Close()
		<-errChan
		return nil
	}

	return nil
}

// startRotator starts a ticker which monitors the server SVID
// for expiration and invokes rotateSVID() as necessary.
func (e *endpoints) startRotator() error {
	for {
		select {
		case <-e.t.Dying():
			e.c.Log.Debug("Stopping SVID rotator")
			return nil
		case <-e.svidCheck.C:
			e.mtx.RLock()
			ttl := e.svid.NotAfter.Sub(time.Now())
			watermark := e.svid.NotAfter.Sub(e.svid.NotBefore) / 2
			e.mtx.RUnlock()

			if ttl < watermark {
				err := e.rotateSVID()
				if err != nil {
					return err
				}
			}

		}
	}
}

// rotateSVID cuts a new server SVID from the CA plugin and installs
// it on the endpoints struct. Also updates the CA certificates.
func (e *endpoints) rotateSVID() error {
	e.c.Log.Debug("Rotating server SVID")

	e.mtx.RLock()
	id := &url.URL{
		Scheme: "spiffe",
		Host:   e.c.TrustDomain.Host,
		Path:   path.Join("spiffe", "cp"),
	}
	e.mtx.RUnlock()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSR(key, id.String())
	if err != nil {
		return err
	}

	ca := e.c.Catalog.CAs()[0]

	// Sign the CSR
	csrReq := &ca_pb.SignCsrRequest{Csr: csr}
	csrRes, err := ca.SignCsr(csrReq)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(csrRes.SignedCertificate)
	if err != nil {
		return err
	}

	e.mtx.Lock()
	defer e.mtx.Unlock()
	e.svid = cert
	e.svidKey = key
	return nil
}

// getGRPCServerConfig implements a TLS Config hook for the gRPC server
func (e *endpoints) getGRPCServerConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	certs, roots, err := e.getCerts()
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

// getHTTPConfig implements a TLS Config hook for the HTTP server.
func (e *endpoints) getHTTPServerConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	certs, _, err := e.getCerts()
	if err != nil {
		e.c.Log.Errorf("Could not generate TLS config for HTTP client %v: %v", hello.Conn.RemoteAddr(), err)
		return nil, err
	}

	c := &tls.Config{
		Certificates: certs,
	}

	return c, nil
}

// getCerts queries the datastore and returns a TLS serving certificate(s) plus
// the current CA root bundle.
func (e *endpoints) getCerts() ([]tls.Certificate, *x509.CertPool, error) {
	ds := e.c.Catalog.DataStores()[0]
	req := &datastore_pb.Bundle{
		TrustDomain: e.c.TrustDomain.String(),
	}
	b, err := ds.FetchBundle(req)
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
