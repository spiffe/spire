package endpoint

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/api/registration"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Endpoint manages gRPC and HTTP server lifecycle,
// and registers the appropriate endpoints.
type Endpoint interface {
	// ListenAndServe starts all endpoints, and
	// blocks for as long as the underlying servers
	// are still running.
	ListenAndServe() error

	// Shutdown gracefully closes all underlying
	// servers. ListenAndServe will unblock with
	// `nil` if shutdown completes cleanly
	Shutdown()
}

type Config struct {
	NS node.NodeServer
	RS registration.RegistrationServer

	// Addresses to bind the servers to
	GRPCAddr *net.TCPAddr
	HTTPAddr *net.TCPAddr

	// SVID to use for server TLS
	SVID    *x509.Certificate
	SVIDKey *ecdsa.PrivateKey

	// Our CA signing cert, used in our server TLS
	// chain and also as a root for client auth
	CACert *x509.Certificate

	Log logrus.FieldLogger
}

func New(c *Config) *endpoint {
	return &endpoint{
		ns:       c.NS,
		rs:       c.RS,
		grpcAddr: c.GRPCAddr,
		httpAddr: c.HTTPAddr,
		svid:     c.SVID,
		svidKey:  c.SVIDKey,
		caCert:   c.CACert,
		log:      c.Log,
	}
}

type endpoint struct {
	ns node.NodeServer
	rs registration.RegistrationServer

	grpcAddr *net.TCPAddr
	httpAddr *net.TCPAddr

	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey
	caCert  *x509.Certificate

	grpcServer *grpc.Server
	httpServer *http.Server

	log logrus.FieldLogger
}

func (e *endpoint) ListenAndServe() error {
	e.log.Debug("Initializing endpoints")

	e.createGRPCServer()
	e.createHTTPServer()

	e.initNodeAPI()
	err := e.initRegistrationAPI()
	if err != nil {
		return err
	}

	return e.listenAndServe()
}

func (e *endpoint) Shutdown() {
	e.stopHTTPServer()
	e.stopGRPCServer()
}

func (e *endpoint) createGRPCServer() {
	// Include our CA cert in the chain for bootstrapping
	certChain := [][]byte{e.svid.Raw, e.caCert.Raw}
	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  e.svidKey,
	}

	// Use our CA cert as the root for client auth
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(e.caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    clientCAs,

		// When bootstrapping, the agent does not yet have
		// an SVID. In order to include the bootstrap endpoint
		// in the same server as the rest of the Node API,
		// request but don't require a client certificate
		ClientAuth: tls.RequestClientCert,
	}

	opts := grpc.Creds(credentials.NewTLS(tlsConfig))
	e.grpcServer = grpc.NewServer(opts)
}

func (e *endpoint) createHTTPServer() {
	// Include our CA cert in the chain so clients with the
	// Upstream CA cert can validate us
	certChain := [][]byte{e.svid.Raw, e.caCert.Raw}
	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  e.svidKey,
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	s := &http.Server{
		Addr:      e.httpAddr.String(),
		TLSConfig: tlsConfig,
	}

	s.Handler = runtime.NewServeMux()
	e.httpServer = s
}

func (e *endpoint) initNodeAPI() {
	node.RegisterNodeServer(e.grpcServer, e.ns)
}

func (e *endpoint) initRegistrationAPI() error {
	registration.RegisterRegistrationServer(e.grpcServer, e.rs)

	// Client TLS config for HTTP gateway
	caCerts := x509.NewCertPool()
	caCerts.AddCert(e.caCert)
	tlsConfig := &tls.Config{RootCAs: caCerts}

	ctx := context.TODO()
	opt := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	// We know this will be successful because we created it as
	// such in createHTTPServer
	mux := e.httpServer.Handler.(*runtime.ServeMux)
	err := registration.RegisterRegistrationHandlerFromEndpoint(ctx, mux, e.grpcAddr.String(), []grpc.DialOption{opt})
	if err != nil {
		return fmt.Errorf("error creating http gateway: %s", err.Error())
	}

	return nil
}

func (e *endpoint) listenAndServe() error {
	grpcListener, err := net.Listen(e.grpcAddr.Network(), e.grpcAddr.String())
	if err != nil {
		return err
	}

	errChan := make(chan error)
	go func() {
		errChan <- e.grpcServer.Serve(grpcListener)
	}()

	go func() {
		errChan <- e.httpServer.ListenAndServe()
	}()

	// Differentiate between shutdown and an actual error condition
	err = <-errChan
	if e.isCleanShutdown(err) {
		// Ensure that the second server shutdown cleanly
		err = <-errChan
		if e.isCleanShutdown(err) {
			return nil
		}

		return err
	}

	e.grpcServer.Stop()
	_ = e.httpServer.Close()
	_ = <-errChan

	return err
}

func (e *endpoint) stopGRPCServer() {
	e.grpcServer.GracefulStop()
}

func (e *endpoint) stopHTTPServer() {
	_ = e.httpServer.Shutdown(context.TODO())
}

// isCleanShutdown determines whether a given error is an indicator
// of successful shutdown, as neither HTTP nor gRPC server return
// a nil error.
func (e *endpoint) isCleanShutdown(err error) bool {
	// Unfortunately, the error returned by grpc server is hard to
	// match. Construct the expected error string and attempt to match
	// on that. If the format ever changes, the result will be an error
	// during shutdown. We'll get to have another stab at this if/when
	// that happens.
	//
	// https://github.com/grpc/grpc-go/issues/1017
	// https://github.com/golang/go/commit/fb4b4342fe298fda640bfa74f24b7bd58519deba
	errStr := fmt.Sprintf("accept tcp %s: use of closed network connection", e.grpcAddr.String())

	if err == http.ErrServerClosed || err.Error() == errStr {
		return true
	}

	return false
}
