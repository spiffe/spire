package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/server/catalog"
	spinode "github.com/spiffe/spire/proto/api/node"
	spiregistration "github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Config struct {
	// TTL we will use when creating the baseSpiffeID
	BaseSpiffeIDTTL int32

	// Directory for plugin configs
	PluginDir string

	Log logrus.FieldLogger

	// Address of SPIRE server
	BindAddress *net.TCPAddr

	// Address of the HTTP SPIRE server
	BindHTTPAddress *net.TCPAddr

	// A channel for receiving errors from server goroutines
	ErrorCh chan error

	// A channel to trigger server shutdown
	ShutdownCh chan struct{}

	// Trust domain
	TrustDomain url.URL
}

type Server struct {
	Catalog    catalog.Catalog
	Config     *Config
	grpcServer *grpc.Server
	privateKey *ecdsa.PrivateKey
	svid       *x509.Certificate
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks on the main event loop.
func (server *Server) Run() error {
	err := server.initPlugins()
	defer server.stopPlugins()
	if err != nil {
		return err
	}

	err = server.rotateSigningCert()
	if err != nil {
		return err
	}

	server.svid, server.privateKey, err = server.rotateSVID()
	if err != nil {
		return err
	}

	err = server.initEndpoints()
	if err != nil {
		return err
	}

	// Main event loop
	server.Config.Log.Info("SPIRE Server is now running")

	for {
		select {
		case err = <-server.Config.ErrorCh:
			return err
		case <-server.Config.ShutdownCh:
			server.grpcServer.GracefulStop()
			return <-server.Config.ErrorCh
		}
	}
}

func (server *Server) initPlugins() error {
	config := &catalog.Config{
		ConfigDir: server.Config.PluginDir,
		Log:       server.Config.Log.WithField("subsystem_name", "catalog"),
	}

	server.Catalog = catalog.New(config)

	err := server.Catalog.Run()
	if err != nil {
		return err
	}

	server.Config.Log.Info("Starting plugins done")

	return nil
}

func (server *Server) stopPlugins() {
	if server.Catalog != nil {
		server.Catalog.Stop()
	}
}

func (server *Server) initEndpoints() error {
	grpcServer, err := server.getGRPCServer()
	if err != nil {
		return err
	}
	server.grpcServer = grpcServer

	server.Config.Log.Debug("Starting the Registration API")
	rs := &registrationServer{
		l:       server.Config.Log,
		catalog: server.Catalog,
	}
	spiregistration.RegisterRegistrationServer(server.grpcServer, rs)

	server.Config.Log.Debug("Starting the Node API")
	ns := &nodeServer{
		l:               server.Config.Log,
		catalog:         server.Catalog,
		trustDomain:     server.Config.TrustDomain,
		baseSpiffeIDTTL: server.Config.BaseSpiffeIDTTL,
	}
	spinode.RegisterNodeServer(server.grpcServer, ns)

	server.Config.Log.Info("Node API started at ", server.Config.BindAddress.String())
	listener, err := net.Listen(server.Config.BindAddress.Network(), server.Config.BindAddress.String())
	if err != nil {
		return fmt.Errorf("Error creating GRPC listener: %s", err)
	}

	//gRPC
	go func() {
		server.Config.ErrorCh <- server.grpcServer.Serve(listener)
	}()

	//http
	go func() {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// TODO: Pass a bundle in here
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		mux := runtime.NewServeMux()
		opt := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
		opts := []grpc.DialOption{opt}

		err := spiregistration.RegisterRegistrationHandlerFromEndpoint(ctx, mux, server.Config.BindAddress.String(), opts)
		if err != nil {
			server.Config.ErrorCh <- err
			return
		}
		server.Config.Log.Info("Registration API started at ", server.Config.BindHTTPAddress.String())
		server.Config.ErrorCh <- http.ListenAndServe(server.Config.BindHTTPAddress.String(), mux)
	}()

	return nil
}

func (server *Server) rotateSVID() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   server.Config.TrustDomain.Host,
		Path:   path.Join("spiffe", "cp"),
	}

	l := server.Config.Log.WithField("SPIFFE_ID", spiffeID.String())
	l.Info("Rotating SPIRE server SVID")

	uriSAN, err := uri.MarshalUriSANs([]string{spiffeID.String()})
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	req := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{{
			Id:       uri.OidExtensionSubjectAltName,
			Value:    uriSAN,
			Critical: false,
		}},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, nil, err
	}

	l.Debug("Sending CSR to the CA plugin")
	serverCA := server.Catalog.CAs()[0]
	res, err := serverCA.SignCsr(&ca.SignCsrRequest{Csr: csr, Ttl: server.Config.BaseSpiffeIDTTL})
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(res.SignedCertificate)
	if err != nil {
		return nil, nil, err
	}

	l.Debug("SPIRE server SVID rotation complete")
	return cert, key, nil
}

func (server *Server) rotateSigningCert() error {
	server.Config.Log.Info("Initiating rotation of signing certificate")

	serverCA := server.Catalog.CAs()[0]
	csrRes, err := serverCA.GenerateCsr(&ca.GenerateCsrRequest{})
	if err != nil {
		return err
	}
	upstreamCA := server.Catalog.UpstreamCAs()[0]
	signRes, err := upstreamCA.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return err
	}

	req := &ca.LoadCertificateRequest{SignedIntermediateCert: signRes.Cert}
	_, err = serverCA.LoadCertificate(req)

	return err
}

func (server *Server) getGRPCServer() (*grpc.Server, error) {
	serverCA := server.Catalog.CAs()[0]
	crtRes, err := serverCA.FetchCertificate(&ca.FetchCertificateRequest{})
	if err != nil {
		return nil, err
	}
	certChain := [][]byte{server.svid.Raw, crtRes.StoredIntermediateCert}
	tlsCert := &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  server.privateKey,
	}

	certpool := x509.NewCertPool()
	intermCert, err := x509.ParseCertificate(crtRes.StoredIntermediateCert)
	if err != nil {
		return nil, err
	}
	certpool.AddCert(intermCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		ClientCAs:    certpool,
		ClientAuth:   tls.RequestClientCert,
	}

	return grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig))), nil
}
