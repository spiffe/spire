package server

import (
	"context"
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
	"github.com/spiffe/spire/pkg/server/endpoints/node"
	"github.com/spiffe/spire/pkg/server/endpoints/registration"
	spinode "github.com/spiffe/spire/proto/api/node"
	spiregistration "github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"

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

type dependencies struct {
	DataStoreImpl    datastore.DataStore
	NodeAttestorImpl nodeattestor.NodeAttestor
	NodeResolverImpl noderesolver.NodeResolver
	ServerCAImpl     ca.ControlPlaneCa
	UpstreamCAImpl   upstreamca.UpstreamCa
}

type Server struct {
	Catalog      catalog.Catalog
	Config       *Config
	grpcServer   *grpc.Server
	dependencies *dependencies
	privateKey   *ecdsa.PrivateKey
	svid         *x509.Certificate
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

	server.initDependencies()

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

func (server *Server) initDependencies() {
	server.Config.Log.Info("Initiating dependencies")
	server.dependencies = &dependencies{}

	// TODO: Catch errors, pass catalog not plugins
	for _, p := range server.Catalog.Plugins() {
		switch p.Config.PluginType {
		case "DataStore":
			server.dependencies.DataStoreImpl = p.Plugin.(datastore.DataStore)
		case "NodeAttestor":
			server.dependencies.NodeAttestorImpl = p.Plugin.(nodeattestor.NodeAttestor)
		case "NodeResolver":
			server.dependencies.NodeResolverImpl = p.Plugin.(noderesolver.NodeResolver)
		case "ControlPlaneCA":
			server.dependencies.ServerCAImpl = p.Plugin.(ca.ControlPlaneCa)
		case "UpstreamCA":
			server.dependencies.UpstreamCAImpl = p.Plugin.(upstreamca.UpstreamCa)
		}
	}

	server.Config.Log.Info("Initiating dependencies done")
}

func (server *Server) initEndpoints() error {
	server.Config.Log.Info("Starting the Registration API")
	var registrationSvc registration.Service
	registrationSvc = registration.NewService(registration.Config{
		Logger:    server.Config.Log,
		DataStore: server.dependencies.DataStoreImpl,
	})
	registrationSvc = registration.ServiceLoggingMiddleWare(server.Config.Log)(registrationSvc)
	registrationEndpoints := getRegistrationEndpoints(registrationSvc)

	server.Config.Log.Info("Starting the Node API")
	nodeSvc := node.NewService(node.Config{
		Logger:          server.Config.Log,
		DataStore:       server.dependencies.DataStoreImpl,
		ServerCA:        server.dependencies.ServerCAImpl,
		NodeAttestor:    server.dependencies.NodeAttestorImpl,
		NodeResolver:    server.dependencies.NodeResolverImpl,
		BaseSpiffeIDTTL: server.Config.BaseSpiffeIDTTL,
	})
	nodeSvc = node.ServiceLoggingMiddleWare(server.Config.Log)(nodeSvc)
	nodeEnpoints := getNodeEndpoints(nodeSvc)

	// TODO: Fix me after server refactor
	crtRes, err := server.dependencies.ServerCAImpl.FetchCertificate(&ca.FetchCertificateRequest{})
	if err != nil {
		return err
	}
	certChain := [][]byte{server.svid.Raw, crtRes.StoredIntermediateCert}
	tlsCert := &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  server.privateKey,
	}

	certpool := x509.NewCertPool()
	intermCert, err := x509.ParseCertificate(crtRes.StoredIntermediateCert)
	if err != nil {
		return nil
	}
	certpool.AddCert(intermCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		ClientCAs:    certpool,
		ClientAuth:   tls.RequestClientCert,
	}

	server.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))

	registrationHandler := registration.MakeGRPCServer(registrationEndpoints)
	spiregistration.RegisterRegistrationServer(server.grpcServer, registrationHandler)

	nodeHandler := node.MakeGRPCServer(nodeEnpoints)
	spinode.RegisterNodeServer(server.grpcServer, nodeHandler)

	server.Config.Log.Info(server.Config.BindAddress.String())
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
		server.Config.Log.Info(server.Config.BindHTTPAddress.String())
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
	signReq := &ca.SignCsrRequest{Csr: csr}
	res, err := server.dependencies.ServerCAImpl.SignCsr(signReq)
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

	csrRes, err := server.dependencies.ServerCAImpl.GenerateCsr(&ca.GenerateCsrRequest{})
	if err != nil {
		return err
	}

	signRes, err := server.dependencies.UpstreamCAImpl.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return err
	}

	req := &ca.LoadCertificateRequest{SignedIntermediateCert: signRes.Cert}
	_, err = server.dependencies.ServerCAImpl.LoadCertificate(req)

	return err
}

func getRegistrationEndpoints(registrationSvc registration.Service) registration.Endpoints {
	return registration.Endpoints{
		CreateEntryEndpoint:           registration.MakeCreateEntryEndpoint(registrationSvc),
		DeleteEntryEndpoint:           registration.MakeDeleteEntryEndpoint(registrationSvc),
		FetchEntryEndpoint:            registration.MakeFetchEntryEndpoint(registrationSvc),
		UpdateEntryEndpoint:           registration.MakeUpdateEntryEndpoint(registrationSvc),
		ListByParentIDEndpoint:        registration.MakeListByParentIDEndpoint(registrationSvc),
		ListBySelectorEndpoint:        registration.MakeListBySelectorEndpoint(registrationSvc),
		ListBySpiffeIDEndpoint:        registration.MakeListBySpiffeIDEndpoint(registrationSvc),
		CreateFederatedBundleEndpoint: registration.MakeCreateFederatedBundleEndpoint(registrationSvc),
		ListFederatedBundlesEndpoint:  registration.MakeListFederatedBundlesEndpoint(registrationSvc),
		UpdateFederatedBundleEndpoint: registration.MakeUpdateFederatedBundleEndpoint(registrationSvc),
		DeleteFederatedBundleEndpoint: registration.MakeDeleteFederatedBundleEndpoint(registrationSvc),
	}
}

func getNodeEndpoints(nodeSvc node.Service) node.Endpoints {
	return node.Endpoints{
		FetchBaseSVIDEndpoint:        node.MakeFetchBaseSVIDEndpoint(nodeSvc),
		FetchCPBundleEndpoint:        node.MakeFetchCPBundleEndpoint(nodeSvc),
		FetchFederatedBundleEndpoint: node.MakeFetchFederatedBundleEndpoint(nodeSvc),
		FetchSVIDEndpoint:            node.MakeFetchSVIDEndpoint(nodeSvc),
	}
}
