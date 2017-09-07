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
	"reflect"

	"github.com/go-kit/kit/log"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/helpers"

	pbnode "github.com/spiffe/spire/pkg/api/node"
	pbregistration "github.com/spiffe/spire/pkg/api/registration"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/endpoints/node"
	"github.com/spiffe/spire/pkg/server/endpoints/registration"
	"github.com/spiffe/spire/pkg/server/nodeattestor"
	"github.com/spiffe/spire/pkg/server/noderesolver"
	"github.com/spiffe/spire/pkg/server/upstreamca"
	"github.com/spiffe/spire/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	PluginTypeMap = map[string]plugin.Plugin{
		"ControlPlaneCA": &ca.ControlPlaneCaPlugin{},
		"NodeAttestor":   &nodeattestor.NodeAttestorPlugin{},
		"NodeResolver":   &noderesolver.NodeResolverPlugin{},
		"DataStore":      &datastore.DataStorePlugin{},
		"UpstreamCA":     &upstreamca.UpstreamCaPlugin{},
	}

	MaxPlugins = map[string]int{
		"ControlPlaneCA": 1,
		"NodeAttestor":   1,
		"NodeResolver":   1,
		"DataStore":      1,
		"UpstreamCA":     1,
	}
)

type Config struct {
	// TTL we will use when creating the baseSpiffeID
	BaseSpiffeIDTTL int32

	// Directory for plugin configs
	PluginDir string

	Logger log.Logger

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
	RegistrationService services.Registration
	AttestationService  services.Attestation
	IdentityService     services.Identity
	CaService           services.CA
	DataStoreImpl       datastore.DataStore
	NodeAttestorImpl    nodeattestor.NodeAttestor
	NodeResolverImpl    noderesolver.NodeResolver
	ServerCAImpl        ca.ControlPlaneCa
	UpstreamCAImpl      upstreamca.UpstreamCa
}

type Server struct {
	Catalog      *helpers.PluginCatalog
	Config       *Config
	grpcServer   *grpc.Server
	dependencies *dependencies
	privateKey   *ecdsa.PrivateKey
	svid         *x509.Certificate
}

// Run the server
// This method initializes the server, including its plugins,
// and then blocks on the main event loop.
func (a *Server) Run() error {
	err := a.initPlugins()
	defer a.stopPlugins()
	if err != nil {
		return err
	}

	a.initDependencies()

	err = a.rotateSigningCert()
	if err != nil {
		return err
	}

	a.svid, a.privateKey, err = a.rotateSVID()
	if err != nil {
		return err
	}

	err = a.initEndpoints()
	if err != nil {
		return err
	}

	// Main event loop
	a.Config.Logger.Log("msg", "SPIRE Server is now running")
	for {
		select {
		case err = <-a.Config.ErrorCh:
			return err
		case <-a.Config.ShutdownCh:
			a.grpcServer.GracefulStop()
			return <-a.Config.ErrorCh
		}
	}
}

func (a *Server) initPlugins() error {
	a.Config.Logger.Log("msg", "Starting plugins")

	// TODO: Feed log level through/fix logging...
	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "pluginLogger",
		Level: hclog.LevelFromString("DEBUG"),
	})

	a.Catalog = &helpers.PluginCatalog{
		PluginConfDirectory: a.Config.PluginDir,
		Logger:              pluginLogger,
	}

	a.Catalog.SetMaxPluginTypeMap(MaxPlugins)
	a.Catalog.SetPluginTypeMap(PluginTypeMap)

	err := a.Catalog.Run()
	if err != nil {
		return err
	}

	a.Config.Logger.Log("msg", "Starting plugins done")

	return nil
}

func (a *Server) stopPlugins() {
	a.Config.Logger.Log("msg", "Stopping plugins...")
	if a.Catalog != nil {
		a.Catalog.Stop()
	}
}

func (a *Server) initDependencies() {
	a.Config.Logger.Log("msg", "Initiating dependencies")
	a.dependencies = &dependencies{}

	//plugins
	dataStore := a.Catalog.GetPluginsByType("DataStore")[0]
	a.Config.Logger.Log("pluginType", reflect.TypeOf(dataStore))
	a.dependencies.DataStoreImpl = dataStore.(datastore.DataStore)

	nodeAttestor := a.Catalog.GetPluginsByType("NodeAttestor")[0]
	a.Config.Logger.Log("pluginType", reflect.TypeOf(nodeAttestor))
	a.dependencies.NodeAttestorImpl = nodeAttestor.(nodeattestor.NodeAttestor)

	nodeResolver := a.Catalog.GetPluginsByType("NodeResolver")[0]
	a.Config.Logger.Log("pluginType", reflect.TypeOf(nodeResolver))
	a.dependencies.NodeResolverImpl = nodeResolver.(noderesolver.NodeResolver)

	serverCA := a.Catalog.GetPluginsByType("ControlPlaneCA")[0]
	a.Config.Logger.Log("pluginType", reflect.TypeOf(serverCA))
	a.dependencies.ServerCAImpl = serverCA.(ca.ControlPlaneCa)

	upCAPlugin := a.Catalog.GetPluginsByType("UpstreamCA")[0].(upstreamca.UpstreamCa)
	a.Config.Logger.Log("pluginType", reflect.TypeOf(upCAPlugin))
	a.dependencies.UpstreamCAImpl = upCAPlugin.(upstreamca.UpstreamCa)

	//services
	a.dependencies.RegistrationService = services.NewRegistrationImpl(a.dependencies.DataStoreImpl)
	a.dependencies.AttestationService = services.NewAttestationImpl(a.dependencies.DataStoreImpl, a.dependencies.NodeAttestorImpl)
	a.dependencies.IdentityService = services.NewIdentityImpl(a.dependencies.DataStoreImpl, a.dependencies.NodeResolverImpl)
	a.dependencies.CaService = services.NewCAImpl(a.dependencies.ServerCAImpl)

	a.Config.Logger.Log("msg", "Initiating dependencies done")
}

func (a *Server) initEndpoints() error {
	a.Config.Logger.Log("msg", "Starting the Registration API")
	var registrationSvc registration.RegistrationService
	registrationSvc = registration.NewService(a.dependencies.RegistrationService)
	registrationSvc = registration.ServiceLoggingMiddleWare(a.Config.Logger)(registrationSvc)
	registrationEndpoints := getRegistrationEndpoints(registrationSvc)

	a.Config.Logger.Log("msg", "Starting the Node API")
	var nodeSvc node.NodeService
	nodeSvc = node.NewService(node.ServiceConfig{
		Attestation:     a.dependencies.AttestationService,
		CA:              a.dependencies.CaService,
		Identity:        a.dependencies.IdentityService,
		BaseSpiffeIDTTL: a.Config.BaseSpiffeIDTTL,
	})
	nodeSvc = node.ServiceLoggingMiddleWare(a.Config.Logger)(nodeSvc)
	nodeEnpoints := getNodeEndpoints(nodeSvc)

	// TODO: Fix me after server refactor
	crtRes, err := a.dependencies.ServerCAImpl.FetchCertificate(&ca.FetchCertificateRequest{})
	if err != nil {
		return err
	}
	certChain := [][]byte{a.svid.Raw, crtRes.StoredIntermediateCert}
	tlsCert := &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  a.privateKey,
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	a.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))

	registrationHandler := registration.MakeGRPCServer(registrationEndpoints)
	pbregistration.RegisterRegistrationServer(a.grpcServer, registrationHandler)

	nodeHandler := node.MakeGRPCServer(nodeEnpoints)
	pbnode.RegisterNodeServer(a.grpcServer, nodeHandler)

	a.Config.Logger.Log("msg", a.Config.BindAddress.String())
	listener, err := net.Listen(a.Config.BindAddress.Network(), a.Config.BindAddress.String())
	if err != nil {
		return fmt.Errorf("Error creating GRPC listener: %s", err)
	}

	//gRPC
	go func() {
		a.Config.ErrorCh <- a.grpcServer.Serve(listener)
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

		err := pbregistration.RegisterRegistrationHandlerFromEndpoint(ctx, mux, a.Config.BindAddress.String(), opts)
		if err != nil {
			a.Config.ErrorCh <- err
			return
		}
		a.Config.Logger.Log("msg", a.Config.BindHTTPAddress.String())
		a.Config.ErrorCh <- http.ListenAndServe(a.Config.BindHTTPAddress.String(), mux)
	}()

	return nil
}

func (a *Server) rotateSVID() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	a.Config.Logger.Log("msg", "Generating SVID certificate")

	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   a.Config.TrustDomain.Host,
		Path:   path.Join("spiffe", "cp"),
	}

	a.Config.Logger.Log("msg", "Generating SVID certificate", "SPIFFE_ID", spiffeID.String())

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

	signReq := &ca.SignCsrRequest{Csr: csr}
	res, err := a.dependencies.ServerCAImpl.SignCsr(signReq)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(res.SignedCertificate)
	if err != nil {
		return nil, nil, err
	}

	a.Config.Logger.Log("msg", "Generated SVID certificate", "SPIFFE_ID", spiffeID.String())

	return cert, key, nil
}

func (a *Server) rotateSigningCert() error {
	a.Config.Logger.Log("msg", "Initiating rotation of signing certificate")

	csrRes, err := a.dependencies.ServerCAImpl.GenerateCsr(&ca.GenerateCsrRequest{})
	if err != nil {
		return err
	}

	signRes, err := a.dependencies.UpstreamCAImpl.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return err
	}

	req := &ca.LoadCertificateRequest{SignedIntermediateCert: signRes.Cert}
	_, err = a.dependencies.ServerCAImpl.LoadCertificate(req)

	return err
}

func getRegistrationEndpoints(registrationSvc registration.RegistrationService) registration.Endpoints {
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

func getNodeEndpoints(nodeSvc node.NodeService) node.Endpoints {
	return node.Endpoints{
		FetchBaseSVIDEndpoint:        node.MakeFetchBaseSVIDEndpoint(nodeSvc),
		FetchCPBundleEndpoint:        node.MakeFetchCPBundleEndpoint(nodeSvc),
		FetchFederatedBundleEndpoint: node.MakeFetchFederatedBundleEndpoint(nodeSvc),
		FetchSVIDEndpoint:            node.MakeFetchSVIDEndpoint(nodeSvc),
	}
}
