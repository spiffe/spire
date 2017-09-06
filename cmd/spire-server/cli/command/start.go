package command

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"reflect"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spiffe/go-spiffe/uri"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/spiffe/sri/pkg/common/plugin"

	"github.com/spiffe/sri/pkg/server/ca"
	"github.com/spiffe/sri/pkg/server/datastore"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
	"github.com/spiffe/sri/pkg/server/noderesolver"
	"github.com/spiffe/sri/pkg/server/upstreamca"

	"github.com/spiffe/sri/cmd/spire-server/endpoints/node"
	"github.com/spiffe/sri/cmd/spire-server/endpoints/registration"
	"github.com/spiffe/sri/cmd/spire-server/endpoints/server"
	nodePB "github.com/spiffe/sri/pkg/api/node"
	registrationPB "github.com/spiffe/sri/pkg/api/registration"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/services"
)

const (
	DefaultServerConfigPath = ".conf/default_server_config.hcl"
	DefaultPluginConfigDir  = "../../plugin/server/.conf"
)

var (
	PluginTypeMap = map[string]plugin.Plugin{
		"ControlPlaneCA": &ca.ControlPlaneCaPlugin{},
		"DataStore":      &datastore.DataStorePlugin{},
		"NodeResolver":   &noderesolver.NodeResolverPlugin{},
		"UpstreamCA":     &upstreamca.UpstreamCaPlugin{},
		"NodeAttestor":   &nodeattestor.NodeAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"ControlPlaneCA": 1,
		"DataStore":      1,
		"NodeResolver":   1,
		"UpstreamCA":     1,
		"NodeAttestor":   1,
	}
	logger = log.NewLogfmtLogger(os.Stdout)
)

type StartCommand struct {
}

//Help returns how to use the server command
func (*StartCommand) Help() string {
	return "Usage: spire-server server"
}

//Run the server command
func (*StartCommand) Run(args []string) int {
	cpConfigPath, isPathSet := os.LookupEnv("SPIRE_SERVER_CONFIG")
	if !isPathSet {
		cpConfigPath = DefaultServerConfigPath
	}

	config := helpers.ControlPlaneConfig{}
	err := config.ParseConfig(cpConfigPath)
	if err != nil {
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger.Log("error", err, "configFile", cpConfigPath)
		return -1

	}
	lFile, lLevel := config.LogConfig()
	logger, err = helpers.NewLogger(lLevel, lFile)
	if err != nil {
		logger.Log("error", err)
		return -1
	}
	pluginCatalog, err := loadPlugins()
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	err = rotateSigningCert(&config, pluginCatalog)
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	err = initEndpoints(&config, pluginCatalog)
	if err != nil {
		level.Error(logger).Log("error", err)
		return -1
	}

	return 0
}

//Synopsis of the server command
func (*StartCommand) Synopsis() string {
	return "Intializes spire-server Runtime."
}

func loadPlugins() (*helpers.PluginCatalog, error) {
	pluginConfigDir, isPathSet := os.LookupEnv("SPIRE_PLUGIN_CONFIG_DIR")
	if !isPathSet {
		pluginConfigDir = DefaultPluginConfigDir
	}
	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "pluginLogger",
		Level: hclog.LevelFromString("DEBUG"),
	})

	pluginCatalog := &helpers.PluginCatalog{
		PluginConfDirectory: pluginConfigDir,
		Logger:              pluginLogger,
	}
	pluginCatalog.SetMaxPluginTypeMap(MaxPlugins)
	pluginCatalog.SetPluginTypeMap(PluginTypeMap)
	err := pluginCatalog.Run()
	level.Info(logger).Log("plugincount", len(pluginCatalog.PluginClientsByName))
	if err != nil {
		level.Error(logger).Log("error", err)
		return nil, err
	}

	return pluginCatalog, nil
}

func initEndpoints(config *helpers.ControlPlaneConfig, pluginCatalog *helpers.PluginCatalog) error {
	logger.Log("msg", "Initializing endpoints")
	//plugins

	dataStore := pluginCatalog.GetPluginsByType("DataStore")[0]
	level.Info(logger).Log("pluginType", reflect.TypeOf(dataStore))
	dataStoreImpl := dataStore.(datastore.DataStore)

	//nodeAttestor := pluginCatalog.GetPluginsByType("NodeAttestor")[0]
	nodeAttestor := pluginCatalog.GetPluginByName("join_token")
	level.Info(logger).Log("pluginType", reflect.TypeOf(nodeAttestor))
	nodeAttestorImpl := nodeAttestor.(nodeattestor.NodeAttestor)

	nodeResolver := pluginCatalog.GetPluginsByType("NodeResolver")[0]
	level.Info(logger).Log("pluginType", reflect.TypeOf(nodeResolver))
	nodeResolverImpl := nodeResolver.(noderesolver.NodeResolver)

	serverCA := pluginCatalog.GetPluginsByType("ControlPlaneCA")[0]
	level.Info(logger).Log("pluginType", reflect.TypeOf(serverCA))
	serverCAImpl := serverCA.(ca.ControlPlaneCa)

	//services
	registrationService := services.NewRegistrationImpl(dataStoreImpl)
	attestationService := services.NewAttestationImpl(dataStoreImpl, nodeAttestorImpl)
	identityService := services.NewIdentityImpl(dataStoreImpl, nodeResolverImpl)
	caService := services.NewCAImpl(serverCAImpl)

	errChan := makeErrorChannel()
	var serverSvc server.ServerService
	serverSvc = server.NewService(pluginCatalog, errChan)
	serverSvc = server.ServiceLoggingMiddleWare(logger)(serverSvc)

	var registrationSvc registration.RegistrationService
	registrationSvc = registration.NewService(registrationService)
	registrationSvc = registration.ServiceLoggingMiddleWare(logger)(registrationSvc)

	var nodeSvc node.NodeService
	nodeSvc = node.NewService(node.ServiceConfig{Attestation: attestationService, CA: caService, Identity: identityService})
	nodeSvc = node.SelectorServiceLoggingMiddleWare(logger)(nodeSvc)

	var (
		httpAddr = flag.String("http", ":8080", "http listen address")
		gRPCAddr = flag.String("grpc", ":8081", "gRPC listen address")
	)
	flag.Parse()

	serverEndpoints := server.Endpoints{
		PluginInfoEndpoint: server.MakePluginInfoEndpoint(serverSvc),
		StopEndpoint:       server.MakeStopEndpoint(serverSvc),
	}

	registrationEndpoints := registration.Endpoints{
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

	nodeEnpoints := node.Endpoints{
		FetchBaseSVIDEndpoint:        node.MakeFetchBaseSVIDEndpoint(nodeSvc),
		FetchCPBundleEndpoint:        node.MakeFetchCPBundleEndpoint(nodeSvc),
		FetchFederatedBundleEndpoint: node.MakeFetchFederatedBundleEndpoint(nodeSvc),
		FetchSVIDEndpoint:            node.MakeFetchSVIDEndpoint(nodeSvc),
	}

	cert, key, err := generateSVID(config, pluginCatalog)
	if err != nil {
		return err
	}

	go func() {
		listener, err := net.Listen("tcp", *gRPCAddr)
		if err != nil {
			errChan <- err
			return
		}
		logger.Log("grpc:", *gRPCAddr)

		// TODO: Fix me after server refactor
		// Get CA Plugin so we can fetch our signing cert
		caPlugin := pluginCatalog.GetPluginsByType("ControlPlaneCA")[0].(ca.ControlPlaneCa)
		crtRes, err := caPlugin.FetchCertificate(&ca.FetchCertificateRequest{})
		if err != nil {
			errChan <- err
			return
		}
		certChain := [][]byte{cert.Raw, crtRes.StoredIntermediateCert}
		tlsCert := &tls.Certificate{
			Certificate: certChain,
			PrivateKey:  key,
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
		}

		nodeHandler := node.MakeGRPCServer(nodeEnpoints)
		gRPCServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
		nodePB.RegisterNodeServer(gRPCServer, nodeHandler)

		serverHandler := server.MakeGRPCServer(serverEndpoints)
		sriplugin.RegisterServerServer(gRPCServer, serverHandler)

		registrationHandler := registration.MakeGRPCServer(registrationEndpoints)
		registrationPB.RegisterRegistrationServer(gRPCServer, registrationHandler)

		errChan <- gRPCServer.Serve(listener)
	}()

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
		logger.Log("http:", *httpAddr)
		err := registrationPB.RegisterRegistrationHandlerFromEndpoint(ctx, mux, *gRPCAddr, opts)
		if err != nil {
			errChan <- err
			return
		}
		errChan <- http.ListenAndServe(*httpAddr, mux)
	}()

	error := <-errChan
	logger.Log("channel", errChan, "error", error)
	return error
}

func generateSVID(config *helpers.ControlPlaneConfig, catalog *helpers.PluginCatalog) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   config.TrustDomain,
		Path:   path.Join("spiffe", "cp"),
	}

	logger.Log("msg", "Generating SVID certificate", "SPIFFE_ID", spiffeID.String())

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
	p := catalog.GetPluginsByType("ControlPlaneCA")[0].(ca.ControlPlaneCa)
	res, err := p.SignCsr(signReq)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(res.SignedCertificate)
	if err != nil {
		return nil, nil, err
	}

	logger.Log("msg", "Generated SVID certificate", "SPIFFE_ID", spiffeID.String())

	return cert, key, nil
}

func rotateSigningCert(config *helpers.ControlPlaneConfig, catalog *helpers.PluginCatalog) error {
	logger.Log("msg", "Initiating rotation of signing certificate")

	caPlugin := catalog.GetPluginsByType("ControlPlaneCA")[0].(ca.ControlPlaneCa)
	upCAPlugin := catalog.GetPluginsByType("UpstreamCA")[0].(upstreamca.UpstreamCa)

	csrRes, err := caPlugin.GenerateCsr(&ca.GenerateCsrRequest{})
	if err != nil {
		return err
	}

	signRes, err := upCAPlugin.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return err
	}

	_, err = caPlugin.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: signRes.Cert})

	return err
}

func makeErrorChannel() (errChannel chan error) {
	errChannel = make(chan error)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errChannel <- fmt.Errorf("%s", <-c)
	}()
	return
}
