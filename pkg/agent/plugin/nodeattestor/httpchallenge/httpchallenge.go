package httpchallenge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "http_challenge"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configData struct {
	port           int
	advertisedPort int
	hostName       string
	agentName      string
}

type Config struct {
	HostName       string `hcl:"hostname"`
	AgentName      string `hcl:"agentname"`
	Port           int    `hcl:"port"`
	AdvertisedPort int    `hcl:"advertised_port"`
}

func (p *Plugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configData {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
	}

	hostName := hclConfig.HostName
	// hostname unset, autodetect hostname
	if hostName == "" {
		var err error
		hostName, err = os.Hostname()
		if err != nil {
			status.ReportErrorf("unable to fetch hostname: %v", err)
		}
	}

	agentName := hclConfig.AgentName
	if agentName == "" {
		agentName = "default"
	}

	advertisedPort := hclConfig.AdvertisedPort
	// if unset, advertised port is same as hcl:"port"
	if advertisedPort == 0 {
		advertisedPort = hclConfig.Port
	}

	newConfig := &configData{
		port:           hclConfig.Port,
		advertisedPort: advertisedPort,
		hostName:       hostName,
		agentName:      agentName,
	}

	return newConfig
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m sync.RWMutex
	c *configData

	log hclog.Logger

	hooks struct {
		// Controls which interface to bind to ("" in production, "localhost"
		// in tests) and acts as the default HostName value when not provided
		// via configuration.
		bindHost string
	}
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	ctx := stream.Context()

	port := config.port

	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", p.hooks.bindHost, port))
	if err != nil {
		return status.Errorf(codes.Internal, "could not listen on port %d: %v", port, err)
	}
	defer l.Close()

	advertisedPort := config.advertisedPort
	if advertisedPort == 0 {
		advertisedPort = l.Addr().(*net.TCPAddr).Port
	}

	attestationPayload, err := json.Marshal(httpchallenge.AttestationData{
		HostName:  config.hostName,
		AgentName: config.agentName,
		Port:      advertisedPort,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationPayload,
		},
	}); err != nil {
		return err
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		return err
	}

	challenge := new(httpchallenge.Challenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return status.Errorf(codes.Internal, "unable to unmarshal challenge: %v", err)
	}

	// due to https://github.com/spiffe/spire/blob/8f9fa036e182a2fab968e03cd25a7fdb2d8c88bb/pkg/agent/plugin/nodeattestor/v1.go#L63, we must respond with a non blank challenge response
	responseBytes := []byte{'\n'}
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: responseBytes,
		},
	}); err != nil {
		return err
	}

	err = p.serveNonce(ctx, l, config.agentName, challenge.Nonce)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to start webserver: %v", err)
	}
	return nil
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.c = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) serveNonce(ctx context.Context, l net.Listener, agentName string, nonce string) (err error) {
	h := http.NewServeMux()
	s := &http.Server{
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	path := fmt.Sprintf("/.well-known/spiffe/nodeattestor/http_challenge/%s/challenge", agentName)
	p.log.Debug("Setting up nonce handler", "path", path)
	h.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, nonce)
	})

	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()

	err = s.Serve(l)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// SetLogger sets this plugin's logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) getConfig() (*configData, error) {
	p.m.RLock()
	defer p.m.RUnlock()
	if p.c == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.c, nil
}
