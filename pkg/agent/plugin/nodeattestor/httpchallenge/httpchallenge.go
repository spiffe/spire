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
	data, err := p.getConfig()
	if err != nil {
		return err
	}

	ctx := stream.Context()

	port := data.port

	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", p.hooks.bindHost, port))
	if err != nil {
		return status.Errorf(codes.Internal, "could not listen on port %d: %v", port, err)
	}
	defer l.Close()

	advertisedPort := data.advertisedPort
	if advertisedPort == 0 {
		advertisedPort = l.Addr().(*net.TCPAddr).Port
	}

	attestationPayload, err := json.Marshal(httpchallenge.AttestationData{
		HostName:  data.hostName,
		AgentName: data.agentName,
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

	err = p.serveNonce(ctx, l, data.agentName, challenge.Nonce)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to start webserver: %v", err)
	}
	return nil
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// Make sure the configuration produces valid data
	configData, err := p.loadConfigData(config)
	if err != nil {
		return nil, err
	}

	p.setConfig(configData)

	return &configv1.ConfigureResponse{}, nil
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

func (p *Plugin) setConfig(c *configData) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func (p *Plugin) loadConfigData(config *Config) (*configData, error) {
	// Determine the host name to pass to the server. Values are preferred in
	// this order:
	// 1. HCL HostName configuration value
	// 2. OS hostname value
	hostName := config.HostName
	if hostName == "" {
		var err error
		hostName, err = os.Hostname()
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unable to fetch hostname: %v", err)
		}
	}

	var agentName = "default"
	if config.AgentName != "" {
		agentName = config.AgentName
	}

	if config.AdvertisedPort == 0 {
		config.AdvertisedPort = config.Port
	}

	return &configData{
		port:           config.Port,
		advertisedPort: config.AdvertisedPort,
		hostName:       hostName,
		agentName:      agentName,
	}, nil
}
