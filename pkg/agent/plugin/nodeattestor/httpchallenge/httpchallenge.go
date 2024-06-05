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

	m sync.Mutex
	c *Config
	l *net.Listener
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) serveNonce(l net.Listener, agentName string, nonce string) (err error) {
	h := http.NewServeMux()
	s := &http.Server{
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	path := fmt.Sprintf("/.well-known/spiffe/nodeattestor/http_challenge/%s/%s", agentName, nonce)
	h.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", nonce)
		go func() {
			_ = s.Shutdown(context.Background())
		}()
	})

	go func() {
		err = s.Serve(l)
		l.Close()
		if err == http.ErrServerClosed {
			return
		}
		if err != nil {
			fmt.Printf("Unexpected error while serving. %e", err)
		}
	}()
	return err
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	data, err := p.loadConfigData()
	if err != nil {
		return err
	}

	port := data.port

	if p.l != nil {
		(*p.l).Close()
	}
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	p.l = &l
	if err != nil {
		return status.Errorf(codes.Internal, "could not listen on port %d: %v", port, err)
	}

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
		l.Close()
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationPayload,
		},
	}); err != nil {
		l.Close()
		return err
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		l.Close()
		return err
	}

	challenge := new(httpchallenge.Challenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		l.Close()
		return status.Errorf(codes.Internal, "unable to unmarshal challenge: %v", err)
	}

	// FIXME open http port and post nonce here. When nonce fetched, auto remove webserver.
	err = p.serveNonce(l, data.agentName, string(challenge.Nonce))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to start webserver: %v", err)
	}

	response, err := httpchallenge.CalculateResponse(challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge response: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: responseBytes,
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// Make sure the configuration produces valid data
	if _, err := loadConfigData(config); err != nil {
		return nil, err
	}

	p.setConfig(config)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) getConfig() *Config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) setConfig(c *Config) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func (p *Plugin) loadConfigData() (*configData, error) {
	config := p.getConfig()
	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return loadConfigData(config)
}

func loadConfigData(config *Config) (*configData, error) {
	if config.HostName == "" {
		var err error
		config.HostName, err = os.Hostname()
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
		hostName:       config.HostName,
		agentName:      agentName,
	}, nil
}
