package k8spsat

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName       = "k8s_psat"
	defaultTokenPath = "/var/run/secrets/tokens/spire-agent" //nolint: gosec // false positive
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// New creates a new PSAT attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

// AttestorPlugin is a PSAT (projected SAT) attestor plugin
type AttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *attestorConfig
}

// AttestorConfig holds configuration for AttestorPlugin
type AttestorConfig struct {
	// Cluster name where the agent lives
	Cluster string `hcl:"cluster"`
	// File path of PSAT
	TokenPath string `hcl:"token_path"`
}

type attestorConfig struct {
	cluster   string
	tokenPath string
}

// AidAttestation loads the PSAT token from the configured path
func (p *AttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	token, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to load token from %s: %v", config.tokenPath, err)
	}

	payload, err := json.Marshal(k8s.PSATAttestationData{
		Cluster: config.cluster,
		Token:   token,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal PSAT token data: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	})
}

// Configure decodes JSON config from request and populates AttestorPlugin with it
func (p *AttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if hclConfig.Cluster == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration missing cluster")
	}

	config := &attestorConfig{
		cluster:   hclConfig.Cluster,
		tokenPath: hclConfig.TokenPath,
	}
	if config.tokenPath == "" {
		config.tokenPath = getDefaultTokenPath()
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func loadTokenFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errs.Wrap(err)
	}
	if len(data) == 0 {
		return "", errs.New("%q is empty", path)
	}
	return string(data), nil
}
