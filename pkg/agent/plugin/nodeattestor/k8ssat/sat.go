package k8ssat

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "k8s_sat"

	defaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // false positive
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type AttestorConfig struct {
	Cluster   string `hcl:"cluster"`
	TokenPath string `hcl:"token_path"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *attestorConfig {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if hclConfig.Cluster == "" {
		status.ReportError("configuration missing cluster")
	}

	newConfig := &attestorConfig{
		cluster:   hclConfig.Cluster,
		tokenPath: hclConfig.TokenPath,
	}

	if newConfig.tokenPath == "" {
		newConfig.tokenPath = getDefaultTokenPath()
	}

	return newConfig
}

type attestorConfig struct {
	cluster   string
	tokenPath string
}

type AttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	log hclog.Logger

	mu     sync.RWMutex
	config *attestorConfig
}

func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

// SetLogger sets a logger in the plugin.
func (p *AttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *AttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	token, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to load token from %s: %v", config.tokenPath, err)
	}

	payload, err := json.Marshal(k8s.SATAttestationData{
		Cluster: config.cluster,
		Token:   token,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal SAT token data: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	})
}

func (p *AttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	p.log.Warn(fmt.Sprintf("The %q node attestor plugin has been deprecated in favor of the \"k8s_psat\" plugin and will be removed in a future release", pluginName))

	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (resp *configv1.ValidateResponse, err error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func loadTokenFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%q is empty", path)
	}
	return string(data), nil
}
