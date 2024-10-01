package awsiid

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	docPath        = "instance-identity/document"
	sigPath        = "instance-identity/signature"
	sigRSA2048Path = "instance-identity/rsa2048"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(caws.PluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p))
}

// IIDAttestorConfig configures a IIDAttestorPlugin.
type IIDAttestorConfig struct {
	EC2MetadataEndpoint string `hcl:"ec2_metadata_endpoint"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *IIDAttestorConfig {
	newConfig := &IIDAttestorConfig{}
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	return newConfig
}

// IIDAttestorPlugin implements aws nodeattestation in the agent.
type IIDAttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log    hclog.Logger
	config *IIDAttestorConfig
	mtx    sync.RWMutex
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	return &IIDAttestorPlugin{}
}

func (p *IIDAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// AidAttestation implements the NodeAttestor interface method of the same name
func (p *IIDAttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	ctx := stream.Context()
	attestationData, err := fetchMetadata(ctx, c.EC2MetadataEndpoint)
	if err != nil {
		return err
	}

	respData, err := json.Marshal(attestationData)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: respData,
		},
	})
}

func fetchMetadata(ctx context.Context, endpoint string) (*caws.IIDAttestationData, error) {
	var opts []func(*config.LoadOptions) error
	if endpoint != "" {
		opts = append(opts, config.WithEC2IMDSEndpoint(endpoint))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	client := imds.NewFromConfig(awsCfg)

	doc, err := getMetadataDoc(ctx, client)
	if err != nil {
		return nil, err
	}

	sig, err := getMetadataSig(ctx, client, sigPath)
	if err != nil {
		return nil, err
	}

	sigRSA2048, err := getMetadataSig(ctx, client, sigRSA2048Path)
	if err != nil {
		return nil, err
	}

	// Agent sends both RSA-1024 and RSA-2048 signatures. This is for maintaining backwards compatibility, to support
	// new SPIRE agents to attest to older SPIRE servers.
	return &caws.IIDAttestationData{
		Document:         doc,
		Signature:        sig,
		SignatureRSA2048: sigRSA2048,
	}, nil
}

func getMetadataDoc(ctx context.Context, client *imds.Client) (string, error) {
	res, err := client.GetDynamicData(ctx, &imds.GetDynamicDataInput{
		Path: docPath,
	})
	if err != nil {
		return "", err
	}

	return readStringAndClose(res.Content)
}

func getMetadataSig(ctx context.Context, client *imds.Client, signaturePath string) (string, error) {
	res, err := client.GetDynamicData(ctx, &imds.GetDynamicDataInput{
		Path: signaturePath,
	})
	if err != nil {
		return "", err
	}

	return readStringAndClose(res.Content)
}

func readStringAndClose(r io.ReadCloser) (string, error) {
	defer r.Close()
	var sb strings.Builder
	if _, err := io.Copy(&sb, r); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// Configure implements the Config interface method of the same name
func (p *IIDAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *IIDAttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
