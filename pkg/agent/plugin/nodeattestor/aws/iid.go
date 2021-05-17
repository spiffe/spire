package aws

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	docPath = "instance-identity/document"
	sigPath = "instance-identity/signature"
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

	attestationData, err := fetchMetadata(c.EC2MetadataEndpoint)
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

func fetchMetadata(endpoint string) (*caws.IIDAttestationData, error) {
	awsCfg := aws.NewConfig()
	if endpoint != "" {
		awsCfg.WithEndpoint(endpoint)
	}
	newSession, err := session.NewSession(awsCfg)
	if err != nil {
		return nil, err
	}

	client := ec2metadata.New(newSession)

	doc, err := client.GetDynamicData(docPath)
	if err != nil {
		return nil, err
	}

	sig, err := client.GetDynamicData(sigPath)
	if err != nil {
		return nil, err
	}

	return &caws.IIDAttestationData{
		Document:  doc,
		Signature: sig,
	}, nil
}

// Configure implements the Config interface method of the same name
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
