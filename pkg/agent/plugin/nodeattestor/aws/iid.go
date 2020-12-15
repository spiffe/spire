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
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	docPath = "instance-identity/document"
	sigPath = "instance-identity/signature"
)

var (
	iidError = caws.IidErrorClass
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(caws.PluginName, nodeattestor.PluginServer(p))
}

// IIDAttestorConfig configures a IIDAttestorPlugin.
type IIDAttestorConfig struct {
	EC2MetadataEndpoint string `hcl:"ec2_metadata_endpoint"`
}

// IIDAttestorPlugin implements aws nodeattestation in the agent.
type IIDAttestorPlugin struct {
	nodeattestor.UnsafeNodeAttestorServer

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

// FetchAttestationData fetches attestation data from the aws metadata server and sends an attestation response
// on given stream.
func (p *IIDAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
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
		return caws.AttestationStepError("marshaling the attested data", err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: caws.PluginName,
			Data: respData,
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

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*IIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, iidError.New("not configured")
	}
	return p.config, nil
}
