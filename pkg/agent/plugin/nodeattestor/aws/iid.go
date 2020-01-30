package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	awsSdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	docPath = "instance-identity/document"
	sigPath = "instance-identity/signature"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(aws.PluginName, nodeattestor.PluginServer(p))
}

// IIDAttestorConfig configures a IIDAttestorPlugin.
type IIDAttestorConfig struct {
	EC2MetadataEndpoint  string `hcl:"ec2_metadata_endpoint"`
	IdentityDocumentURL  string `hcl:"identity_document_url"`
	IdentitySignatureURL string `hcl:"identity_signature_url"`
}

// IIDAttestorPlugin implements aws nodeattestation in the agent.
type IIDAttestorPlugin struct {
	session *session.Session
	mtx     sync.RWMutex
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	return &IIDAttestorPlugin{}
}

// FetchAttestationData fetches attestation data from the aws metadata server and sends an attestation response
// on given stream.
func (p *IIDAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	if p.session == nil {
		return errors.New("not configured")
	}

	client := ec2metadata.New(p.session)

	doc, err := client.GetDynamicData(docPath)
	if err != nil {
		return aws.AttestationStepError("retrieving the IID from AWS", err)
	}

	sig, err := client.GetDynamicData(sigPath)
	if err != nil {
		return aws.AttestationStepError("retrieving the IID signature from AWS", err)
	}

	attestationData := aws.IIDAttestationData{
		Document:  doc,
		Signature: sig,
	}

	respData, err := json.Marshal(attestationData)
	if err != nil {
		return aws.AttestationStepError("marshaling the attested data", err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: aws.PluginName,
			Data: respData,
		},
	})
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// If the endpoint isn't explicitly configured but the legacy URLs are, extract the endpoint from it
	// This code is transitional, here until these deprecated configs are removed
	if config.EC2MetadataEndpoint == "" && (config.IdentityDocumentURL != "" || config.IdentitySignatureURL != "") {
		endpoint, err := endpointFromLegacyConfig(config.IdentityDocumentURL, config.IdentitySignatureURL)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		config.EC2MetadataEndpoint = endpoint
	}

	awsCfg := awsSdk.NewConfig()

	if config.EC2MetadataEndpoint != "" {
		awsCfg.WithEndpoint(config.EC2MetadataEndpoint)
	}

	newSession, err := session.NewSession(awsCfg)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.session = newSession

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*IIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// endpointFromLegacyConfig extracts the endpoint from legacy configuration values
// This code is transitional, here until these deprecated configs are removed
func endpointFromLegacyConfig(docURL, sigURL string) (string, error) {
	docSuffix := "/dynamic/" + docPath
	if !strings.HasSuffix(docURL, docSuffix) {
		return "", fmt.Errorf("IID URL '%s' doesn't end in expected suffix %s", docURL, docSuffix)
	}
	docEndpoint := strings.TrimSuffix(docURL, docSuffix)

	sigSuffix := "/dynamic/" + sigPath
	if !strings.HasSuffix(sigURL, sigSuffix) {
		return "", fmt.Errorf("IID signature URL '%s' doesn't end in expected suffix %s", sigURL, sigSuffix)
	}
	sigEndpoint := strings.TrimSuffix(sigURL, sigSuffix)

	if docEndpoint != sigEndpoint {
		return "", fmt.Errorf("IID URL and Signature URL had different endpoints: %s != %s", docEndpoint, sigEndpoint)
	}

	return docEndpoint, nil
}
