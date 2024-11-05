package x509pop

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "x509pop"
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
	privateKey         crypto.PrivateKey
	attestationPayload []byte
}

type Config struct {
	PrivateKeyPath    string `hcl:"private_key_path"`
	CertificatePath   string `hcl:"certificate_path"`
	IntermediatesPath string `hcl:"intermediates_path"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.PrivateKeyPath == "" {
		status.ReportError("private_key_path is required")
	}

	if newConfig.CertificatePath == "" {
		status.ReportError("certificate_path is required")
	}

	return newConfig
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m sync.Mutex
	c *Config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	data, err := p.loadConfigData()
	if err != nil {
		return err
	}

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: data.attestationPayload,
		},
	}); err != nil {
		return err
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		return err
	}

	challenge := new(x509pop.Challenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return status.Errorf(codes.Internal, "unable to unmarshal challenge: %v", err)
	}

	// calculate and send the challenge response
	response, err := x509pop.CalculateResponse(data.privateKey, challenge)
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
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	// make sure the configuration produces valid data
	if _, err := loadConfigData(newConfig); err != nil {
		return nil, err
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.c = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() *Config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) loadConfigData() (*configData, error) {
	config := p.getConfig()
	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return loadConfigData(config)
}

// TODO: this needs more attention.  Parts of it might belong in buildConfig
func loadConfigData(config *Config) (*configData, error) {
	certificate, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to load keypair: %v", err)
	}

	certificates := certificate.Certificate

	// Append intermediate certificates if IntermediatesPath is set.
	if strings.TrimSpace(config.IntermediatesPath) != "" {
		intermediates, err := util.LoadCertificates(config.IntermediatesPath)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unable to load intermediate certificates: %v", err)
		}

		for _, cert := range intermediates {
			certificates = append(certificates, cert.Raw)
		}
	}

	attestationPayload, err := json.Marshal(x509pop.AttestationData{
		Certificates: certificates,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	return &configData{
		privateKey:         certificate.PrivateKey,
		attestationPayload: attestationPayload,
	}, nil
}
