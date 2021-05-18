package tpm_devid

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpm_devid/tpmutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpm_devid"
	"github.com/spiffe/spire/pkg/common/util"
	spc "github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/nodeattestor/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// defaultDevicePath is the value used when tpm_device_path is not set
	defaultDevicePath = "/dev/tpmrm0"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(common_devid.PluginName, nodeattestorv0.PluginServer(p))
}

type Config struct {
	DevIDPrivPath string `hcl:"devid_priv_path"`
	DevIDPubPath  string `hcl:"devid_pub_path"`
	DevIDCertPath string `hcl:"devid_cert_path"`

	DevicePath string `hcl:"tpm_device_path"`
}

type config struct {
	trustDomain string
	devicePath  string

	devIDCert *x509.Certificate
	devIDPub  []byte
	devIDPriv []byte
}

type Plugin struct {
	nodeattestorv0.UnsafeNodeAttestorServer
	log hclog.Logger

	m sync.Mutex
	c *config
}

func New() *Plugin {
	return &Plugin{
		c: newDefaultConfig(),
	}
}

func (p *Plugin) FetchAttestationData(stream nodeattestorv0.NodeAttestor_FetchAttestationDataServer) error {
	conf := p.getConfig()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	// Open TPM connection and load DevID keys
	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevicePath: conf.devicePath,
		DevIDPriv:  conf.devIDPriv,
		DevIDPub:   conf.devIDPub,
		Log:        p.log,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable start a new TPM session: %v", err)
	}
	defer tpm.Close()

	// Get endorsement certificate from TPM NV index
	ekCert, err := tpm.GetEKCert()
	if err != nil {
		return fmt.Errorf("unable to get endorsement certificate: %w", err)
	}

	// Get regenerated endorsement public key
	ekPub, err := tpm.GetEKPublic()
	if err != nil {
		return fmt.Errorf("unable to get endorsement public key: %w", err)
	}

	// Certify DevID in in the same TPM than AK
	id, sig, err := tpm.CertifyDevIDKey()
	if err != nil {
		return fmt.Errorf("unable to certify DevID key: %w", err)
	}

	// Marshal attestation data
	marshaledAttData, err := json.Marshal(common_devid.AttestationRequest{
		DevIDCert: conf.devIDCert.Raw,
		DevIDPub:  conf.devIDPub,

		EKCert: ekCert,
		EKPub:  ekPub,

		AKPub: tpm.GetAKPublic(),

		CertifiedDevID:         id,
		CertificationSignature: sig,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	// Send attestation request
	err = stream.Send(&nodeattestorv0.FetchAttestationDataResponse{
		AttestationData: &spc.AttestationData{
			Type: common_devid.PluginName,
			Data: marshaledAttData,
		},
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send attestation data: %s", st.Message())
	}

	// Receive challenges
	marshalledChallenges, err := stream.Recv()
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to receive challenges: %s", st.Message())
	}

	challenges := &common_devid.ChallengeRequest{}
	if err = json.Unmarshal(marshalledChallenges.Challenge, challenges); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenges: %v", err)
	}

	// Solve DevID challenge (verify the possession of the DevID private key)
	devIDChallengeResp, err := tpm.SolveDevIDChallenge(challenges.DevID)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to solve DevID challenge: %v", err)
	}

	// Solve Credential Activation challenge
	var credActChallengeResp []byte
	if challenges.CredActivation == nil {
		return status.Errorf(codes.Internal, "received empty credential activation challenge from server")
	}

	credActChallengeResp, err = tpm.SolveCredActivationChallenge(
		challenges.CredActivation.Credential,
		challenges.CredActivation.Secret)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to solve credential activation challenge: %v", err)
	}

	// Marshal challenges responses
	marshalledChallengeResp, err := json.Marshal(common_devid.ChallengeResponse{
		DevID:          devIDChallengeResp,
		CredActivation: credActChallengeResp,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge response: %v", err)
	}

	// Send challenge response back to the server
	err = stream.Send(&nodeattestorv0.FetchAttestationDataResponse{
		Response: marshalledChallengeResp,
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send challenge response: %s", st.Message())
	}

	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	err := common_devid.ValidateGlobalConfig(req.GlobalConfig)
	if err != nil {
		return nil, err
	}

	extConf, err := decodePluginConfig(req.Configuration)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	err = validatePluginConfig(extConf)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "missing configurable: %v", err)
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.c.trustDomain = req.GlobalConfig.TrustDomain

	if extConf.DevicePath != "" {
		p.c.devicePath = extConf.DevicePath
	}

	err = p.loadDevIDFiles(extConf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to load DevID files: %v", err)
	}

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) getConfig() *config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) loadDevIDFiles(c *Config) error {
	certs, err := util.LoadCertificates(c.DevIDCertPath)
	if err != nil {
		return fmt.Errorf("cannot load certificate: %w", err)
	}

	if len(certs) != 1 {
		return errors.New("only one certificate is expected")
	}
	p.c.devIDCert = certs[0]

	p.c.devIDPriv, err = ioutil.ReadFile(c.DevIDPrivPath)
	if err != nil {
		return fmt.Errorf("cannot load private key: %w", err)
	}

	p.c.devIDPub, err = ioutil.ReadFile(c.DevIDPubPath)
	if err != nil {
		return fmt.Errorf("cannot load public key: %w", err)
	}

	return nil
}

func newDefaultConfig() *config {
	return &config{
		devicePath: defaultDevicePath,
	}
}

func decodePluginConfig(hclConf string) (*Config, error) {
	extConfig := new(Config)
	if err := hcl.Decode(extConfig, hclConf); err != nil {
		return nil, err
	}

	return extConfig, nil
}

func validatePluginConfig(c *Config) error {
	// DevID certificate, public and private key are always required
	switch {
	case c.DevIDCertPath == "":
		return fmt.Errorf("devid_cert_path is required")

	case c.DevIDPrivPath == "":
		return fmt.Errorf("devid_priv_path is required")

	case c.DevIDPubPath == "":
		return fmt.Errorf("devid_pub_path is required")
	}

	return nil
}
