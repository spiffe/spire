package devid

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/devid/tpm"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/devid"
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

	AKPrivPath string `hcl:"ak_priv_path"`
	AKPubPath  string `hcl:"ak_pub_path"`

	DevicePath string `hcl:"tpm_device_path"`
}

type config struct {
	trustDomain string
	devicePath  string

	devIDCert *x509.Certificate
	devIDPub  []byte
	devIDPriv []byte

	checkDevIDResidency bool
	akPub               []byte
	akPriv              []byte
}

type Plugin struct {
	nodeattestorv0.UnsafeNodeAttestorServer
	log hclog.Logger

	m sync.Mutex
	c *config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) FetchAttestationData(stream nodeattestorv0.NodeAttestor_FetchAttestationDataServer) error {
	conf := p.getConfig()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	// Open TPM connection and loads keys
	tpm, err := loadTPMContext(conf, p.log)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to load context: %v", err)
	}
	defer tpm.Close()

	// Marshal attestation data
	marshaledAttData, err := json.Marshal(common_devid.AttestationRequest{
		DevIDCert: conf.devIDCert.Raw,
		DevIDPub:  conf.devIDPub,

		EKCert: tpm.EKCert,
		EKPub:  tpm.EKPub,

		AKPub: conf.akPub,

		CertifiedDevID:         tpm.CertifiedDevID,
		CertificationSignature: tpm.CertificationSignature,
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

	// If DevID residency verification configured
	var credActChallengeResp []byte
	if conf.checkDevIDResidency && challenges.CredActivation != nil {
		// Solve Credential Activation challenge
		credActChallengeResp, err = tpm.SolveCredActivationChallenge(
			challenges.CredActivation.Credential,
			challenges.CredActivation.Secret)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to solve credential activation challenge: %v", err)
		}
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

	p.setPluginConfigDefaults(extConf)

	err = validatePluginConfig(extConf)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "missing configurable: %v", err)
	}

	// Create initial internal configuration
	intConf := &config{
		trustDomain: req.GlobalConfig.TrustDomain,
		devicePath:  extConf.DevicePath,

		// If Attestation Key is configured, it is assumed that the user wants to verify DevID residency
		checkDevIDResidency: akConfigured(extConf),
	}

	// Load DevID files
	err = loadDevIDFiles(extConf, intConf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to load DevID files: %v", err)
	}

	// Load Attestation Key files (if configured)
	if intConf.checkDevIDResidency {
		err = loadAKFiles(extConf, intConf)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to load attestation key files: %v", err)
		}
	}

	p.setConfig(intConf)

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

func (p *Plugin) setConfig(c *config) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func (p *Plugin) setPluginConfigDefaults(config *Config) {
	if config.DevicePath == "" {
		config.DevicePath = defaultDevicePath
		p.log.Info("tpm_device_path is not set, using default: %q", defaultDevicePath)
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

	// Attestation private and public keys are not required but if one is
	// provided the other one is also needed.
	switch {
	case c.AKPrivPath == "" && c.AKPubPath == "":
		return nil

	case c.AKPrivPath == "":
		return fmt.Errorf("ak_priv_path is required if ak_pub_path is provided")

	case c.AKPubPath == "":
		return fmt.Errorf("ak_pub_path is required if ak_priv_path is provided")
	}

	return nil
}

func akConfigured(c *Config) bool {
	return c.AKPubPath != "" && c.AKPrivPath != ""
}

func loadDevIDFiles(c *Config, info *config) error {
	devIDCertBytes, err := ioutil.ReadFile(c.DevIDCertPath)
	if err != nil {
		return fmt.Errorf("cannot load certificate: %w", err)
	}

	info.devIDCert, err = x509.ParseCertificate(devIDCertBytes)
	if err != nil {
		return fmt.Errorf("cannot parse certificate: %w", err)
	}

	info.devIDPriv, err = ioutil.ReadFile(c.DevIDPrivPath)
	if err != nil {
		return fmt.Errorf("cannot load private key: %w", err)
	}

	info.devIDPub, err = ioutil.ReadFile(c.DevIDPubPath)
	if err != nil {
		return fmt.Errorf("cannot load public key: %w", err)
	}

	return nil
}

func loadAKFiles(c *Config, info *config) error {
	var err error

	info.akPub, err = ioutil.ReadFile(c.AKPubPath)
	if err != nil {
		return fmt.Errorf("cannot load public key: %w", err)
	}

	info.akPriv, err = ioutil.ReadFile(c.AKPrivPath)
	if err != nil {
		return fmt.Errorf("cannot load private key: %w", err)
	}

	return nil
}

func loadTPMContext(intConf *config, log hclog.Logger) (*tpm.Context, error) {
	// Open TPM connection
	tpmCtx, err := tpm.Open(intConf.devicePath, log)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM at %q: %w", intConf.devicePath, err)
	}

	// Clean context in case of error
	defer func() {
		if err != nil {
			tpmCtx.Close()
		}
	}()

	// Load DevID
	tpmCtx.DevID, err = tpmCtx.LoadKey(intConf.devIDPub, intConf.devIDPriv)
	if err != nil {
		return nil, fmt.Errorf("cannot load DevID: %w", err)
	}

	// If DevID residency verification is not configured
	if !intConf.checkDevIDResidency {
		return tpmCtx, nil
	}

	// Load Attestation Key
	tpmCtx.AK, err = tpmCtx.LoadKey(intConf.akPub, intConf.akPriv)
	if err != nil {
		return nil, fmt.Errorf("cannot load attestation key: %w", err)
	}

	// Create Endorsement Key
	tpmCtx.EKPub, tpmCtx.EKHandle, err = tpmCtx.CreateEK()
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement key: %w", err)
	}

	// Get Endorsement Certificate
	tpmCtx.EKCert, err = tpmCtx.GetEKCert()
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve endorsement certificate: %w", err)
	}

	// Certify that DevID is in the same TPM than Attestation Key
	tpmCtx.CertifiedDevID, tpmCtx.CertificationSignature, err = tpmCtx.AK.Certify(tpmCtx.DevID.Handle)
	if err != nil {
		return nil, fmt.Errorf("cannot to certify DevID: %w", err)
	}

	return tpmCtx, nil
}
