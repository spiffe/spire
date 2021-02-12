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
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/devid/tpm"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/devid"
	spc "github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	// defaultDevicePath is the value used when tpm_device_path is not set
	defaultDevicePath = "/dev/tpmrm0"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(devid.PluginName, nodeattestor.PluginServer(p))
}

type ExternalConfig struct {
	DevIDPrivPath string `hcl:"devid_priv_path"`
	DevIDPubPath  string `hcl:"devid_pub_path"`
	DevIDCertPath string `hcl:"devid_cert_path"`

	AKPrivPath string `hcl:"ak_priv_path"`
	AKPubPath  string `hcl:"ak_pub_path"`

	DevicePath string `hcl:"tpm_device_path"`
}

type internalConfig struct {
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
	nodeattestor.UnsafeNodeAttestorServer
	log hclog.Logger

	m sync.Mutex
	c *internalConfig
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	conf := p.getConfig()
	if conf == nil {
		return devid.Error("not configured")
	}

	// Open TPM connection and loads keys
	tpm, err := loadTPMContext(conf, p.log)
	if err != nil {
		return fmt.Errorf("unable to load context: %w", err)
	}
	defer tpm.Close()

	// Marshal attestation data
	marshalledAttData, err := json.Marshal(devid.AttestationRequest{
		DevIDCert: conf.devIDCert.Raw,
		DevIDPub:  conf.devIDPub,

		EKCert: tpm.EKCert,
		EKPub:  tpm.EKPub,

		AKPub: conf.akPub,

		CertifiedDevID:         tpm.CertifiedDevID,
		CertificationSignature: tpm.CertificationSignature,
	})
	if err != nil {
		return fmt.Errorf("unable to marshall attestation data: %w", err)
	}

	// Send attestation request
	err = stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &spc.AttestationData{
			Type: devid.PluginName,
			Data: marshalledAttData,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to send attestation data: %w", err)
	}

	// Receive challenges
	marshalledChallenges, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("unable to receive challenge: %w", err)
	}

	challenges := &devid.ChallengeRequest{}
	if err = json.Unmarshal(marshalledChallenges.Challenge, challenges); err != nil {
		return fmt.Errorf("unable to unmarshall challenge: %w", err)
	}

	// Solve DevID challenge (verify the possession of the DevID private key)
	devIDChallengeResp, err := tpm.SolveDevIDChallenge(challenges.DevID)
	if err != nil {
		return fmt.Errorf("unable to solve DevID challenge: %w", err)
	}

	// If DevID residency verification configured
	var credActChallengeResp []byte
	if conf.checkDevIDResidency && challenges.CredActivation != nil {
		// Solve Credential Activation challenge
		credActChallengeResp, err = tpm.SolveCredActivationChallenge(
			challenges.CredActivation.Credential,
			challenges.CredActivation.Secret)
		if err != nil {
			return fmt.Errorf("unable to solve credential activation challenge: %w", err)
		}
	}

	// Marshal challenges responses
	marshalledChallengeResp, err := json.Marshal(devid.ChallengeResponse{
		DevID:          devIDChallengeResp,
		CredActivation: credActChallengeResp,
	})
	if err != nil {
		return fmt.Errorf("unable to marshal challenge response: %w", err)
	}

	// Send challenge response back to the server
	err = stream.Send(&nodeattestor.FetchAttestationDataResponse{
		Response: marshalledChallengeResp,
	})
	if err != nil {
		return fmt.Errorf("unable to send challenge response: %w", err)
	}

	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	err := devid.ValidateGlobalConfig(req.GlobalConfig)
	if err != nil {
		return nil, err
	}

	extConf, err := decodePluginConfig(req.Configuration)
	if err != nil {
		return nil, devid.Error("unable to decode configuration: %w", err)
	}

	p.setPluginConfigDefaults(extConf)

	err = validatePluginConfig(extConf)
	if err != nil {
		return nil, fmt.Errorf("missing configurable: %w", err)
	}

	// Create initial internal configuration
	inConf := &internalConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		devicePath:  extConf.DevicePath,

		// If Attestation Key is configured, it is assumed that the user wants to verify DevID residency
		checkDevIDResidency: akConfigured(extConf),
	}

	// Load DevID files
	err = loadDevIDFiles(extConf, inConf)
	if err != nil {
		return nil, fmt.Errorf("unable to load DevID files: %w", err)
	}

	// Load Attestation Key files (if configured)
	if inConf.checkDevIDResidency {
		err = loadAKFiles(extConf, inConf)
		if err != nil {
			return nil, fmt.Errorf("unable to load attestation key files: %w", err)
		}
	}

	p.setConfig(inConf)

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) getConfig() *internalConfig {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) setConfig(c *internalConfig) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func (p *Plugin) setPluginConfigDefaults(config *ExternalConfig) {
	if config.DevicePath == "" {
		config.DevicePath = defaultDevicePath
		p.log.Info("tpm_device_path is not set, using default: %q", defaultDevicePath)
	}
}

func decodePluginConfig(hclConf string) (*ExternalConfig, error) {
	extConfig := new(ExternalConfig)
	if err := hcl.Decode(extConfig, hclConf); err != nil {
		return nil, err
	}

	return extConfig, nil
}

func validatePluginConfig(c *ExternalConfig) error {
	// DevID certificate, public and private key are always required
	if c.DevIDCertPath == "" {
		return fmt.Errorf("devid_cert_path is required")
	}

	if c.DevIDPrivPath == "" {
		return fmt.Errorf("devid_priv_path is required")
	}

	if c.DevIDPubPath == "" {
		return fmt.Errorf("devid_pub_path is required")
	}

	// Attestation private and public keys are not required but if one is
	// provided the other one is also needed.
	if c.AKPrivPath == "" && c.AKPubPath == "" {
		return nil
	}

	if c.AKPrivPath == "" {
		return fmt.Errorf("ak_priv_path is required if ak_pub_path is provided")
	}

	if c.AKPubPath == "" {
		return fmt.Errorf("ak_pub_path is required if ak_priv_path is provided")
	}

	return nil
}

func akConfigured(c *ExternalConfig) bool {
	return c.AKPubPath != "" && c.AKPrivPath != ""
}

func loadDevIDFiles(c *ExternalConfig, info *internalConfig) error {
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

func loadAKFiles(c *ExternalConfig, info *internalConfig) error {
	var err error

	info.akPub, err = ioutil.ReadFile(c.AKPubPath)
	if err != nil {
		return fmt.Errorf("cannot load public key")
	}

	info.akPriv, err = ioutil.ReadFile(c.AKPrivPath)
	if err != nil {
		return fmt.Errorf("cannot load private key")
	}

	return nil
}

func loadTPMContext(attInfo *internalConfig, log hclog.Logger) (*tpm.Context, error) {
	// Open TPM connection
	c, err := tpm.Open(attInfo.devicePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM at %q: %w", attInfo.devicePath, err)
	}

	// Set TPM context logger
	c.SetLogger(log)

	// Clean context in case of error
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	// Load DevID
	c.DevID, err = c.LoadKey(attInfo.devIDPub, attInfo.devIDPriv)
	if err != nil {
		return nil, fmt.Errorf("cannot load DevID: %w", err)
	}

	// If DevID residency verification is configured
	if attInfo.checkDevIDResidency {
		// Load Attestation Key
		c.AK, err = c.LoadKey(attInfo.akPub, attInfo.akPriv)
		if err != nil {
			return nil, fmt.Errorf("cannot load attestation key: %w", err)
		}

		// Create Endorsement Key
		c.EKPub, c.EKHandle, err = c.CreateEK()
		if err != nil {
			return nil, fmt.Errorf("cannot create endorsement key: %w", err)
		}

		// Get Endorsement Certificate
		c.EKCert, err = c.GetEKCert()
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve endorsement certificate: %w", err)
		}

		// Certify that DevID is in the same TPM than Attestation Key
		c.CertifiedDevID, c.CertificationSignature, err = c.AK.Certify(c.DevID.Handle)
		if err != nil {
			return nil, fmt.Errorf("cannot to certify DevID: %w", err)
		}
	}

	return c, nil
}
