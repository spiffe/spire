package devid

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/devid"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	spc "github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(devid.PluginName,
		nodeattestor.PluginServer(p),
	)
}

type internalConfig struct {
	trustDomain string

	devIDRoots          *x509.CertPool
	ekRoots             *x509.CertPool
	checkDevIDResidency bool
}

type ExternalConfig struct {
	DevIDBundlePath       string `hcl:"devid_bundle_path"`
	EndorsementBundlePath string `hcl:"endorsement_bundle_path"`
	CheckDevIDResidency   bool   `hcl:"check_devid_residency"`
}

type Plugin struct {
	nodeattestor.UnsafeNodeAttestorServer

	m sync.Mutex
	c *internalConfig
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	// Receive attestation request
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	conf := p.getConfiguration()
	if conf == nil {
		return devid.Error("not configured")
	}

	if dataType := req.AttestationData.Type; dataType != devid.PluginName {
		return devid.Error("unexpected attestation data type %q", dataType)
	}

	// Unmarshall received attestation data
	attData := new(devid.AttestationRequest)
	err = json.Unmarshal(req.AttestationData.Data, attData)
	if err != nil {
		return devid.Error("unable to unmarshall attestation data: %w", err)
	}

	// Decode attestation data
	if len(attData.DevIDCert) == 0 {
		return devid.Error("no DevID certificate to attest")
	}

	devIDCert, err := x509.ParseCertificate(attData.DevIDCert)
	if err != nil {
		return devid.Error("unable to parse DevID certificate: %w", err)
	}

	// Verify DevID certificate chain of trust
	err = verifyDevIDSignature(devIDCert, conf.devIDRoots)
	if err != nil {
		return devid.Error("unable to verify DevID signature: %w", err)
	}

	// Issue a DevID challenge (to prove the possession of the DevID private key).
	devIDChallenge, err := newDevIDChallenge()
	if err != nil {
		return devid.Error("unable to generate challenge: %w", err)
	}

	// Verify DevID residency (if configured)
	var nonce []byte
	var credActivationChallenge *devid.CredActivation
	if conf.checkDevIDResidency {
		credActivationChallenge, nonce, err = verifyDevIDResidency(attData, conf.ekRoots)
		if err != nil {
			return devid.Error("unable to verify DevID residency: %w", err)
		}
	}

	// Marshal challenges
	challenge, err := json.Marshal(devid.ChallengeRequest{
		DevID:          devIDChallenge,
		CredActivation: credActivationChallenge,
	})
	if err != nil {
		return devid.Error("unable to marshal challenge data: %w", err)
	}

	// Send challenges to the agent
	err = stream.Send(&nodeattestor.AttestResponse{Challenge: challenge})
	if err != nil {
		return err
	}

	// Receive challenges response
	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	// Unmarshal challenges response
	challengeResponse := &devid.ChallengeResponse{}
	if err = json.Unmarshal(responseReq.Response, challengeResponse); err != nil {
		return devid.Error("unable to unmarshall challenges response: %w", err)
	}

	// Verify DevID challenge
	err = verifyDevIDChallenge(devIDCert, devIDChallenge, challengeResponse.DevID)
	if err != nil {
		return devid.Error("devID challenge verification failed: %w", err)
	}

	// Verify credential activation challenge (if configured)
	if conf.checkDevIDResidency {
		err = verifyCredActivationChallenge(nonce, challengeResponse.CredActivation)
		if err != nil {
			return devid.Error("credential activation failed: %w", err)
		}
	}

	// Create SPIFFE ID and selectors
	certSelectors := FromCertificate(devid.PluginName, "certificate", devIDCert)
	fingerprint := x509pop.Fingerprint(devIDCert)
	certSelectors = append(certSelectors, &spc.Selector{
		Type:  devid.PluginName,
		Value: fmt.Sprintf("fingerprint:%s", fingerprint),
	})

	spiffeID := idutil.AgentID(conf.trustDomain, fmt.Sprintf("%s/%s", devid.PluginName, fingerprint))

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   spiffeID,
		Selectors: certSelectors,
	})
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	err := devid.ValidateGlobalConfig(req.GlobalConfig)
	if err != nil {
		return nil, err
	}

	extConf, err := decodePluginConfig(req.Configuration)
	if err != nil {
		return nil, devid.Error("unable to decode configuration: %w", err)
	}

	err = validatePluginConfig(extConf)
	if err != nil {
		return nil, fmt.Errorf("missing configurable: %w", err)
	}

	// Create initial internal configuration
	inConf := &internalConfig{
		trustDomain:         req.GlobalConfig.TrustDomain,
		checkDevIDResidency: extConf.CheckDevIDResidency,
	}

	// Load DevID bundle
	inConf.devIDRoots, err = util.LoadCertPool(extConf.DevIDBundlePath)
	if err != nil {
		return nil, devid.Error("unable to load DevID trust bundle: %w", err)
	}

	// Load endorsement bundle if configured
	if extConf.CheckDevIDResidency {
		inConf.ekRoots, err = util.LoadCertPool(extConf.EndorsementBundlePath)
		if err != nil {
			return nil, devid.Error("unable to load endorsement trust bundle: %w", err)
		}
	}

	p.setConfiguration(inConf)

	return &spi.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfiguration() *internalConfig {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) setConfiguration(c *internalConfig) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func decodePluginConfig(hclConf string) (*ExternalConfig, error) {
	extConfig := new(ExternalConfig)
	if err := hcl.Decode(extConfig, hclConf); err != nil {
		return nil, err
	}

	return extConfig, nil
}

func validatePluginConfig(extConf *ExternalConfig) error {
	// DevID bundle path is always required
	if extConf.DevIDBundlePath == "" {
		return devid.Error("devid_bundle_path is required")
	}

	// Endorsement bundle path is required if check_devid_residency is set
	if extConf.CheckDevIDResidency && extConf.EndorsementBundlePath == "" {
		return devid.Error("endorsement_bundle_path is required if check_devid_residency is enabled")
	}

	return nil
}

func verifyDevIDSignature(cert *x509.Certificate, roots *x509.CertPool) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}

// verifyDevIDResidency verifies that the DevID resides on the same TPM than EK.
// The process is the following:
//  1. Verify that DevID is in the same TPM than AK
//  2. Verify that AK is in the same TPM than EK (credential activation)
//  3. Verify EK chain of trust using the provided manufacturer roots.
func verifyDevIDResidency(attData *devid.AttestationRequest, ekRoots *x509.CertPool) (*devid.CredActivation, []byte, error) {
	// Check that request contains all the information required to validate DevID residency
	err := isDevIDResidencyInfoComplete(attData)
	if err != nil {
		return nil, nil, err
	}

	// Decode attestation data
	ekCert, err := x509.ParseCertificate(attData.EKCert)
	if err != nil {
		return nil, nil, devid.Error("cannot parse endorsement certificate: %w", err)
	}

	devIDPub, err := tpm2.DecodePublic(attData.DevIDPub)
	if err != nil {
		return nil, nil, devid.Error("cannot decode public DevID: %v", err)
	}

	akPub, err := tpm2.DecodePublic(attData.AKPub)
	if err != nil {
		return nil, nil, devid.Error("cannot to decode attestation key")
	}

	ekPub, err := tpm2.DecodePublic(attData.EKPub)
	if err != nil {
		return nil, nil, devid.Error("cannot decode endorsement key")
	}

	// 1. Verify DevID resides in the same TPM than AK
	err = verifyDevIDCertification(&akPub, &devIDPub, attData.CertifiedDevID, attData.CertificationSignature)
	if err != nil {
		return nil, nil, devid.Error("cannot to verify that DevID is in the same TPM than AK: %v", err)
	}

	// 2. Issue a credential activation challenge (to verify AK is in the same TPM than EK)
	challenge, nonce, err := newCredActivationChallenge(akPub, ekPub)
	if err != nil {
		return nil, nil, devid.Error("cannot generate credential activation challenge")
	}

	// 3. Verify EK chain of trust using the provided manufacturer roots.
	err = verifyEKSignature(ekCert, ekRoots)
	if err != nil {
		return nil, nil, err
	}

	return challenge, nonce, nil
}

func isDevIDResidencyInfoComplete(attReq *devid.AttestationRequest) error {
	if len(attReq.AKPub) == 0 {
		return fmt.Errorf("missing attestation public key")
	}

	if len(attReq.DevIDPub) == 0 {
		return fmt.Errorf("missing DevID public key")
	}

	if len(attReq.EKCert) == 0 {
		return fmt.Errorf("missing endorsement certificate")
	}

	if len(attReq.EKPub) == 0 {
		return fmt.Errorf("missing endorsement public key")
	}

	return nil
}

func verifyEKSignature(ekCert *x509.Certificate, roots *x509.CertPool) error {
	// Check UnhandledCriticalExtensions for OIDs that we know what to do about
	// it (e.g. it's safe to ignore)
	subjectAlternativeNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	if len(ekCert.UnhandledCriticalExtensions) > 0 {
		unhandledExtensions := []asn1.ObjectIdentifier{}
		for _, oid := range ekCert.UnhandledCriticalExtensions {
			if oid.Equal(subjectAlternativeNameOID) {
				// Subject Alternative Name is not processed at the time.
				continue
			}
		}

		ekCert.UnhandledCriticalExtensions = unhandledExtensions
	}

	_, err := ekCert.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	})
	if err != nil {
		return fmt.Errorf("endorsement certificate verification failed: %w", err)
	}

	return nil
}

func verifyDevIDCertification(pubAK, pubDevID *tpm2.Public, attestData, attestSig []byte) error {
	err := checkSignature(pubAK, attestData, attestSig)
	if err != nil {
		return err
	}

	data, err := tpm2.DecodeAttestationData(attestData)
	if err != nil {
		return err
	}

	if data.AttestedCertifyInfo == nil {
		return errors.New("missing certify info")
	}

	ok, err := data.AttestedCertifyInfo.Name.MatchesPublic(*pubDevID)
	if err != nil {
		return err
	}

	if !ok {
		return errors.New("certify failed")
	}

	return nil
}

func checkSignature(pub *tpm2.Public, data, sig []byte) error {
	key, err := pub.Key()
	if err != nil {
		return err
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("only RSA keys are supported")
	}

	sigScheme, err := getSignatureScheme(*pub)
	if err != nil {
		return err
	}

	hash, err := sigScheme.Hash.Hash()
	if err != nil {
		return err
	}

	h := hash.New()
	_, err = h.Write(data)
	if err != nil {
		return err
	}

	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, hash, hashed, sig)
}

func getSignatureScheme(pub tpm2.Public) (*tpm2.SigScheme, error) {
	canSign := (pub.Attributes & tpm2.FlagSign) == tpm2.FlagSign
	if !canSign {
		return nil, errors.New("not a signing key")
	}

	switch pub.Type {
	case tpm2.AlgRSA:
		params := pub.RSAParameters
		if params == nil {
			return nil, errors.New("malformed key")
		}

		return params.Sign, nil

	case tpm2.AlgECDSA:
		params := pub.ECCParameters
		if params == nil {
			return nil, errors.New("malformed key")
		}

		return params.Sign, nil

	default:
		return nil, fmt.Errorf("unsupported key type 0x%04x", pub.Type)
	}
}
