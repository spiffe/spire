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
	common_devid "github.com/spiffe/spire/pkg/common/plugin/devid"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	spc "github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/server/nodeattestor/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(common_devid.PluginName,
		nodeattestorv0.PluginServer(p),
	)
}

type config struct {
	trustDomain string

	devIDRoots          *x509.CertPool
	ekRoots             *x509.CertPool
	checkDevIDResidency bool
}

type Config struct {
	DevIDBundlePath       string `hcl:"devid_bundle_path"`
	EndorsementBundlePath string `hcl:"endorsement_bundle_path"`
	CheckDevIDResidency   bool   `hcl:"check_devid_residency"`
}

type Plugin struct {
	nodeattestorv0.UnsafeNodeAttestorServer

	m sync.Mutex
	c *config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv0.NodeAttestor_AttestServer) error {
	// Receive attestation request
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	conf := p.getConfiguration()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	if dataType := req.AttestationData.Type; dataType != common_devid.PluginName {
		return status.Errorf(codes.InvalidArgument, "unexpected attestation data type %q", dataType)
	}

	// Unmarshall received attestation data
	attData := new(common_devid.AttestationRequest)
	err = json.Unmarshal(req.AttestationData.Data, attData)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall attestation data: %v", err)
	}

	// Decode attestation data
	if len(attData.DevIDCert) == 0 {
		return status.Error(codes.InvalidArgument, "no DevID certificate to attest")
	}

	devIDCert, err := x509.ParseCertificate(attData.DevIDCert)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to parse DevID certificate: %v", err)
	}

	// Verify DevID certificate chain of trust
	err = verifyDevIDSignature(devIDCert, conf.devIDRoots)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "unable to verify DevID signature: %v", err)
	}

	// Issue a DevID challenge (to prove the possession of the DevID private key).
	devIDChallenge, err := newDevIDChallenge()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to generate challenge: %v", err)
	}

	// Verify DevID residency (if configured)
	var nonce []byte
	var credActivationChallenge *common_devid.CredActivation
	if conf.checkDevIDResidency {
		credActivationChallenge, nonce, err = verifyDevIDResidency(attData, conf.ekRoots)
		if err != nil {
			return err
		}
	}

	// Marshal challenges
	challenge, err := json.Marshal(common_devid.ChallengeRequest{
		DevID:          devIDChallenge,
		CredActivation: credActivationChallenge,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenges data: %v", err)
	}

	// Send challenges to the agent
	err = stream.Send(&nodeattestorv0.AttestResponse{Challenge: challenge})
	if err != nil {
		return status.Errorf(status.Code(err), "unable to send challenges: %v", err)
	}

	// Receive challenges response
	responseReq, err := stream.Recv()
	if err != nil {
		return status.Errorf(status.Code(err), "unable to receive challenges response: %v", err)
	}

	// Unmarshal challenges response
	challengeResponse := &common_devid.ChallengeResponse{}
	if err = json.Unmarshal(responseReq.Response, challengeResponse); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenges response: %v", err)
	}

	// Verify DevID challenge
	err = verifyDevIDChallenge(devIDCert, devIDChallenge, challengeResponse.DevID)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "devID challenge verification failed: %v", err)
	}

	// Verify credential activation challenge (if configured)
	if conf.checkDevIDResidency {
		err = verifyCredActivationChallenge(nonce, challengeResponse.CredActivation)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "credential activation failed: %v", err)
		}
	}

	// Create SPIFFE ID and selectors
	certSelectors := selectorsFromCertificate(common_devid.PluginName, "certificate", devIDCert)
	fingerprint := x509pop.Fingerprint(devIDCert)
	certSelectors = append(certSelectors, &spc.Selector{
		Type:  common_devid.PluginName,
		Value: fmt.Sprintf("fingerprint:%s", fingerprint),
	})

	spiffeID := idutil.AgentID(conf.trustDomain, fmt.Sprintf("%s/%s", common_devid.PluginName, fingerprint))

	return stream.Send(&nodeattestorv0.AttestResponse{
		AgentId:   spiffeID,
		Selectors: certSelectors,
	})
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
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

	// Create initial internal configuration
	intConf := &config{
		trustDomain:         req.GlobalConfig.TrustDomain,
		checkDevIDResidency: extConf.CheckDevIDResidency,
	}

	// Load DevID bundle
	intConf.devIDRoots, err = util.LoadCertPool(extConf.DevIDBundlePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to load DevID trust bundle: %v", err)
	}

	// Load endorsement bundle if configured
	if extConf.CheckDevIDResidency {
		intConf.ekRoots, err = util.LoadCertPool(extConf.EndorsementBundlePath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to load endorsement trust bundle: %v", err)
		}
	}

	p.setConfiguration(intConf)

	return &spi.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfiguration() *config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) setConfiguration(c *config) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func decodePluginConfig(hclConf string) (*Config, error) {
	extConfig := new(Config)
	if err := hcl.Decode(extConfig, hclConf); err != nil {
		return nil, err
	}

	return extConfig, nil
}

func validatePluginConfig(extConf *Config) error {
	switch {
	case extConf.DevIDBundlePath == "":
		return errors.New("devid_bundle_path is required")

	case extConf.CheckDevIDResidency && extConf.EndorsementBundlePath == "":
		return errors.New("endorsement_bundle_path is required if check_devid_residency is enabled")
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
func verifyDevIDResidency(attData *common_devid.AttestationRequest, ekRoots *x509.CertPool) (*common_devid.CredActivation, []byte, error) {
	// Check that request contains all the information required to validate DevID residency
	err := isDevIDResidencyInfoComplete(attData)
	if err != nil {
		return nil, nil, err
	}

	// Decode attestation data
	ekCert, err := x509.ParseCertificate(attData.EKCert)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot parse endorsement certificate: %v", err)
	}

	devIDPub, err := tpm2.DecodePublic(attData.DevIDPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode public DevID: %v", err)
	}

	akPub, err := tpm2.DecodePublic(attData.AKPub)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "cannot to decode attestation key")
	}

	ekPub, err := tpm2.DecodePublic(attData.EKPub)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "cannot decode endorsement key")
	}

	// 1. Verify DevID resides in the same TPM than AK
	err = verifyDevIDCertification(&akPub, &devIDPub, attData.CertifiedDevID, attData.CertificationSignature)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unauthenticated, "cannot to verify that DevID is in the same TPM than AK: %v", err)
	}

	// 2. Issue a credential activation challenge (to verify AK is in the same TPM than EK)
	challenge, nonce, err := newCredActivationChallenge(akPub, ekPub)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, "cannot generate credential activation challenge")
	}

	// 3. Verify EK chain of trust using the provided manufacturer roots.
	err = verifyEKSignature(ekCert, ekRoots)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unauthenticated, "cannot verify EK signature: %v", err)
	}

	return challenge, nonce, nil
}

func isDevIDResidencyInfoComplete(attReq *common_devid.AttestationRequest) error {
	if len(attReq.AKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing attestation public key")
	}

	if len(attReq.DevIDPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing DevID public key")
	}

	if len(attReq.EKCert) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement certificate")
	}

	if len(attReq.EKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement public key")
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
