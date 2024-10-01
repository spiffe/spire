package tpmdevid

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// We use a 32 bytes nonce to provide enough cryptographical randomness and to be
// consistent with other nonces sizes around the project.
const devIDChallengeNonceSize = 32

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(common_devid.PluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Config struct {
	DevIDBundlePath       string `hcl:"devid_ca_path"`
	EndorsementBundlePath string `hcl:"endorsement_ca_path"`
}

type config struct {
	trustDomain spiffeid.TrustDomain

	devIDRoots *x509.CertPool
	ekRoots    *x509.CertPool
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *config {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	if hclConfig.DevIDBundlePath == "" {
		status.ReportError("devid_ca_path is required")
	}
	if hclConfig.EndorsementBundlePath == "" {
		status.ReportError("endorsement_ca_path is required")
	}

	// Create initial internal configuration
	newConfig := &config{
		trustDomain: coreConfig.TrustDomain,
	}

	// Load DevID bundle
	var err error
	newConfig.devIDRoots, err = util.LoadCertPool(hclConfig.DevIDBundlePath)
	if err != nil {
		status.ReportErrorf("unable to load DevID trust bundle: %v", err)
	}

	// Load endorsement bundle if configured
	newConfig.ekRoots, err = util.LoadCertPool(hclConfig.EndorsementBundlePath)
	if err != nil {
		status.ReportErrorf("unable to load endorsement trust bundle: %v", err)
	}

	return newConfig
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m sync.Mutex
	c *config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	// Receive attestation request
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	conf := p.getConfiguration()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	// Unmarshall received attestation data
	attData := new(common_devid.AttestationRequest)
	err = json.Unmarshal(payload, attData)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall attestation data: %v", err)
	}

	// Decode attestation data
	if len(attData.DevIDCert) == 0 {
		return status.Error(codes.InvalidArgument, "no DevID certificate to attest")
	}

	devIDCert, err := x509.ParseCertificate(attData.DevIDCert[0])
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to parse DevID certificate: %v", err)
	}

	devIDIntermediates := x509.NewCertPool()
	for i, intermediatesBytes := range attData.DevIDCert[1:] {
		intermediate, err := x509.ParseCertificate(intermediatesBytes)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to parse DevID intermediate certificate %d: %v", i, err)
		}
		devIDIntermediates.AddCert(intermediate)
	}

	// Verify DevID certificate chain of trust
	chains, err := verifyDevIDSignature(devIDCert, devIDIntermediates, conf.devIDRoots)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to verify DevID signature: %v", err)
	}

	// Issue a DevID challenge (to prove the possession of the DevID private key).
	devIDChallenge, err := newNonce(devIDChallengeNonceSize)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to generate challenge: %v", err)
	}

	// Verify DevID residency
	var nonce []byte
	var credActivationChallenge *common_devid.CredActivation
	credActivationChallenge, nonce, err = verifyDevIDResidency(attData, conf.ekRoots)
	if err != nil {
		return err
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
	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challenge,
		},
	})
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
	if err = json.Unmarshal(responseReq.GetChallengeResponse(), challengeResponse); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenges response: %v", err)
	}

	// Verify DevID challenge
	err = VerifyDevIDChallenge(devIDCert, devIDChallenge, challengeResponse.DevID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "devID challenge verification failed: %v", err)
	}

	// Verify credential activation challenge
	err = VerifyCredActivationChallenge(nonce, challengeResponse.CredActivation)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "credential activation failed: %v", err)
	}

	// Create SPIFFE ID and selectors
	spiffeID, err := idutil.AgentID(conf.trustDomain, fmt.Sprintf("/%s/%s", common_devid.PluginName, Fingerprint(devIDCert)))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create agent ID: %v", err)
	}
	selectors := buildSelectorValues(devIDCert, chains)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    true,
				SpiffeId:       spiffeID.String(),
				SelectorValues: selectors,
			},
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.c = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

func (p *Plugin) getConfiguration() *config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func verifyDevIDSignature(cert *x509.Certificate, intermediates *x509.CertPool, roots *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Intermediates: intermediates,
	})
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return chains, nil
}

// verifyDevIDResidency verifies that the DevID resides on the same TPM than EK.
// This is done in two steps:
// (1) Verify that the DevID resides in the same TPM than the AK
// (2) Verify that the AK is in the same TPM than the EK.
// The verification is complete once the agent solves the challenge that this
// function generates.
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
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode DevID key public blob: %v", err)
	}

	akPub, err := tpm2.DecodePublic(attData.AKPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode attestation key public blob: %v", err)
	}

	ekPub, err := tpm2.DecodePublic(attData.EKPub)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "cannot decode endorsement key public blob")
	}

	// Verify the public part of the EK generated from the template is the same
	// than the one in the EK certificate.
	err = verifyEKsMatch(ekCert, ekPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "public key in EK certificate differs from public key created via EK template: %v", err)
	}

	// Verify EK chain of trust using the provided manufacturer roots.
	err = verifyEKSignature(ekCert, ekRoots)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot verify EK signature: %v", err)
	}

	// Verify DevID resides in the same TPM than AK
	err = VerifyDevIDCertification(&akPub, &devIDPub, attData.CertifiedDevID, attData.CertificationSignature)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot verify that DevID is in the same TPM than AK: %v", err)
	}

	// Issue a credential activation challenge (to verify AK is in the same TPM than EK)
	challenge, nonce, err := NewCredActivationChallenge(akPub, ekPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "cannot generate credential activation challenge: %v", err)
	}

	return challenge, nonce, nil
}

func isDevIDResidencyInfoComplete(attReq *common_devid.AttestationRequest) error {
	if len(attReq.AKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing attestation key public blob")
	}

	if len(attReq.DevIDPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing DevID key public blob")
	}

	if len(attReq.EKCert) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement certificate")
	}

	if len(attReq.EKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement key public blob")
	}

	return nil
}

func verifyEKSignature(ekCert *x509.Certificate, roots *x509.CertPool) error {
	// Check UnhandledCriticalExtensions for OIDs that we know what to do about
	// it (e.g. it's safe to ignore)
	subjectAlternativeNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	unhandledExtensions := []asn1.ObjectIdentifier{}
	for _, oid := range ekCert.UnhandledCriticalExtensions {
		// Endorsement certificate's SAN is not fully processed by x509 package
		if !oid.Equal(subjectAlternativeNameOID) {
			unhandledExtensions = append(unhandledExtensions, oid)
		}
	}

	ekCert.UnhandledCriticalExtensions = unhandledExtensions

	_, err := ekCert.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	})
	if err != nil {
		return fmt.Errorf("endorsement certificate verification failed: %w", err)
	}

	return nil
}

// verifyEKsMatch checks that the public key generated using the EK template
// matches the public key included in the Endorsement Certificate.
func verifyEKsMatch(ekCert *x509.Certificate, ekPub tpm2.Public) error {
	keyFromCert, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("key from certificate is not an RSA key")
	}

	cryptoKey, err := ekPub.Key()
	if err != nil {
		return fmt.Errorf("cannot get template key: %w", err)
	}

	keyFromTemplate, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("key from template is not an RSA key")
	}

	if keyFromCert.E != keyFromTemplate.E {
		return errors.New("exponent mismatch")
	}

	if keyFromCert.N.Cmp(keyFromTemplate.N) != 0 {
		return errors.New("modulus mismatch")
	}

	return nil
}

func VerifyDevIDCertification(pubAK, pubDevID *tpm2.Public, attestData, attestSig []byte) error {
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

func checkSignature(pub *tpm2.Public, data, sigRaw []byte) error {
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
	if _, err = h.Write(data); err != nil {
		return err
	}

	hashed := h.Sum(nil)

	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(sigRaw))
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(rsaKey, hash, hashed, sig.RSA.Signature)
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
