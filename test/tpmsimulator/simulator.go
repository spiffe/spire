//go:build !darwin

package tpmsimulator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	ErrUsingClosedSimulator = simulator.ErrUsingClosedSimulator
)

type TPMSimulator struct {
	*simulator.Simulator
	ekRoot                       *x509.Certificate
	ownerHierarchyPassword       string
	endorsementHierarchyPassword string
}
type Credential struct {
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
	PrivateBlob   []byte
	PublicBlob    []byte
}

type ProvisioningAuthority struct {
	RootCert         *x509.Certificate
	RootKey          *rsa.PrivateKey
	IntermediateCert *x509.Certificate
	IntermediateKey  *rsa.PrivateKey
}

type ProvisioningConf struct {
	NoIntermediates bool
	RootCertificate *x509.Certificate
	RootKey         *rsa.PrivateKey
}

type KeyType int

const (
	RSA KeyType = iota
	ECC
)

// The "never expires" timestamp from RFC5280
var neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// DevID key template attributes according to TPM 2.0 Keys for device identity
// and attestation (section 7.3.4.1)
var flagDevIDKeyDefault = tpm2.FlagSign |
	tpm2.FlagFixedTPM |
	tpm2.FlagFixedParent |
	tpm2.FlagSensitiveDataOrigin |
	tpm2.FlagUserWithAuth

// New creates a new TPM simulator and sets an RSA endorsement certificate.
func New(endorsementHierarchyPassword, ownerHierarchyPassword string) (*TPMSimulator, error) {
	s, err := simulator.Get()
	if err != nil {
		return nil, err
	}
	sim := &TPMSimulator{
		Simulator:                    s,
		ownerHierarchyPassword:       ownerHierarchyPassword,
		endorsementHierarchyPassword: endorsementHierarchyPassword,
	}

	err = tpm2.HierarchyChangeAuth(sim,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession},
		sim.endorsementHierarchyPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to change endorsement hierarchy auth: %w", err)
	}

	ekCert, err := sim.createEndorsementCertificate()
	if err != nil {
		return nil, fmt.Errorf("unable to create endorsement certificate: %w", err)
	}

	err = sim.SetEndorsementCertificate(ekCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("unable to set endorsement certificate: %w", err)
	}

	err = tpm2.HierarchyChangeAuth(sim,
		tpm2.HandleOwner,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession},
		sim.ownerHierarchyPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to change owner hierarchy auth: %w", err)
	}

	return sim, nil
}

// NewProvisioningCA creates a new provisioning authority to issue DevIDs
// certificate. If root certificate and key are not provided, a new, self-signed
// certificate and key are generated.
func NewProvisioningCA(c *ProvisioningConf) (*ProvisioningAuthority, error) {
	if c == nil {
		return nil, errors.New("provisioning config is nil")
	}

	var rootCertificate *x509.Certificate
	var rootKey *rsa.PrivateKey
	switch {
	case c.RootCertificate != nil && c.RootKey != nil:
		rootCertificate = c.RootCertificate
		rootKey = c.RootKey

	case c.RootCertificate == nil && c.RootKey == nil:
		var err error
		rootKey, err = generateRSAKey()
		if err != nil {
			return nil, err
		}

		rootCertificate, err = createRootCertificate(rootKey, &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "root"},
			BasicConstraintsValid: true,
			IsCA:                  true,
			NotAfter:              neverExpires,
		})
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("the root certificate or private key is nil but not both")
	}

	provisioningAuthority := &ProvisioningAuthority{
		RootCert: rootCertificate,
		RootKey:  rootKey,
	}

	if c.NoIntermediates {
		return provisioningAuthority, nil
	}

	intermediateSigningKey, err := generateRSAKey()
	if err != nil {
		return nil, err
	}

	intermediateCertificate, err := createCertificate(&intermediateSigningKey.PublicKey, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotAfter:              neverExpires,
		Subject:               pkix.Name{CommonName: "intermediate"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, rootKey, rootCertificate)
	if err != nil {
		return nil, err
	}

	provisioningAuthority.IntermediateCert = intermediateCertificate
	provisioningAuthority.IntermediateKey = intermediateSigningKey

	return provisioningAuthority, nil
}

// Chain returns the leaf and intermediate certificates in DER format
func (c *Credential) Chain() [][]byte {
	chain := [][]byte{c.Certificate.Raw}
	for _, intermediate := range c.Intermediates {
		chain = append(chain, intermediate.Raw)
	}

	return chain
}

// ChainPem returns the leaf and intermediate certificates in PEM format
func (c *Credential) ChainPem() []byte {
	chain := []*x509.Certificate{c.Certificate}
	chain = append(chain, c.Intermediates...)
	return pemutil.EncodeCertificates(chain)
}

func (s *TPMSimulator) OpenTPM(path ...string) (io.ReadWriteCloser, error) {
	expectedTPMDevicePath := "/dev/tpmrm0"
	if runtime.GOOS == "windows" {
		expectedTPMDevicePath = ""
	}

	if len(path) != 0 && path[0] != expectedTPMDevicePath {
		return nil, fmt.Errorf("unexpected TPM device path %q (expected %q)", path[0], expectedTPMDevicePath)
	}
	return struct {
		io.ReadCloser
		io.Writer
	}{
		ReadCloser: io.NopCloser(s),
		Writer:     s,
	}, nil
}

// GenerateDevID generates a new DevID credential using the given provisioning
// authority and key type.
// DevIDs generated using this function are for test only. There is not guarantee
// that the identities generated by this method are compliant with the TCG/IEEE
// specification.
func (s *TPMSimulator) GenerateDevID(p *ProvisioningAuthority, keyType KeyType, keyPassword string) (*Credential, error) {
	// Create key in TPM according to the given key type
	privateBlob, publicBlob, err := s.createOrdinaryKey(keyType, "srk-key", keyPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to create ordinary key: %w", err)
	}

	// Decode public blob returned by TPM to get the public key
	devIDPublicBlobDecoded, err := tpm2.DecodePublic(publicBlob)
	if err != nil {
		return nil, fmt.Errorf("unable to decode public blob: %w", err)
	}

	devIDPublicKey, err := devIDPublicBlobDecoded.Key()
	if err != nil {
		return nil, fmt.Errorf("cannot get DevID key: %w", err)
	}

	// Mint DevID certificate
	devIDCert, err := p.issueCertificate(devIDPublicKey)
	if err != nil {
		return nil, err
	}

	// Create DevID credential
	devIDCred := &Credential{
		Certificate: devIDCert,
		PrivateBlob: privateBlob,
		PublicBlob:  publicBlob,
	}

	if p.IntermediateCert != nil {
		devIDCred.Intermediates = []*x509.Certificate{p.IntermediateCert}
	}

	return devIDCred, nil
}

// GetEKRoot returns the manufacturer CA used to sign the endorsement certificate
func (s *TPMSimulator) GetEKRoot() *x509.Certificate {
	return s.ekRoot
}

func (s *TPMSimulator) SetEndorsementCertificate(ekCert []byte) error {
	_ = tpm2.NVUndefineSpace(s, "", tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA)

	err := tpm2.NVDefineSpace(s,
		tpm2.HandlePlatform,
		tpmutil.EKCertificateHandleRSA,
		"",
		"",
		nil,
		tpm2.AttrPlatformCreate|tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrAuthWrite|tpm2.AttrAuthRead,
		uint16(len(ekCert)))
	if err != nil {
		return fmt.Errorf("cannot define NV space: %w", err)
	}

	err = tpm2.NVWrite(s, tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA, "", ekCert, 0)
	if err != nil {
		return fmt.Errorf("cannot write data to NV: %w", err)
	}

	return nil
}

func (s *TPMSimulator) createEndorsementCertificate() (*x509.Certificate, error) {
	rootKey, err := generateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("cannot generate root RSA key: %w", err)
	}

	s.ekRoot, err = createRootCertificate(rootKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot generate root certificate: %w", err)
	}

	ekHandle, ekPublicBlob, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(s, tpm2.HandleEndorsement,
			tpm2.PCRSelection{},
			s.endorsementHierarchyPassword,
			"",
			client.DefaultEKTemplateRSA())
	if err != nil {
		return nil, fmt.Errorf("cannot generate endorsement key pair: %w", err)
	}

	err = tpm2.FlushContext(s, ekHandle)
	if err != nil {
		return nil, fmt.Errorf("cannot to flush endorsement key handle: %w", err)
	}

	ekPublicBlobDecoded, err := tpm2.DecodePublic(ekPublicBlob)
	if err != nil {
		return nil, fmt.Errorf("cannot decode endorsement key public blob: %w", err)
	}

	ekPublicKey, err := ekPublicBlobDecoded.Key()
	if err != nil {
		return nil, fmt.Errorf("cannot get endorsement public key: %w", err)
	}

	return createCertificate(ekPublicKey, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
		Subject:      pkix.Name{CommonName: "root"},
	}, rootKey, s.ekRoot)
}

// createOrdinaryKey creates an ordinary TPM key of the type keyType under
// the owner hierarchy
func (s *TPMSimulator) createOrdinaryKey(keyType KeyType, parentKeyPassword, keyPassword string) ([]byte, []byte, error) {
	var err error
	var keyTemplate tpm2.Public
	var srkTemplate tpm2.Public
	switch keyType {
	case RSA:
		keyTemplate = defaultDevIDTemplateRSA()
		srkTemplate = tpmutil.SRKTemplateHighRSA()

	case ECC:
		keyTemplate = defaultDevIDTemplateECC()
		srkTemplate = tpmutil.SRKTemplateHighECC()

	default:
		return nil, nil, fmt.Errorf("unknown key type: %v", keyType)
	}

	srkHandle, _, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(s, tpm2.HandleOwner, tpm2.PCRSelection{}, s.ownerHierarchyPassword, parentKeyPassword, srkTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create new storage root key: %w", err)
	}

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(
		s,
		srkHandle,
		tpm2.PCRSelection{},
		parentKeyPassword,
		keyPassword,
		keyTemplate,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create key: %w", err)
	}

	err = tpm2.FlushContext(s, srkHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot flush storage root key handle: %w", err)
	}

	return privateBlob, publicBlob, nil
}

func (p *ProvisioningAuthority) issueCertificate(publicKey any) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var privateKey *rsa.PrivateKey

	switch {
	case p.IntermediateCert != nil && p.IntermediateKey != nil:
		cert = p.IntermediateCert
		privateKey = p.IntermediateKey

	case p.IntermediateCert == nil && p.IntermediateKey == nil:
		cert = p.RootCert
		privateKey = p.RootKey

	default:
		return nil, errors.New("the intermediate certificate or private key is nil but not both")
	}

	return createCertificate(publicKey, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: "devid-leaf"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, privateKey, cert)
}

func createRootCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate) (*x509.Certificate, error) {
	return createCertificate(&key.PublicKey, tmpl, key, tmpl)
}

func createCertificate(key any, tmpl *x509.Certificate, parentKey *rsa.PrivateKey, parent *x509.Certificate) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key, parentKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 768) //nolint: gosec // small key is to keep test fast... not a security feature
}

func defaultDevIDTemplateRSA() tpm2.Public {
	devIDKeyTemplateRSA := client.AKTemplateRSA()
	devIDKeyTemplateRSA.Attributes = flagDevIDKeyDefault
	return devIDKeyTemplateRSA
}

func defaultDevIDTemplateECC() tpm2.Public {
	devIDKeyTemplateECC := client.AKTemplateECC()
	devIDKeyTemplateECC.Attributes = flagDevIDKeyDefault
	return devIDKeyTemplateECC
}
