// +build linux

package tpmsimulator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/HewlettPackard/devid-provisioning-tool/pkg/agent/keygen"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/devid"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
)

type Credential struct {
	Certificate *x509.Certificate
	PrivateBlob []byte
	PublicBlob  []byte
}

type ProvisioningAuthority struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

type TPMSimulator struct {
	*simulator.Simulator
	ekRoot *x509.Certificate
}

type KeyType int

const (
	RSA KeyType = iota
	ECC
)

// The "never expires" timestamp from RFC5280
var neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// New creates a new TPM simulator. In addition, DevID credentials
// are generated using this TPM and returned as a result.
func New() (*TPMSimulator, error) {
	s, err := simulator.Get()
	if err != nil {
		return nil, err
	}
	sim := &TPMSimulator{Simulator: s}

	ekCert, err := sim.createEndorsementCertificate()
	if err != nil {
		return nil, fmt.Errorf("unable to create endorsement certificate: %v", err)
	}

	err = sim.setEndorsementCertificate(ekCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("unable to set endorsement certificate: %v", err)
	}

	return sim, nil
}

func CreateProvisioningCA() (*ProvisioningAuthority, error) {
	caSigningKey, err := generateRSAKey()
	if err != nil {
		return nil, err
	}

	caCertificate, err := createRootCertificate(caSigningKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
	})
	if err != nil {
		return nil, err
	}

	return &ProvisioningAuthority{
		Cert: caCertificate,
		Key:  caSigningKey,
	}, nil
}

func (s *TPMSimulator) GenerateDevID(p *ProvisioningAuthority, keyType KeyType) (*Credential, error) {
	// Create key generator
	var kgen *keygen.Keygen
	switch keyType {
	case RSA:
		kgen = keygen.New(keygen.UseSRKTemplate(tpmutil.SRKTemplateHighRSA()))
	case ECC:
		kgen = keygen.New(keygen.UseSRKTemplate(tpm2tools.SRKTemplateECC()), keygen.UseDevIDTemplate(tpm2tools.AIKTemplateECC()))
	default:
		return nil, fmt.Errorf("unknown key type")
	}

	// Generate CSRs for DevID
	csr, resources, err := devid.CreateSigningRequest(context.Background(), kgen, s)
	if err != nil {
		return nil, fmt.Errorf("cannot create CSR: %w", err)
	}

	// Flush keys from TPM
	tpm2.FlushContext(s, resources.DevID.Handle)
	tpm2.FlushContext(s, resources.Attestation.Handle)

	// Mint DevID certificate
	devIDKey, err := csr.DevIDKey.Key()
	if err != nil {
		return nil, fmt.Errorf("cannot get DevID key: %w", err)
	}

	devIDCert, err := p.issueCertificate(devIDKey)
	if err != nil {
		return nil, err
	}

	// Return DevID credential
	devIDCred := &Credential{
		Certificate: devIDCert,
		PrivateBlob: resources.DevID.PrivateBlob,
		PublicBlob:  resources.DevID.PublicBlob,
	}

	return devIDCred, nil
}

// GetEKRoot returns the "manufacturer" CA used to sign the endorsement certificate
func (s *TPMSimulator) GetEKRoot() *x509.Certificate {
	return s.ekRoot
}

func (s *TPMSimulator) setEndorsementCertificate(ekCert []byte) error {
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

	ek, err := tpm2tools.EndorsementKeyRSA(s)
	if err != nil {
		return nil, fmt.Errorf("cannot generate endorsement key pair: %w", err)
	}
	defer ek.Close()

	ekPub, ok := ek.PublicKey().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("endorsement key is not an RSA key: %v", ek.PublicKey())
	}

	return createCertificate(ekPub, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
		Subject:      pkix.Name{CommonName: "some common name"},
	}, rootKey, s.ekRoot)
}

func (p *ProvisioningAuthority) issueCertificate(key interface{}) (*x509.Certificate, error) {
	return createCertificate(key, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: "CommonName"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, p.Key, p.Cert)

}

func createRootCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate) (*x509.Certificate, error) {
	return createCertificate(&key.PublicKey, tmpl, key, tmpl)
}

func createCertificate(key interface{}, tmpl *x509.Certificate, parentKey *rsa.PrivateKey, parent *x509.Certificate) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key, parentKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 768) //nolint: gosec // small key is to keep test fast... not a security feature
}
