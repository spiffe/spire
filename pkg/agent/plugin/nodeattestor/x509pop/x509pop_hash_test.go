package x509pop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
)

// legacyChallenge mirrors the challenge representation produced by servers
// that predate hash selection; it has no hash field.
type legacyChallenge struct {
	RSASignature   *x509pop.RSASignatureChallenge   `json:"rsa_signature"`
	ECDSASignature *x509pop.ECDSASignatureChallenge `json:"ecdsa_signature"`
}

func (s *Suite) TestAttestSuccessWithHashAlgorithm() {
	keys := []struct {
		name string
		key  crypto.Signer
	}{
		{name: "RSA-2048", key: testkey.MustRSA2048()},
		{name: "ECDSA-P256", key: testkey.MustEC256()},
		{name: "ECDSA-P384", key: testkey.MustEC384()},
	}

	for _, key := range keys {
		cert, p := s.loadPluginWithKey(key.key)
		for _, hash := range []string{"", x509pop.HashSHA256, x509pop.HashSHA384} {
			s.Run(fmt.Sprintf("%s/hash=%q", key.name, hash), func() {
				challenge, err := x509pop.GenerateChallengeWithHash(cert, hash)
				s.Require().NoError(err)
				s.attestWithChallenge(p, cert, s.marshal(challenge), func(response *x509pop.Response) error {
					return x509pop.VerifyChallengeResponse(cert.PublicKey, challenge, response)
				})
			})
		}
	}
}

func (s *Suite) TestAttestLegacyServerChallenge() {
	// A server that predates hash selection sends challenges without the hash
	// field and verifies them with SHA-256.
	rsaKey := testkey.MustRSA2048()
	rsaCert, rsaPlugin := s.loadPluginWithKey(rsaKey)
	rsaChallenge, err := x509pop.GenerateRSASignatureChallenge()
	s.Require().NoError(err)
	s.attestWithChallenge(rsaPlugin, rsaCert, s.marshal(legacyChallenge{RSASignature: rsaChallenge}), func(response *x509pop.Response) error {
		return x509pop.VerifyRSASignatureResponse(&rsaKey.PublicKey, rsaChallenge, response.RSASignature)
	})

	ecKey := testkey.MustEC256()
	ecCert, ecPlugin := s.loadPluginWithKey(ecKey)
	ecChallenge, err := x509pop.GenerateECDSASignatureChallenge()
	s.Require().NoError(err)
	s.attestWithChallenge(ecPlugin, ecCert, s.marshal(legacyChallenge{ECDSASignature: ecChallenge}), func(response *x509pop.Response) error {
		return x509pop.VerifyECDSASignatureResponse(&ecKey.PublicKey, ecChallenge, response.ECDSASignature)
	})
}

func (s *Suite) TestAttestSHA384ResponseFailsSHA256Verification() {
	key := testkey.MustEC384()
	cert, p := s.loadPluginWithKey(key)
	challenge, err := x509pop.GenerateChallengeWithHash(cert, x509pop.HashSHA384)
	s.Require().NoError(err)

	err = p.Attest(context.Background(), streamBuilder.
		IgnoreThenChallenge(s.marshal(challenge)).
		Handle(func(challengeResponse []byte) ([]byte, error) {
			response := new(x509pop.Response)
			if err := json.Unmarshal(challengeResponse, response); err != nil {
				return nil, err
			}
			return nil, x509pop.VerifyECDSASignatureResponse(&key.PublicKey, challenge.ECDSASignature, response.ECDSASignature)
		}).Build())
	s.Require().ErrorContains(err, "ECDSA signature verify failed")
}

func (s *Suite) TestAttestFailureUnsupportedHash() {
	p := s.loadAndConfigurePlugin(false)
	challenge, err := x509pop.GenerateChallenge(s.leafCert)
	s.Require().NoError(err)

	for _, hash := range []string{"sha512", "SHA384", "md5"} {
		challenge.Hash = hash
		err = p.Attest(context.Background(), streamBuilder.IgnoreThenChallenge(s.marshal(challenge)).Build())
		s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(x509pop): failed to calculate challenge response")
		s.RequireGRPCStatusContains(err, codes.Internal, fmt.Sprintf("unsupported hash algorithm %q", hash))
	}
}

func (s *Suite) attestWithChallenge(p nodeattestor.NodeAttestor, cert *x509.Certificate, challengeBytes []byte, verify func(*x509pop.Response) error) {
	expectPayload := s.marshal(x509pop.AttestationData{
		Certificates: [][]byte{cert.Raw},
	})
	err := p.Attest(context.Background(), streamBuilder.
		ExpectThenChallenge(expectPayload, challengeBytes).
		Handle(func(challengeResponse []byte) ([]byte, error) {
			response := new(x509pop.Response)
			if err := json.Unmarshal(challengeResponse, response); err != nil {
				return nil, err
			}
			return nil, verify(response)
		}).Build())
	s.Require().NoError(err)
}

// loadPluginWithKey writes a self-signed certificate for key to disk and
// returns the certificate and an agent plugin configured to use it.
func (s *Suite) loadPluginWithKey(key crypto.Signer) (*x509.Certificate, nodeattestor.NodeAttestor) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node1.example.org"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	s.Require().NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	s.Require().NoError(err)

	dir := s.T().TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	s.Require().NoError(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600))
	s.Require().NoError(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))

	return cert, s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
		}),
		plugintest.Configuref(`
			private_key_path = %q
			certificate_path = %q`, keyPath, certPath),
	)
}
