package keymanagertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

type Maker func(t *testing.T) keymanager.Plugin

// the maker function is called. the returned key manager is expected to be
// already configured.
func Run(t *testing.T, maker Maker) {
	suite.Run(t, &keymanagerSuite{maker: maker})
}

type keymanagerSuite struct {
	suite.Suite

	maker Maker
	m     *keymanager.BuiltIn
}

func (s *keymanagerSuite) SetupTest() {
	s.m = keymanager.NewBuiltIn(s.maker(s.T()))
}

func (s *keymanagerSuite) TestGenerateKeyMissingKeyId() {
	// missing key id
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P256,
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *keymanagerSuite) TestGenerateKeyMissingKeyAlgorithm() {
	// missing key algorithm
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId: "KEY",
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *keymanagerSuite) TestGenerateKeyECDSAP256() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        "KEY",
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P256,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Algorithm, keymanager.KeyAlgorithm_ECDSA_P256)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(ecdsaPublicKey.Curve, elliptic.P256())
}

func (s *keymanagerSuite) TestGenerateKeyECDSAP384() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        "KEY",
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P384,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Algorithm, keymanager.KeyAlgorithm_ECDSA_P384)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(ecdsaPublicKey.Curve, elliptic.P384())
}

func (s *keymanagerSuite) TestGetPublicKeyMissingKeyId() {
	resp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *keymanagerSuite) TestGetPublicKeyNoKey() {
	resp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "KEY",
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Nil(resp.PublicKey)
}

func (s *keymanagerSuite) TestGetPublicKey() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        "KEY",
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P384,
	})
	s.Require().NoError(err)

	getResp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "KEY",
	})
	s.Require().NoError(err)
	s.Require().NotNil(getResp)
	s.Require().Equal(resp.PublicKey, getResp.PublicKey)

}

func (s *keymanagerSuite) TestGetPublicKeysNoKeys() {
	resp, err := s.m.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.PublicKeys)
}

func (s *keymanagerSuite) TestGetPublicKeys() {
	z, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        "Z",
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P384,
	})
	s.Require().NoError(err)

	a, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        "A",
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P384,
	})
	s.Require().NoError(err)

	resp, err := s.m.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal([]*keymanager.PublicKey{a.PublicKey, z.PublicKey}, resp.PublicKeys)

}

func (s *keymanagerSuite) TestSignData() {
	// create a new key
	generateResp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        "KEY",
		KeyAlgorithm: keymanager.KeyAlgorithm_ECDSA_P256,
	})
	s.Require().NoError(err)

	publicKey, err := x509.ParsePKIXPublicKey(generateResp.PublicKey.PkixData)
	s.Require().NoError(err)

	// self-sign a certificate with it
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(time.Minute),
	}

	// self sign the certificate using the keymanager as a signer
	cert, err := cryptoutil.CreateCertificate(ctx, s.m, template, template, "KEY", publicKey)
	s.Require().NoError(err)

	// verify the signature
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	s.Require().NoError(err)
}

func (s *keymanagerSuite) TestSignDataMissingKeyId() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		HashAlgorithm: keymanager.HashAlgorithm_SHA1,
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *keymanagerSuite) TestSignDataMissingHashAlgorithm() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: "KEY",
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *keymanagerSuite) TestSignDataNoKey() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		KeyId:         "KEY",
		HashAlgorithm: keymanager.HashAlgorithm_SHA1,
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}
