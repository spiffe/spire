package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/spiffe/spire/test/spiretest"
)

var (
	ctx = context.Background()
)

type Maker func(t *testing.T) catalog.Plugin

// the maker function is called. the returned key manager is expected to be
// already configured.
func Run(t *testing.T, maker Maker) {
	spiretest.Run(t, &baseSuite{maker: maker})
}

type baseSuite struct {
	spiretest.Suite

	maker Maker
	m     keymanager.Plugin
}

func (s *baseSuite) SetupTest() {
	s.LoadPlugin(s.maker(s.T()), &s.m)
}

func (s *baseSuite) TestGenerateKeyMissingKeyId() {
	// missing key id
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *baseSuite) TestGenerateKeyMissingKeyType() {
	// missing key type
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId: "KEY",
	})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *baseSuite) TestGenerateKeyECP256() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P256,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Type, keymanager.KeyType_EC_P256)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(elliptic.P256(), ecdsaPublicKey.Curve)
}

func (s *baseSuite) TestGenerateKeyECP384() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P384,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Type, keymanager.KeyType_EC_P384)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(elliptic.P384(), ecdsaPublicKey.Curve)
}

func (s *baseSuite) TestGenerateKeyRSA1024() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_RSA_1024,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Type, keymanager.KeyType_RSA_1024)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(1024, rsaPublicKey.N.BitLen())
}

func (s *baseSuite) TestGenerateKeyRSA2048() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_RSA_2048,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Type, keymanager.KeyType_RSA_2048)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(2048, rsaPublicKey.N.BitLen())
}

func (s *baseSuite) TestGenerateKeyRSA4096() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_RSA_4096,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.PublicKey)
	s.Require().Equal(resp.PublicKey.Id, "KEY")
	s.Require().Equal(resp.PublicKey.Type, keymanager.KeyType_RSA_4096)
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	s.Require().NoError(err)
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	s.Require().True(ok)
	s.Require().Equal(4096, rsaPublicKey.N.BitLen())
}

func (s *baseSuite) TestGetPublicKeyMissingKeyId() {
	resp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{})
	s.Require().Error(err)
	s.Require().Nil(resp)
}

func (s *baseSuite) TestGetPublicKeyNoKey() {
	resp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "KEY",
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Nil(resp.PublicKey)
}

func (s *baseSuite) TestGetPublicKey() {
	resp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keymanager.KeyType_EC_P384,
	})
	s.Require().NoError(err)

	getResp, err := s.m.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "KEY",
	})
	s.Require().NoError(err)
	s.Require().NotNil(getResp)
	s.Require().Equal(resp.PublicKey, getResp.PublicKey)

}

func (s *baseSuite) TestGetPublicKeysNoKeys() {
	resp, err := s.m.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.PublicKeys)
}

func (s *baseSuite) TestGetPublicKeys() {
	z, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "Z",
		KeyType: keymanager.KeyType_EC_P384,
	})
	s.Require().NoError(err)

	a, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "A",
		KeyType: keymanager.KeyType_EC_P384,
	})
	s.Require().NoError(err)

	resp, err := s.m.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal([]*keymanager.PublicKey{a.PublicKey, z.PublicKey}, resp.PublicKeys)
}

func (s *baseSuite) TestSignDataECDSA() {
	s.testSignData(keymanager.KeyType_EC_P256, x509.ECDSAWithSHA256)
}

func (s *baseSuite) TestSignDataRSAPKCS1v15() {
	s.testSignData(keymanager.KeyType_RSA_1024, x509.SHA256WithRSA)
}

func (s *baseSuite) TestSignDataRSAPSS() {
	s.testSignData(keymanager.KeyType_RSA_1024, x509.SHA256WithRSAPSS)
}

func (s *baseSuite) testSignData(keyType keymanager.KeyType, signatureAlgorithm x509.SignatureAlgorithm) {
	// create a new key
	generateResp, err := s.m.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   "KEY",
		KeyType: keyType,
	})
	s.Require().NoError(err)

	publicKey, err := x509.ParsePKIXPublicKey(generateResp.PublicKey.PkixData)
	s.Require().NoError(err)

	// self-sign a certificate with it
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		NotAfter:           time.Now().Add(time.Minute),
		SignatureAlgorithm: signatureAlgorithm,
	}

	// self sign the certificate using the keymanager as a signer
	cert, err := x509util.CreateCertificate(ctx, s.m, template, template, "KEY", publicKey)
	s.Require().NoError(err)

	// verify the signature
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	s.Require().NoError(err)
}

func (s *baseSuite) TestSignDataMissingKeyId() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})
	s.requireErrorContains(err, "key id is required")
	s.Require().Nil(resp)
}

func (s *baseSuite) TestSignDataMissingSignerOpts() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: "KEY",
	})
	s.requireErrorContains(err, "signer opts is required")
	s.Require().Nil(resp)
}

func (s *baseSuite) TestSignDataMissingHashAlgorithm() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		KeyId:      "KEY",
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{},
	})
	s.requireErrorContains(err, "hash algorithm is required")
	s.Require().Nil(resp)
}

func (s *baseSuite) TestSignDataNoKey() {
	resp, err := s.m.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: "KEY",
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})
	s.requireErrorContains(err, `no such key "KEY"`)
	s.Require().Nil(resp)
}

func (s *baseSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}
