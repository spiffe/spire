package azure

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/jwtutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/stretchr/testify/suite"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// Azure MSI tokens are RSA signed
	keyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAKC4t/KjGW7qAuK89ZQGasYlI1octSwElSGioJag1w7s/d2EXjtY
4FDYOYa8bKB3wC6rIzPDKUR783fZ3gJmvdI8TLlnj25wyPApVkRXC3ZQxYj5/hcG
aQuNWr6zrY8C8QIDAQABAmB95nViQtWHhxTfnPobDLPTp//7dQWPB7/y6zw1AqW0
8X0ka66Net+tNNRLcYr+YQ8Sv4suvGVo3NXBNU+jJVys2s+kB2vvfh5w/mpaEyM1
C3UGsX8WWcRvxkxQhwR5VmECMQDWAufI9k7mfo8kjPcFcxKZbwiklTn0p6IVNXIf
cA7f210xizyPm2NDUvs1v+f6Yw0CMQDAQT1zR4qlTm4tufG0+IlfPaP9FxvTl+ox
dxnOm4DzNx14+seX6Mont4ucrrFnNnUCMQC3u8zVGqnId3VbMu7MreuU8N+htUAJ
jHW58aWl2eXbSJCs/VYkEIra/P4ROk3mCG0CMQC3mpaRDXW/QRO/36CR7/lhV4DR
J8yPWrlx3AhtY9zWaYBgFT+gN9U38PYIAF2z8DECMHNJ/MNm0Keasv9K3sfrCpL6
bpR/VgtruOOSiOvJJ9xOAKCSsyeVpZdHrWlY7fkCKg==
-----END RSA PRIVATE KEY-----`)
)

const (
	resourceID = "https://example.org/app/"
)

func TestMSIAttestorPlugin(t *testing.T) {
	suite.Run(t, new(MSIAttestorSuite))
}

type MSIAttestorSuite struct {
	suite.Suite

	attestor *nodeattestor.BuiltIn
	key      *rsa.PrivateKey
	jwks     *jose.JSONWebKeySet
	now      time.Time
}

func (s *MSIAttestorSuite) SetupTest() {
	// load up the signer used for JWT signing
	var err error
	s.key, err = pemutil.ParseRSAPrivateKey(keyPEM)
	s.Require().NoError(err)
	s.jwks = new(jose.JSONWebKeySet)
	s.now = time.Now()

	s.attestor = s.newAttestor()
	s.configureAttestor()
}

func (s *MSIAttestorSuite) TestAttestFailsWhenNotConfigured() {
	resp, err := s.doAttestOnAttestor(s.newAttestor(), &nodeattestor.AttestRequest{})
	s.Require().EqualError(err, "azure-msi: not configured")
	s.Require().Nil(resp)
}

func (s *MSIAttestorSuite) TestAttestFailsWhenAttestedBefore() {
	s.requireAttestError(&nodeattestor.AttestRequest{AttestedBefore: true},
		"azure-msi: node has already attested")
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoAttestationData() {
	s.requireAttestError(&nodeattestor.AttestRequest{},
		"azure-msi: missing attestation data")
}

func (s *MSIAttestorSuite) TestAttestFailsWithWrongAttestationDataType() {
	s.requireAttestError(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "blah",
		},
	}, `azure-msi: unexpected attestation data type "blah"`)
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoAttestationDataPayload() {
	s.requireAttestError(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "azure_msi",
		},
	}, "azure-msi: missing attestation data payload")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedAttestationDataPayload() {
	s.requireAttestError(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "azure_msi",
			Data: []byte("{"),
		},
	}, "azure-msi: failed to unmarshal data payload")
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoToken() {
	s.requireAttestError(makeAttestRequest(""),
		"azure-msi: missing token from attestation data")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedToken() {
	s.requireAttestError(makeAttestRequest("blah"),
		"azure-msi: unable to parse token")
}

func (s *MSIAttestorSuite) TestAttestFailsIfTokenKeyIDMissing() {
	s.requireAttestError(s.signAttestRequest("", "", "", ""),
		"azure-msi: token missing key id")
}

func (s *MSIAttestorSuite) TestAttestFailsIfTokenKeyIDNotFound() {
	s.requireAttestError(s.signAttestRequest("KEYID", "", "", ""),
		`azure-msi: key id "KEYID" not found`)
}

func (s *MSIAttestorSuite) TestAttestFailsWithBadSignature() {
	s.addKey("KEYID")

	// sign a token and replace the signature
	token := s.signToken("KEYID", "", "", "")
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3)
	parts[2] = "aaaa"
	token = strings.Join(parts, ".")

	s.requireAttestError(makeAttestRequest(token),
		"unable to verify token")
}

func (s *MSIAttestorSuite) TestAttestFailsWithAlgorithmMismatch() {
	s.addKey("KEYID")

	// sign a token with a different key algorithm than that of the key in
	// the key set.
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte("0123456789ABCDEF"),
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "KEYID",
		},
	})
	token, err := jwt.Signed(signer).CompactSerialize()
	s.Require().NoError(err)

	s.requireAttestError(makeAttestRequest(token),
		"unable to verify token")
}

func (s *MSIAttestorSuite) TestAttestFailsClaimValidation() {
	s.addKey("KEYID")

	// missing tenant id claim
	s.requireAttestError(s.signAttestRequest("KEYID", resourceID, "", "PRINCIPALID"),
		"token missing tenant ID claim")

	// unauthorized tenant id claim
	s.requireAttestError(s.signAttestRequest("KEYID", resourceID, "BADTENANTID", "PRINCIPALID"),
		`tenant "BADTENANTID" is not authorized`)

	// no audience
	s.requireAttestError(s.signAttestRequest("KEYID", "", "TENANTID", "PRINCIPALID"),
		"invalid audience claim")

	// wrong audience
	s.requireAttestError(s.signAttestRequest("KEYID", "FOO", "TENANTID", "PRINCIPALID"),
		"invalid audience claim")

	// missing principal id (sub) claim
	s.requireAttestError(s.signAttestRequest("KEYID", resourceID, "TENANTID", ""),
		"token missing subject claim")
}

func (s *MSIAttestorSuite) TestAttestTokenExpiration() {
	s.addKey("KEYID")
	token := s.signAttestRequest("KEYID", resourceID, "TENANTID", "PRINCIPALID")

	// within 5m leeway (token expires at 1m + 5m leeway = 6m)
	s.adjustTime(6 * time.Minute)
	_, err := s.doAttest(token)
	s.Require().NotNil(err)

	// just after 5m leeway
	s.adjustTime(time.Second)
	s.requireAttestError(token, "token is expired")
}

func (s *MSIAttestorSuite) TestAttestSuccess() {
	s.addKey("KEYID")

	// Success against TENANTID, which uses the custom resource ID
	resp, err := s.doAttest(s.signAttestRequest("KEYID", resourceID, "TENANTID", "PRINCIPALID"))
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().True(resp.Valid)
	s.Require().Equal(resp.BaseSPIFFEID, "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID")
	s.Require().Nil(resp.Challenge)

	// Success against TENANTID2, which uses the default resource ID
	resp, err = s.doAttest(s.signAttestRequest("KEYID", azure.DefaultMSIResourceID, "TENANTID2", "PRINCIPALID"))
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().True(resp.Valid)
	s.Require().Equal(resp.BaseSPIFFEID, "spiffe://example.org/spire/agent/azure_msi/TENANTID2/PRINCIPALID")
	s.Require().Nil(resp.Challenge)
}

func (s *MSIAttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
	})
	s.requireErrorContains(err, "azure-msi: unable to decode configuration")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.Require().EqualError(err, "azure-msi: configuration missing trust domain")
	s.Require().Nil(resp)

	// missing tenants
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `trust_domain = "example.org"`,
	})
	s.Require().EqualError(err, "azure-msi: configuration must have at least one tenant")
	s.Require().Nil(resp)

	// success
	s.configureAttestor()
}

func (s *MSIAttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *MSIAttestorSuite) adjustTime(d time.Duration) {
	s.now = s.now.Add(d)
}

func (s *MSIAttestorSuite) newSigner(keyID string) jose.Signer {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:   s.key,
			KeyID: keyID,
		},
	}, nil)
	s.Require().NoError(err)
	return signer
}

func (s *MSIAttestorSuite) signToken(keyID, audience, tenantID, principalID string) string {
	builder := jwt.Signed(s.newSigner(keyID))

	// build up standard claims
	claims := jwt.Claims{
		Subject:   principalID,
		NotBefore: jwt.NewNumericDate(s.now),
		Expiry:    jwt.NewNumericDate(s.now.Add(time.Minute)),
	}
	if audience != "" {
		claims.Audience = []string{audience}
	}
	builder = builder.Claims(claims)

	// add the tenant id claim
	if tenantID != "" {
		builder = builder.Claims(map[string]interface{}{
			"tid": tenantID,
		})
	}

	token, err := builder.CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *MSIAttestorSuite) signAttestRequest(keyID, audience, tenantID, principalID string) *nodeattestor.AttestRequest {
	return makeAttestRequest(s.signToken(keyID, audience, tenantID, principalID))
}

func (s *MSIAttestorSuite) addKey(keyID string) {
	s.jwks.Keys = append(s.jwks.Keys, jose.JSONWebKey{
		Key:   s.key.Public(),
		KeyID: keyID,
	})
}

func (s *MSIAttestorSuite) newAttestor() *nodeattestor.BuiltIn {
	attestor := NewMSIAttestorPlugin()
	attestor.hooks.now = func() time.Time {
		return s.now
	}
	attestor.hooks.keySetProvider = jwtutil.KeySetProviderFunc(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
		return s.jwks, nil
	})
	return nodeattestor.NewBuiltIn(attestor)
}

func (s *MSIAttestorSuite) configureAttestor() {
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		trust_domain = "example.org"
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
			"TENANTID2" = {}
		}
		`,
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *MSIAttestorSuite) doAttest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	return s.doAttestOnAttestor(s.attestor, req)
}

func (s *MSIAttestorSuite) doAttestOnAttestor(attestor *nodeattestor.BuiltIn, req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	stream, err := attestor.Attest(context.Background())
	s.Require().NoError(err)

	err = stream.Send(req)
	s.Require().NoError(err)

	err = stream.CloseSend()
	s.Require().NoError(err)

	return stream.Recv()
}

func (s *MSIAttestorSuite) requireAttestError(req *nodeattestor.AttestRequest, contains string) {
	resp, err := s.doAttest(req)
	s.requireErrorContains(err, contains)
	s.Require().Nil(resp)
}

func (s *MSIAttestorSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}

func makeAttestRequest(token string) *nodeattestor.AttestRequest {
	return &nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "azure_msi",
			Data: []byte(fmt.Sprintf(`{"token": %q}`, token)),
		},
	}
}
