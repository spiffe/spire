package gcp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/stretchr/testify/suite"
)

const (
	testRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBzAIBAAJhAMnVzWSZn20CtcFaWh1Uuoh7NObRt9z84h8zzuIVSNkeJV6Dei0v
8FGp3ZilrU3MDM6WsuFTUVo21qBTOTnYKuEI0bk7pTgZk9CN6aF0iZbzyrvsU6hy
b09dN0PFBc5A2QIDAQABAmEAqSpioQvFPKfF0M46s1S9lwC1ATULRtRJbd+NaZ5v
VVLX/VRzRYZlhPy7d2J9U7ROFjSM+Fng8S1knrHAK0ka/ZfYOl1ZLoMexpBovebM
mGcsCHrHz4eBN8B1Y+8JRhkBAjEA7fTLjbz3M7za1nGODqWsoBv33yJHGh9GIaf9
umpx3qpFZCVsqHgCvmalAu+IXAz5AjEA2SPTRcddrGVsDnSOYot3eCArVOIxgI+r
H9A4cjS4cp4W4nBZhb+08/IYtDfYdirhAjAtl8LMtJE045GWlwld+xZ5UwKKSVoQ
Qj/AwRxXdH++5ycGijkoil4UNzyUtGqPIJkCMQC5g9ola8ekWqKPVxWvK+jOQO3E
f9w7MoPJkmQnbtOHWXnDzKkvlDJNmTFyB6RwkQECMQDp+GR2I305amG9isTzm7UU
8pJxbXLymDwR4A7x5vwH6x2gLBgpat21QAR14W4dYEg=
-----END RSA PRIVATE KEY-----`
)

type staticKeyRetriever struct {
	key *rsa.PublicKey
}

func (s staticKeyRetriever) retrieveKey(token *jwt.Token) (interface{}, error) {
	if token.Header["kid"] == nil {
		return nil, newError("identity token missing kid header")
	}
	return s.key, nil
}

func buildClaims(projectID string, audience string) jwt.MapClaims {
	return jwt.MapClaims{
		"google": &gcp.Google{
			ComputeEngine: gcp.ComputeEngine{
				ProjectID:  projectID,
				InstanceID: "instance-123",
			},
		},
		"aud": audience,
	}
}

func buildDefaultClaims() jwt.MapClaims {
	return buildClaims("project-123", tokenAudience)
}

func buildToken() *jwt.Token {
	return buildTokenWithClaims(buildDefaultClaims())
}

func buildTokenWithClaims(claims jwt.Claims) *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "123"
	return token
}

func TestIITAttestorPlugin(t *testing.T) {
	suite.Run(t, new(IITAttestorSuite))
}

type IITAttestorSuite struct {
	suite.Suite

	p      *nodeattestor.BuiltIn
	rsaKey *rsa.PrivateKey
}

func (s *IITAttestorSuite) SetupTest() {
	pemBlock, _ := pem.Decode([]byte(testRSAKey))
	s.Require().NotNil(pemBlock)
	rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	s.Require().NoError(err)
	s.rsaKey = rsaKey

	p := NewIITAttestorPlugin()
	p.tokenKeyRetriever = &staticKeyRetriever{key: &rsaKey.PublicKey}
	s.p = nodeattestor.NewBuiltIn(p)

	_, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
trust_domain = "example.org"
projectid_whitelist = ["project-123"]
`,
	})
	s.Require().NoError(err)
}

func (s *IITAttestorSuite) TestErrorWhenNotConfigured() {
	p := nodeattestor.NewBuiltIn(NewIITAttestorPlugin())
	stream, err := p.Attest(context.Background())
	defer stream.CloseSend()
	resp, err := stream.Recv()
	s.requireErrorContains(err, "gcp-iit: not configured")
	s.Require().Nil(resp)
}

func (s *IITAttestorSuite) TestErrorOnInvalidToken() {
	_, err := s.attest(&nodeattestor.AttestRequest{})
	s.requireErrorContains(err, "gcp-iit: request missing attestation data")
}

func (s *IITAttestorSuite) TestErrorOnInvalidType() {
	_, err := s.attest(&nodeattestor.AttestRequest{
		AttestationData: &nodeattestor.AttestationData{
			Type: "foo",
		},
	})
	s.requireErrorContains(err, `gcp-iit: unexpected attestation data type "foo"`)
}

func (s *IITAttestorSuite) TestErrorOnMissingKid() {
	token := buildToken()
	token.Header["kid"] = nil

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: s.signToken(token),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.requireErrorContains(err, "gcp-iit: identity token missing kid header")
}

func (s *IITAttestorSuite) TestErrorOnInvalidClaims() {
	claims := buildDefaultClaims()
	claims["exp"] = 1
	token := buildTokenWithClaims(claims)

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: s.signToken(token),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.requireErrorContains(err, "gcp-iit: unable to parse/validate the identity token: token is expired")
}

func (s *IITAttestorSuite) TestErrorOnInvalidAudience() {
	claims := buildClaims("project-123", "invalid")
	token := buildTokenWithClaims(claims)

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: s.signToken(token),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.requireErrorContains(err, `gcp-iit: unexpected identity token audience "invalid"`)
}

func (s *IITAttestorSuite) TestErrorOnAttestedBefore() {
	token := buildToken()

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: s.signToken(token),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data, AttestedBefore: true})
	s.requireErrorContains(err, "gcp-iit: instance ID has already been attested")
}

func (s *IITAttestorSuite) TestErrorOnProjectIdMismatch() {
	claims := buildClaims("project-whatever", tokenAudience)
	token := buildTokenWithClaims(claims)

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: s.signToken(token),
	}
	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.requireErrorContains(err, `gcp-iit: identity token project ID "project-whatever" is not in the whitelist`)
}

func (s *IITAttestorSuite) TestSuccesfullyProcessAttestationRequest() {
	token := buildToken()

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: s.signToken(token),
	}
	res, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.Require().NoError(err)
	s.Require().NotNil(res)
	s.Require().True(res.Valid)
}

func (s *IITAttestorSuite) TestErrorOnInvalidAlgorithm() {
	token := buildToken()

	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: []byte(tokenString),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.requireErrorContains(err, "gcp-iit: unable to parse/validate the identity token: token contains an invalid number of segments")
}

func (s *IITAttestorSuite) TestConfigure() {
	require := s.Require()

	// malformed
	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `trust_domain`,
	})
	s.requireErrorContains(err, "gcp-iit: unable to decode configuration")
	require.Nil(resp)

	// missing trust domain
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
projectid_whitelist = ["bar"]
`})
	s.requireErrorContains(err, "gcp-iit: trust_domain is required")
	require.Nil(resp)

	// missing projectID whitelist
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
trust_domain = "foo"
`})
	s.requireErrorContains(err, "gcp-iit: projectid_whitelist is required")
	require.Nil(resp)

	// success
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
trust_domain = "example.org"
projectid_whitelist = ["bar"]
`})
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(resp, &plugin.ConfigureResponse{})
}

func (s *IITAttestorSuite) TestGetPluginInfo() {
	require := s.Require()
	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *IITAttestorSuite) attest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	stream, err := s.p.Attest(context.Background())
	defer stream.CloseSend()
	s.Require().NoError(err)
	err = stream.Send(req)
	s.Require().NoError(err)
	return stream.Recv()
}

func (s *IITAttestorSuite) signToken(token *jwt.Token) []byte {
	signedToken, err := token.SignedString(s.rsaKey)
	s.Require().NoError(err)
	return []byte(signedToken)
}

func (s *IITAttestorSuite) requireErrorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}
