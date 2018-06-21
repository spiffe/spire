package gcp

import (
	"context"
	"fmt"
	"io"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	cgcp "github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/stretchr/testify/require"
)

type staticKeyRetriever struct {
	key string
}

func (s staticKeyRetriever) retrieveKey(token *jwt.Token) (interface{}, error) {
	if token.Header["kid"] == nil {
		return nil, fmt.Errorf("Missing kid in identityToken header. Cannot verify token")
	}
	return []byte(s.key), nil
}

func buildToken() *jwt.Token {
	computEngine := &cgcp.ComputeEngine{
		ProjectID:  "project-123",
		InstanceID: "instance-123",
	}

	google := &cgcp.Google{
		ComputeEngine: *computEngine,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"google": google,
		"aud":    audience,
	})
	token.Header["kid"] = "123"
	return token
}

func buildIITPlugin() *IITAttestorPlugin {
	return &IITAttestorPlugin{
		tokenKeyRetriever:  &staticKeyRetriever{key: "secret"},
		projectIDWhitelist: []string{"project-123"},
	}
}

func TestErrorOnInvalidToken(t *testing.T) {
	p := buildIITPlugin()
	_, err := doAttest(p, &nodeattestor.AttestRequest{})
	require.Error(t, err)
}

func TestErrorOnMissingKid(t *testing.T) {
	token := buildToken()
	token.Header["kid"] = nil
	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}

	p := buildIITPlugin()
	_, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data})
	require.Error(t, err)
}

func TestErrorOnInvalidClaims(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": 1,
	})
	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}

	p := buildIITPlugin()
	_, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data})
	require.Error(t, err)
}

func TestErrorOnInvalidAudience(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": "invalid",
	})
	token.Header["kid"] = "123"
	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}

	p := buildIITPlugin()
	_, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data})
	require.Error(t, err)
}

func TestErrorOnAttestedBefore(t *testing.T) {
	token := buildToken()
	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}

	p := buildIITPlugin()
	_, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data, AttestedBefore: true})
	require.Error(t, err)
}

func TestErrorOnProjectIdMismatch(t *testing.T) {
	token := buildToken()
	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}
	p := buildIITPlugin()
	p.projectIDWhitelist = []string{"invalid-id"}
	_, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data})
	require.Error(t, err)
}

func TestSuccesfullyProcessAttestationRequest(t *testing.T) {
	token := buildToken()
	tokenString, _ := token.SignedString([]byte("secret"))

	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}
	p := buildIITPlugin()
	res, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.True(t, res.Valid)
}

func TestErrorOnInvalidAlgorithm(t *testing.T) {
	token := buildToken()
	tokenString, _ := token.SignedString([]byte("secret"))
	data := &common.AttestationData{
		Type: pluginName,
		Data: []byte(tokenString),
	}
	p := buildIITPlugin()
	p.tokenKeyRetriever = &googlePublicKeyRetriever{}
	_, err := doAttest(p, &nodeattestor.AttestRequest{AttestationData: data})
	require.Error(t, err)
}

type fakeAttestPluginStream struct {
	req  *nodeattestor.AttestRequest
	resp *nodeattestor.AttestResponse
}

func (f *fakeAttestPluginStream) Context() context.Context {
	return context.Background()
}

func (f *fakeAttestPluginStream) Recv() (*nodeattestor.AttestRequest, error) {
	req := f.req
	f.req = nil
	if req == nil {
		return nil, io.EOF
	}
	return req, nil
}

func (f *fakeAttestPluginStream) Send(resp *nodeattestor.AttestResponse) error {
	if f.resp != nil {
		return io.EOF
	}
	f.resp = resp
	return nil
}

func doAttest(p nodeattestor.Plugin, req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	s := &fakeAttestPluginStream{req: req}
	if err := p.Attest(s); err != nil {
		return nil, err
	}
	return s.resp, nil
}
