package jointoken

import (
	"context"
	"io"
	"testing"

	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
)

const (
	goodConfig  = `{"join_token":"foobar"}`
	badConfig   = `{}`
	trustDomain = "example.com"

	token    = "foobar"
	spiffeId = "spiffe://example.com/spire/agent/join_token/foobar"
)

var (
	ctx = context.Background()
)

type fakeFetchAttestationDataStream struct {
	req  *nodeattestor.FetchAttestationDataRequest
	resp *nodeattestor.FetchAttestationDataResponse
}

func newFakeFetchAttestationStream() *fakeFetchAttestationDataStream {
	return &fakeFetchAttestationDataStream{
		req: new(nodeattestor.FetchAttestationDataRequest),
	}
}

func (f *fakeFetchAttestationDataStream) Context() context.Context {
	return ctx
}

func (f *fakeFetchAttestationDataStream) Recv() (*nodeattestor.FetchAttestationDataRequest, error) {
	req := f.req
	f.req = nil
	if req == nil {
		return nil, io.EOF
	}
	return req, nil
}

func (f *fakeFetchAttestationDataStream) Send(resp *nodeattestor.FetchAttestationDataResponse) error {
	if f.resp != nil {
		return io.EOF
	}
	f.resp = resp
	return nil
}

func PluginGenerator(config string, trustDomain string) (nodeattestor.Plugin, *spi.ConfigureResponse, error) {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: trustDomain},
	}

	p := New()
	r, err := p.Configure(ctx, pluginConfig)
	return p, r, err
}

func TestJoinToken_Configure(t *testing.T) {
	assert := assert.New(t)
	_, r, err := PluginGenerator(goodConfig, trustDomain)
	assert.Nil(err)
	assert.Equal(&spi.ConfigureResponse{}, r)

	// Global configuration no provided
	_, r, err = PluginGenerator(goodConfig, "")
	assert.Error(err, "trust_domain is required")
	assert.Equal(1, len(r.ErrorList))
	assert.Equal(err.Error(), r.ErrorList[0])

	// Trust domain no provided
}

func TestJoinToken_FetchAttestationData_TokenPresent(t *testing.T) {
	assert := assert.New(t)

	// Build expected response
	attestationData := &common.AttestationData{
		Type: "join_token",
		Data: []byte(token),
	}
	expectedResp := &nodeattestor.FetchAttestationDataResponse{
		AttestationData: attestationData,
		SpiffeId:        spiffeId,
	}

	p, _, err := PluginGenerator(goodConfig, trustDomain)
	assert.Nil(err)

	stream := newFakeFetchAttestationStream()
	assert.NoError(p.FetchAttestationData(stream))
	assert.Nil(err)
	assert.Equal(expectedResp, stream.resp)
}

func TestJoinToken_FetchAttestationData_TokenNotPresent(t *testing.T) {
	assert := assert.New(t)
	p, _, err := PluginGenerator(badConfig, trustDomain)
	assert.Nil(err)

	stream := newFakeFetchAttestationStream()
	assert.NotNil(p.FetchAttestationData(stream))
}

func TestJoinToken_GetPluginInfo(t *testing.T) {
	plugin := New()
	data, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	assert.Nil(t, e)
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
}

func TestJoinToken_race(t *testing.T) {
	p := New()
	testutil.RaceTest(t, func(t *testing.T) {
		p.Configure(ctx, &spi.ConfigureRequest{
			Configuration: goodConfig,
		})
		stream := newFakeFetchAttestationStream()
		p.FetchAttestationData(stream)
	})
}
