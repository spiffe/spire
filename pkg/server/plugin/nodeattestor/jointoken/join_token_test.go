package jointoken

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
)

const (
	config = `{"join_tokens":{"foo":600,"bar":1}, "trust_domain":"example.com"}`
)

var (
	ctx = context.Background()
)

type fakeAttestPluginStream struct {
	req  *nodeattestor.AttestRequest
	resp *nodeattestor.AttestResponse
}

func (f *fakeAttestPluginStream) Context() context.Context {
	return ctx
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

func AttestStreamGenerator(token string, attestedBefore bool) *fakeAttestPluginStream {
	return &fakeAttestPluginStream{
		req: &nodeattestor.AttestRequest{
			AttestationData: &common.AttestationData{
				Type: "join_token",
				Data: []byte(token),
			},
			AttestedBefore: attestedBefore,
		},
	}
}

func TestJoinToken_Configure(t *testing.T) {
	assert := assert.New(t)

	config := `{"join_tokens":{"bar":1}, "trust_domain":"example.com"}`
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	p := &JoinTokenPlugin{
		mtx: &sync.Mutex{},
	}
	resp, err := p.Configure(ctx, pluginConfig)
	assert.Nil(err)
	assert.Equal(&spi.ConfigureResponse{}, resp)
}

func TestJoinToken_Attest(t *testing.T) {
	assert := assert.New(t)

	config := `{"join_tokens":{"foo":600,"bar":60, "bat":1}, "trust_domain":"example.com"}`
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	p := &JoinTokenPlugin{
		mtx: &sync.Mutex{},
	}
	_, err := p.Configure(ctx, pluginConfig)
	assert.Nil(err)

	// Test valid token
	f := AttestStreamGenerator("foo", false)
	assert.NoError(p.Attest(f))
	assert.True(f.resp.Valid)

	// SPIFFE ID is well-formed
	assert.Equal(f.resp.BaseSPIFFEID, "spiffe://example.com/spiffe/node-id/foo")

	// Token is not re-usable
	// Token must be registered
	f = AttestStreamGenerator("foo", false)
	assert.NotNil(p.Attest(f))
	assert.Nil(f.resp)

	// Plugin doesn't support AttestedBefore
	f = AttestStreamGenerator("bar", true)
	assert.NotNil(p.Attest(f))
	assert.Nil(f.resp)

	// Token must not be expired
	// 1s ttl on `bat`
	time.Sleep(time.Second * 1)
	f = AttestStreamGenerator("bat", false)
	assert.NotNil(p.Attest(f))
	assert.Nil(f.resp)
}

func TestJoinToken_GetPluginInfo(t *testing.T) {
	var plugin JoinTokenPlugin
	data, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	assert.Nil(t, e)
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
}

func TestJoinToken_race(t *testing.T) {
	p := New()
	testutil.RaceTest(t, func(t *testing.T) {
		p.Configure(ctx, &spi.ConfigureRequest{
			Configuration: config,
		})
		p.Attest(AttestStreamGenerator("foo", false))
	})
}
