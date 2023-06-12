package idutil

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/assert"
)

func TestRequireIDProtoString(t *testing.T) {
	assert.NotPanics(t, func() {
		id := RequireIDProtoString(&types.SPIFFEID{
			TrustDomain: td.Name(),
			Path:        "/path",
		})
		assert.Equal(t, "spiffe://domain.test/path", id)
	})

	assert.Panics(t, func() {
		RequireIDProtoString(&types.SPIFFEID{})
	})
}

func TestRequireIDFromProto(t *testing.T) {
	assert.NotPanics(t, func() {
		id := RequireIDFromProto(&types.SPIFFEID{
			TrustDomain: td.Name(),
			Path:        "/path",
		})
		assert.Equal(t, "spiffe://domain.test/path", id.String())
	})

	assert.Panics(t, func() {
		RequireIDFromProto(&types.SPIFFEID{})
	})
}

func TestRequireServerID(t *testing.T) {
	assert.NotPanics(t, func() {
		id := RequireServerID(td)
		assert.Equal(t, "spiffe://domain.test/spire/server", id.String())
	})

	assert.Panics(t, func() {
		RequireServerID(spiffeid.TrustDomain{})
	})
}

func TestRequireAgentID(t *testing.T) {
	assert.NotPanics(t, func() {
		id := RequireAgentID(td, "/foo")
		assert.Equal(t, "spiffe://domain.test/spire/agent/foo", id.String())
	})

	assert.Panics(t, func() {
		RequireAgentID(td, "foo")
	})
}
