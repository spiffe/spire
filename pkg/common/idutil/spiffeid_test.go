package idutil

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

var td = spiffeid.RequireTrustDomainFromString("domain.test")

func TestMemberFromString(t *testing.T) {
	t.Run("is member", func(t *testing.T) {
		id, err := MemberFromString(td, "spiffe://domain.test/foo")
		assert.NoError(t, err)
		assert.Equal(t, "spiffe://domain.test/foo", id.String())
	})
	t.Run("is not a member", func(t *testing.T) {
		_, err := MemberFromString(td, "spiffe://otherdomain.test/foo")
		assert.EqualError(t, err, `SPIFFE ID "spiffe://otherdomain.test/foo" is not a member of trust domain "domain.test"`)
	})
	t.Run("empty trust domain", func(t *testing.T) {
		_, err := MemberFromString(spiffeid.TrustDomain{}, "spiffe://domain.test/foo")
		assert.EqualError(t, err, `SPIFFE ID "spiffe://domain.test/foo" is not a member of trust domain ""`)
	})
	t.Run("invalid id", func(t *testing.T) {
		_, err := MemberFromString(td, "spiffe:///foo")
		assert.EqualError(t, err, "trust domain is missing")
	})
}

func TestIsAgentPath(t *testing.T) {
	assert.False(t, IsAgentPath(""))
	assert.False(t, IsAgentPath("/not/an/agent/path"))
	assert.True(t, IsAgentPath("/spire/agent/join_token/d3f678b4-d41d-4b1c-a971-73e012729b43"))
}

func TestIsReservedPath(t *testing.T) {
	assert.False(t, IsReservedPath(""))
	assert.False(t, IsReservedPath("/not/an/agent/path"))
	assert.True(t, IsReservedPath("/spire/agent/join_token/d3f678b4-d41d-4b1c-a971-73e012729b43"))
	assert.True(t, IsReservedPath("/spire/foo"))
}

func TestAgentID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		id, err := AgentID(td, "/suffix")
		assert.NoError(t, err)
		assert.Equal(t, "spiffe://domain.test/spire/agent/suffix", id.String())
	})
	t.Run("trust domain is empty", func(t *testing.T) {
		_, err := AgentID(spiffeid.TrustDomain{}, "/suffix")
		assert.EqualError(t, err, `cannot create agent ID with suffix "/suffix" for empty trust domain`)
	})
	t.Run("suffix is not valid absolute path", func(t *testing.T) {
		_, err := AgentID(td, "suffix")
		assert.EqualError(t, err, `invalid agent path suffix "suffix": path must have a leading slash`)
	})
}

func TestServerID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		id, err := ServerID(td)
		assert.NoError(t, err)
		assert.Equal(t, "spiffe://domain.test/spire/server", id.String())
	})
	t.Run("trust domain is empty", func(t *testing.T) {
		_, err := ServerID(spiffeid.TrustDomain{})
		assert.EqualError(t, err, "cannot create server ID for empty trust domain")
	})
}
