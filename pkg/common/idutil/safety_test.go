package idutil

import (
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/assert"
)

func TestIDProtoString(t *testing.T) {
	assert := assert.New(t)

	id, err := IDProtoString(&types.SPIFFEID{})
	assert.EqualError(err, "trust domain is missing")
	assert.Empty(id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org", id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/"})
	assert.EqualError(err, "path cannot have a trailing slash")
	assert.Empty(id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org", Path: "workload"})
	assert.EqualError(err, "path must have a leading slash")
	assert.Empty(id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload", id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload/foo"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload/foo", id)
}

func TestIDProtoFromString(t *testing.T) {
	assert := assert.New(t)

	id, err := IDProtoFromString("other://whocares")
	assert.EqualError(err, "scheme is missing or invalid")
	assert.Nil(id)

	id, err = IDProtoFromString("spiffe://")
	assert.EqualError(err, "trust domain is missing")
	assert.Nil(id)

	id, err = IDProtoFromString("spiffe://example.org")
	assert.NoError(err)
	assert.Equal(&types.SPIFFEID{TrustDomain: "example.org"}, id)

	id, err = IDProtoFromString("spiffe://example.org/")
	assert.EqualError(err, "path cannot have a trailing slash")
	assert.Nil(id)

	id, err = IDProtoFromString("spiffe://example.org/workload")
	assert.NoError(err)
	assert.Equal(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"}, id)

	id, err = IDProtoFromString("spiffe://example.org/workload/foo")
	assert.NoError(err)
	assert.Equal(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload/foo"}, id)
}

func TestIDFromProto(t *testing.T) {
	assert := assert.New(t)

	id, err := IDFromProto(&types.SPIFFEID{})
	assert.EqualError(err, "trust domain is missing")
	assert.Empty(id)

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org", id.String())

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/"})
	assert.EqualError(err, "path cannot have a trailing slash")
	assert.Empty(id)

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "workload"})
	assert.EqualError(err, "path must have a leading slash")
	assert.Empty(id)

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload", id.String())

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload/%41%42%43"})
	assert.EqualError(err, "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assert.Empty(id)
}
