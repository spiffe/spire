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
	for _, tt := range []struct {
		name      string
		proto     *types.SPIFFEID
		expected  string
		expectErr string
	}{
		{
			name:      "empty proto",
			proto:     &types.SPIFFEID{},
			expectErr: "trust domain is missing",
		},
		{
			name:     "valid trust domain",
			proto:    &types.SPIFFEID{TrustDomain: "example.org"},
			expected: "spiffe://example.org",
		},
		{
			name:     "valid trust domain and path",
			proto:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
			expected: "spiffe://example.org/workload",
		},
		{
			name:      "trailing slash in path",
			proto:     &types.SPIFFEID{TrustDomain: "example.org", Path: "/"},
			expectErr: "path cannot have a trailing slash",
		},
		{
			name:      "missing leading slash in path",
			proto:     &types.SPIFFEID{TrustDomain: "example.org", Path: "workload"},
			expectErr: "path must have a leading slash",
		},
		{
			name:      "invalid characters in path",
			proto:     &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload/%41%42%43"},
			expectErr: "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
		},
		{
			name:      "invalid characters in trust domain",
			proto:     &types.SPIFFEID{TrustDomain: "example.org/path"},
			expectErr: "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
		},
		{
			name:      "trust domain with space",
			proto:     &types.SPIFFEID{TrustDomain: "example .org"},
			expectErr: "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			id, err := IDFromProto(tt.proto)
			if tt.expectErr != "" {
				assert.EqualError(err, tt.expectErr)
				assert.Empty(id)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.expected, id.String())
		})
	}
}
