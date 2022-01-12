package idutil

import (
	"net/url"
	"strings"
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIDURLNormalization(t *testing.T) {
	assertGood := func(id string) {
		u, err := url.Parse(id)
		require.NoError(t, err)
		assert.NoError(t, CheckIDURLNormalization(u), "%s should have passed", id)
	}
	assertBad := func(id string, expectedErr string) {
		u, err := url.Parse(id)
		if err != nil {
			assert.EqualError(t, err, expectedErr, "parsing %s should have failed", id)
			return
		}
		assert.EqualError(t, CheckIDURLNormalization(u), expectedErr, "%s should have failed", id)
	}

	testCommonCheckIDNormalization(assertGood, assertBad)

	// Assert the scheme is spiffe
	assertBad("sparfe://example.org/workload",
		"scheme is missing or invalid")
}

func TestCheckIDStringNormalization(t *testing.T) {
	assertGood := func(id string) {
		assert.NoError(t, CheckIDStringNormalization(id), "%s should have passed", id)
	}
	assertBad := func(id string, expectedErr string) {
		assert.EqualError(t, CheckIDStringNormalization(id), expectedErr, "%s should have failed", id)
	}

	// Test the common normalization cases
	testCommonCheckIDNormalization(assertGood, assertBad)

	// Ensure we don't allow percent-encoded ASCII in the hostname. We can't
	// test this case everywhere, since it is disallowed by the url.Parse
	// function but we can at least test it here to make sure our go-spiffe
	// dependency works.
	assertBad("spiffe://%45example.org/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
	// Ensure we don't allow malformed percent encoding. Can't test this
	// everywhere since it is rejected by the url.Parse function.
	assertBad("spiffe://example.org/%2z",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")

	// Assert the scheme is spiffe
	assertBad("sparfe://example.org/workload",
		"scheme is missing or invalid")
	assertBad("sPiFfE://example.org/workload",
		"scheme is missing or invalid")
}

func TestCheckIDProtoNormalization(t *testing.T) {
	protoFromString := func(t *testing.T, id string) *types.SPIFFEID {
		// Rough parsing. We know the shape of the incoming ID's so this is
		// ok. We don't want to use url.Parse() here because it will trip
		// up some of the tests.
		schemeIndex := strings.Index(id, "://")
		require.GreaterOrEqual(t, schemeIndex, 0)
		rest := id[schemeIndex+3:]
		pathIndex := strings.IndexByte(rest, '/')

		out := &types.SPIFFEID{TrustDomain: rest}
		if pathIndex >= 0 {
			out.TrustDomain = rest[:pathIndex]
			out.Path = rest[pathIndex:]
		}
		return out
	}
	assertGood := func(id string) {
		assert.NoError(t, CheckIDProtoNormalization(protoFromString(t, id)), "%s should have passed", id)
	}
	assertBad := func(id string, expectedErr string) {
		assert.EqualError(t, CheckIDProtoNormalization(protoFromString(t, id)), expectedErr, "%s should have failed", id)
	}

	// Since the ID proto doesn't include the scheme, the following
	// test is irrelevant but is included here for parity with the other
	// Check* tests.
	assertGood("sparfe://example.org/workload")

	// Assert that the path is auto-prefixed with "/" when considering
	// normalization
	assert.EqualError(t, CheckIDProtoNormalization(&types.SPIFFEID{
		TrustDomain: "example.org",
		Path:        "workload",
	}), "path must have a leading slash")

	// Test the common normalization cases
	testCommonCheckIDNormalization(assertGood, assertBad)
}

func TestCheckAgentIDStringNormalization(t *testing.T) {
	assertGood := func(id string) {
		assert.NoError(t, CheckAgentIDStringNormalization(id), "%s should have passed", id)
	}
	assertBad := func(id string, expectedErr string) {
		assert.EqualError(t, CheckAgentIDStringNormalization(id), expectedErr, "%s should have failed", id)
	}

	// Test the common normalization cases
	testCommonCheckIDNormalization(assertGood, assertBad)

	// Assert the scheme is spiffe
	assertBad("sparfe://example.org/workload",
		"scheme is missing or invalid")
	assertBad("sPiFfE://example.org/workload",
		"scheme is missing or invalid")

	// Agent ID cannot be the server ID
	assertBad("spiffe://example.org/spire/server",
		"server ID is not allowed for agents")
}

func testCommonCheckIDNormalization(assertGood func(string), assertBad func(string, string)) {
	assertGood("spiffe://example.org")
	assertGood("spiffe://example.org/workload")
	assertGood("spiffe://abcdefghijklmnopqrstuvwxyz0123456789.-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")

	assertBad("spiffe://example.org/世界/%E4%B8%96%E7%95%8C",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/",
		"path cannot have a trailing slash")
	assertBad("spiffe://example.org/workload/",
		"path cannot have a trailing slash")
	assertBad("spiffe://eXaMplE.org/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org//workload",
		"path cannot contain empty segments")
	assertBad("spiffe://example.org///workload",
		"path cannot contain empty segments")
	assertBad("spiffe://example.org/./workload",
		"path cannot contain dot segments")
	assertBad("spiffe://example.org/workload/../workload2",
		"path cannot contain dot segments")
	assertBad("spiffe://example.org/workload/%2e%2e/workload2",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%252e",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%23",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%00",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/"+url.PathEscape("%E4%B8%96%E7%95%8C"),
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%E4%B8%96%E7%95%8C",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://世界/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/世界",
		"path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://%E4%B8%96%E7%95%8C/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
}

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
