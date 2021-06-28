package idutil

import (
	"net/url"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
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
		"scheme must be 'spiffe'")

	SetAllowUnsafeIDs(true)
	defer SetAllowUnsafeIDs(false)

	assertGood("sparfe://example.org/workload")
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

	// Assert the scheme is spiffe
	assertBad("sparfe://example.org/workload",
		"scheme must be 'spiffe'")
	assertBad("sPiFfE://example.org/workload",
		"scheme must be 'spiffe'")

	SetAllowUnsafeIDs(true)
	defer SetAllowUnsafeIDs(false)

	assertGood("sparfe://example.org/workload")
	assertGood("sPiFfE://example.org/workload")
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
	assert.NoError(t, CheckIDProtoNormalization(&types.SPIFFEID{
		TrustDomain: "example.org",
		Path:        "workload",
	}))

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
		"scheme must be 'spiffe'")
	assertBad("sPiFfE://example.org/workload",
		"scheme must be 'spiffe'")

	// Agent ID cannot be the server ID
	assertBad("spiffe://example.org/spire/server",
		"server ID is not allowed for agents")

	SetAllowUnsafeIDs(true)
	defer SetAllowUnsafeIDs(false)

	assertGood("sparfe://example.org/workload")
	assertGood("sPiFfE://example.org/workload")
	assertGood("spiffe://example.org/spire/server")
}

func testCommonCheckIDNormalization(assertGood func(string), assertBad func(string, string)) {
	assertGood("spiffe://example.org")
	assertGood("spiffe://example.org/workload")
	assertGood("spiffe://abcdefghijklmnopqrstuvwxyz0123456789.-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")

	assertBad("spiffe://%45example.org/workload",
		`parse "spiffe://%45example.org/workload": invalid URL escape "%45"`)
	assertBad("spiffe://example.org/世界/%E4%B8%96%E7%95%8C",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/",
		"path cannot have a trailing slash")
	assertBad("spiffe://example.org/workload/",
		"path cannot have a trailing slash")
	assertBad("spiffe://eXaMplE.org/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, and dashes")
	assertBad("spiffe://example.org//workload",
		"path cannot contain empty segments")
	assertBad("spiffe://example.org///workload",
		"path cannot contain empty segments")
	assertBad("spiffe://example.org/./workload",
		"path cannot contain dot segments")
	assertBad("spiffe://example.org/workload/../workload2",
		"path cannot contain dot segments")
	assertBad("spiffe://example.org/workload/%2e%2e/workload2",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%252e",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%23",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%00",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/%2z",
		`parse "spiffe://example.org/%2z": invalid URL escape "%2z"`)
	assertBad("spiffe://example.org/workload/"+url.PathEscape("%E4%B8%96%E7%95%8C"),
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://example.org/workload/%E4%B8%96%E7%95%8C",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://世界/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, and dashes")
	assertBad("spiffe://example.org/世界",
		"path characters are limited to letters, numbers, dots, dashes, and underscores")
	assertBad("spiffe://%E4%B8%96%E7%95%8C/workload",
		"trust domain characters are limited to lowercase letters, numbers, dots, and dashes")

	// Now test that the function responds favorably if the checks are
	// disabled via the flag.
	SetAllowUnsafeIDs(true)
	defer SetAllowUnsafeIDs(false)

	assertGood("spiffe://example.org/世界/%E4%B8%96%E7%95%8C")
	assertGood("spiffe://example.org/")
	assertGood("spiffe://example.org/workload/")
	assertGood("spiffe://eXaMplE.org/workload")
	assertGood("spiffe://example.org//workload")
	assertGood("spiffe://example.org///workload")
	assertGood("spiffe://example.org/./workload")
	assertGood("spiffe://example.org/workload/../workload2")
	assertGood("spiffe://example.org/workload/%2e%2e/workload2")
	assertGood("spiffe://example.org/workload/%252e")
	assertGood("spiffe://example.org/workload/%23")
	assertGood("spiffe://example.org/workload/%00")
	assertGood("spiffe://example.org/workload/" + url.PathEscape("%E4%B8%96%E7%95%8C"))
	assertGood("spiffe://example.org/workload/%E4%B8%96%E7%95%8C")
	assertGood("spiffe://世界/workload")
	assertGood("spiffe://example.org/世界")
	assertGood("spiffe://%E4%B8%96%E7%95%8C/workload")
}

func TestIDProtoString(t *testing.T) {
	assert := assert.New(t)

	id, err := IDProtoString(&types.SPIFFEID{})
	assert.EqualError(err, "trust domain is empty")
	assert.Empty(id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org", id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/", id)

	id, err = IDProtoString(&types.SPIFFEID{TrustDomain: "example.org", Path: "workload"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload", id)

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
	assert.EqualError(err, `scheme must be "spiffe://"`)
	assert.Nil(id)

	id, err = IDProtoFromString("spiffe://")
	assert.EqualError(err, "trust domain is empty")
	assert.Nil(id)

	id, err = IDProtoFromString("spiffe://example.org")
	assert.NoError(err)
	assert.Equal(&types.SPIFFEID{TrustDomain: "example.org"}, id)

	id, err = IDProtoFromString("spiffe://example.org/")
	assert.NoError(err)
	assert.Equal(&types.SPIFFEID{TrustDomain: "example.org", Path: "/"}, id)

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
	assert.EqualError(err, "trust domain is empty")
	assert.Empty(id)

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org", id.String())

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/", id.String())

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "workload"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload", id.String())

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload", id.String())

	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload/%41%42%43"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload/ABC", id.String())

	SetAllowUnsafeIDs(true)
	defer SetAllowUnsafeIDs(false)

	// When unsafe IDs are allowed, this will not percent encoding properly
	// which restores the original behavior of the API.
	id, err = IDFromProto(&types.SPIFFEID{TrustDomain: "example.org", Path: "/workload/%41%42%43"})
	assert.NoError(err)
	assert.Equal("spiffe://example.org/workload/%2541%2542%2543", id.String())
}

func TestTrustDomainFromString(t *testing.T) {
	assertGood := func(s string, expected string) {
		actual, err := TrustDomainFromString(s)
		assert.NoError(t, err, "%s should have passed", s)
		assert.Equal(t, expected, actual.String())
	}
	assertBad := func(s string, expectedErr string) {
		actual, err := TrustDomainFromString(s)
		assert.EqualError(t, err, expectedErr, "%s should have failed", s)
		assert.Equal(t, spiffeid.TrustDomain{}, actual)
	}

	assertGood("example.org", "example.org")
	assertGood("spiffe://example.org", "example.org")
	assertGood("spiffe://example.org/path", "example.org")
	assertGood("abcdefghijklmnopqrstuvwxyz0123456789.-_", "abcdefghijklmnopqrstuvwxyz0123456789.-_")

	assertBad("eXample.org", "trust domain characters are limited to lowercase letters, numbers, dots, and dashes")
	assertBad("spiffe://eXample.org", "trust domain characters are limited to lowercase letters, numbers, dots, and dashes")
	assertBad("spiffe://eXample.org/path", "trust domain characters are limited to lowercase letters, numbers, dots, and dashes")

	SetAllowUnsafeIDs(true)
	defer SetAllowUnsafeIDs(false)

	assertGood("eXample.org", "example.org")
	assertGood("spiffe://eXample.org", "example.org")
	assertGood("spiffe://eXample.org/path", "example.org")
}

func TestJoinPathSegments(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("", JoinPathSegments())
	assert.Equal("/foo", JoinPathSegments("foo"))
	assert.Equal("/foo", JoinPathSegments("/foo"))
	assert.Equal("/foo/世界", JoinPathSegments("foo", "世界"))
}

func TestFormatPath(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("", FormatPath(""))
	assert.Equal("/", FormatPath("/"))
	assert.Equal("/foo", FormatPath("%s", "foo"))
	assert.Equal("/foo", FormatPath("/%s", "foo"))
	assert.Equal("/foo//世界", FormatPath("%s//%s", "foo", "世界"))
}
