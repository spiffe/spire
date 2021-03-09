package idutil

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/types"
)

var (
	rePercentEncodedASCII = regexp.MustCompile(`%[0-7][[:xdigit:]]`)
	rePercentEncoded      = regexp.MustCompile(`%[[:xdigit:]][[:xdigit:]]`)

	allowUnsafeIDsPolicy bool
)

func allowUnsafeIDs() bool {
	return allowUnsafeIDsPolicy
}

// SetAllowUnsafeIDs effectively removes all safety checks provided by the
// "safety" functions in this source file. It is a switch to allow turning off
// the safety valve for deployments that need time to adjust API usage to
// conform to the restrictions.
func SetAllowUnsafeIDs(allow bool) {
	allowUnsafeIDsPolicy = allow
}

// CheckIDProtoNormalization ensures the the provided ID is properly normalized.
func CheckIDProtoNormalization(in *types.SPIFFEID) error {
	if allowUnsafeIDs() {
		return nil
	}
	s, err := IDProtoString(in)
	if err != nil {
		return err
	}
	return CheckIDStringNormalization(s)
}

// CheckIDStringNormalization ensures the the provided ID is properly normalized.
func CheckIDStringNormalization(id string) error {
	if allowUnsafeIDs() {
		return nil
	}

	// Parse the URL. This will unescape the percent-encoded characters. If
	// there are invalid percent-encoded characters, this function will fail.
	u, err := url.Parse(id)
	if err != nil {
		return err
	}

	return CheckIDURLNormalization(u)
}

// CheckIDURLNormalization returns if a URL is normalized or not. It relies on
// behavior and fields populated by url.Parse(). DO NOT call it with a URL that
// has not gone through url.Parse().
func CheckIDURLNormalization(u *url.URL) error {
	if allowUnsafeIDs() {
		return nil
	}

	// Rule out percent-encoded ASCII
	if rePercentEncodedASCII.MatchString(u.EscapedPath()) {
		return errors.New("path cannot contain percent-encoded ASCII characters")
	}

	// At this point, if RawPath is set, then the path contains non-ASCII
	// characters, since percent-encoded ASCII was ruled out above. Ensure
	// that there is no percent-encoded characters, since that would imply
	// a mix-n-match of utf-8 and percent-encoded utf-8, which we want to
	// reject since it wouldn't be normal to have this kind of path and it
	// likely indicates either 1) a bug, or 2) malicious intent.
	if u.RawPath != "" && rePercentEncoded.MatchString(u.RawPath) {
		return errors.New("path cannot contain both non-ASCII and percent-encoded characters")
	}

	// Check the scheme and host
	switch {
	case u.Scheme != "spiffe":
		return errors.New("scheme must be 'spiffe'")
	case strings.ToLower(u.Host) != u.Host:
		return errors.New("trust domain name must be lowercase")
	}

	// Check the path
	switch {
	case u.Path == "":
	case u.Path[len(u.Path)-1] == '/':
		return errors.New("path cannot have a trailing slash")
	case u.Path != path.Clean(u.Path):
		return errors.New("path cannot contain empty, '.', or '..' segments")
	}

	return nil
}

// IDProtoString constructs a URL string for the given ID protobuf. It does
// not interpret the contents of the trust domain or path with the exception
// of adding a leading slash on the path where necessary.
func IDProtoString(id *types.SPIFFEID) (string, error) {
	if id.TrustDomain == "" {
		return "", errors.New("trust domain is empty")
	}
	return "spiffe://" + id.TrustDomain + ensureLeadingSlash(id.Path), nil
}

// IDProtoFromString parses a SPIFFE ID string into the raw ID proto components.
// It does not attempt to escape/unescape any portion of the ID.
func IDProtoFromString(id string) (*types.SPIFFEID, error) {
	trimmed := strings.TrimPrefix(id, "spiffe://")
	if trimmed == id {
		return nil, errors.New(`scheme must be "spiffe://"`)
	}
	parts := strings.SplitN(trimmed, "/", 2)
	td := parts[0]
	if len(td) == 0 {
		return nil, errors.New("trust domain is empty")
	}
	path := ""
	if len(parts) > 1 {
		path = "/" + parts[1]
	}
	return &types.SPIFFEID{
		TrustDomain: td,
		Path:        path,
	}, nil
}

// CheckAgentIDStringNormalization ensures the provided agent ID string is
// properly normalized. It also ensures it is not a server ID.
func CheckAgentIDStringNormalization(agentID string) error {
	if allowUnsafeIDs() {
		return nil
	}

	// Parse the URL. This will unescape the percent-encoded characters. If
	// there are invalid percent-encoded characters, this function will fail.
	u, err := url.Parse(agentID)
	if err != nil {
		return err
	}

	if err := CheckIDURLNormalization(u); err != nil {
		return err
	}

	// We want to do more than this but backcompat compels us to not too. We'll
	// get more aggressive in the future.
	if u.Path == ServerIDPath {
		return errors.New("server ID is not allowed for agents")
	}

	return nil
}

// IDFromProto returns SPIFFE ID from the proto representation
func IDFromProto(id *types.SPIFFEID) (spiffeid.ID, error) {
	if allowUnsafeIDs() {
		return spiffeid.New(id.TrustDomain, id.Path)
	}
	s, err := IDProtoString(id)
	if err != nil {
		return spiffeid.ID{}, err
	}
	return spiffeid.FromString(s)
}

// FormatPath formats a path string. The function ensures a leading slash is
// present.
func FormatPath(format string, args ...interface{}) string {
	return ensureLeadingSlash(fmt.Sprintf(format, args...))
}

// JoinPathSegments escapes path segments and joins them together. The
// function also ensures a leading slash is present.
func JoinPathSegments(segments ...string) string {
	return ensureLeadingSlash(strings.Join(segments, "/"))
}

func ensureLeadingSlash(p string) string {
	if p != "" && p[0] != '/' {
		p = "/" + p
	}
	return p
}
