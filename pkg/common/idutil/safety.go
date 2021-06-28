package idutil

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

var (
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
	u, err := urlParse(id)
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

	// Check the scheme and host
	if u.Scheme != "spiffe" {
		return errors.New("scheme must be 'spiffe'")
	}

	return validateComponents(u.Host, u.EscapedPath())
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
	u, err := urlParse(agentID)
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
	// TODO: when the safety valve is removed, this function should:
	// 1. not ensure the leading slash.
	// 2. validate that the produced path is correct
	return ensureLeadingSlash(fmt.Sprintf(format, args...))
}

// JoinPathSegments escapes path segments and joins them together. The
// function also ensures a leading slash is present.
func JoinPathSegments(segments ...string) string {
	// TODO: when the safety valve is removed, this function should:
	// 1. not ensure the leading slash.
	// 2. validate that the produced path is correct
	return ensureLeadingSlash(strings.Join(segments, "/"))
}

// TrustDomainFromString parses a trust domain from a string.
func TrustDomainFromString(s string) (spiffeid.TrustDomain, error) {
	td, err := spiffeid.TrustDomainFromString(s)
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	if !allowUnsafeIDs() {
		if err := validateTrustDomain(td.String()); err != nil {
			return spiffeid.TrustDomain{}, err
		}

		// spiffeid.TrustDomainFromString currently "normalizes" the trust
		// domain portion by lowercasing. We don't want to mask an "invalid"
		// trust domain by this normalization, so we do this prefix check here
		// to detect if it happened. The input string should prefix match
		// either trust domain name or trust domain ID otherwise some
		// normalization occurred.
		if !strings.HasPrefix(s, td.String()) && !strings.HasPrefix(s, td.IDString()) {
			return spiffeid.TrustDomain{}, errors.New("trust domain characters are limited to lowercase letters, numbers, dots, and dashes")
		}
	}
	return td, nil
}

func ensureLeadingSlash(p string) string {
	if p != "" && p[0] != '/' {
		p = "/" + p
	}
	return p
}

func urlParse(id string) (*url.URL, error) {
	// Detect an errant scheme beforehand since url.Parse will lowercase the
	// scheme automatically.
	if !strings.HasPrefix(id, "spiffe://") {
		return nil, errors.New("scheme must be 'spiffe'")
	}
	return url.Parse(id)
}

func validateComponents(td, path string) error {
	if err := validateTrustDomain(td); err != nil {
		return err
	}
	return validatePath(path)
}

func validateTrustDomain(td string) error {
	for i := 0; i < len(td); i++ {
		if !isValidTrustDomainChar(td[i]) {
			return errors.New("trust domain characters are limited to lowercase letters, numbers, dots, and dashes")
		}
	}
	return nil
}

func validatePath(path string) error {
	segmentStart := 0
	segmentEnd := 0
	for ; segmentEnd < len(path); segmentEnd++ {
		c := path[segmentEnd]
		if c == '/' {
			switch path[segmentStart:segmentEnd] {
			case "/":
				return errors.New("path cannot contain empty segments")
			case "/.", "/..":
				return errors.New("path cannot contain dot segments")
			}
			segmentStart = segmentEnd
			continue
		}
		if !isValidPathSegmentChar(c) {
			return errors.New("path characters are limited to letters, numbers, dots, dashes, and underscores")
		}
	}

	switch path[segmentStart:segmentEnd] {
	case "/":
		return errors.New("path cannot have a trailing slash")
	case "/.", "/..":
		return errors.New("path cannot contain dot segments")
	}
	return nil
}

func isValidTrustDomainChar(c uint8) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.', c == '-', c == '_':
		return true
	default:
		return false
	}
}

func isValidPathSegmentChar(c uint8) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.', c == '-', c == '_':
		return true
	default:
		return false
	}
}
