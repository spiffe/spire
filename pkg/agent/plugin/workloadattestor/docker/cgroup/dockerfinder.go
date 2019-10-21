package cgroup

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// A token to match an entire path component in a "/" delimited path
	wildcardToken = "*"
	// A regex expression that expresses wildcardToken
	regexpWildcard = "[^\\/]*"

	// A token to match, and extract as a container ID, an entire path component in a
	// "/" delimited path
	containerIDToken = "<id>"
	// A regex expression that expresses containerIDToken
	regexpContainerID = "([^\\/]*)"
	// index for slice returned by FindStringSubmatch
	submatchIndex = 1
)

// ContainerIDFinder finds a container id from a cgroup entry.
type ContainerIDFinder interface {
	// FindContainerID returns a container id and true if the known pattern is matched, false otherwise.
	FindContainerID(cgroup string) (containerID string, found bool)
}

func newContainerIDFinder(pattern string) (ContainerIDFinder, error) {
	idTokenCount := 0
	elems := strings.Split(pattern, "/")
	for i, e := range elems {
		switch e {
		case wildcardToken:
			elems[i] = regexpWildcard
		case containerIDToken:
			idTokenCount++
			elems[i] = regexpContainerID
		default:
			elems[i] = regexp.QuoteMeta(e)
		}
	}
	if idTokenCount != 1 {
		return nil, fmt.Errorf("pattern %q must contain the container id token %q exactly once", pattern, containerIDToken)
	}

	pattern = "^" + strings.Join(elems, "/") + "$"
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create container id fetcher: %v", err)
	}
	return &containerIDFinder{
		re: re,
	}, nil
}

// NewContainerIDFinder returns a new ContainerIDFinder.
//
// The patterns provided should use the Tokens defined in this package in order
// to describe how a container id should be extracted from a cgroup entry. The
// given patterns MUST NOT be ambiguous and an error will be returned if multiple
// patterns can match the same input. An example of invalid input:
//     "/a/b/<id>"
//     "/*/b/<id>"
//
// Examples:
//     "/docker/<id>"
//     "/my.slice/*/<id>/*"
//
// Note: The pattern provided is *not* a regular expression. It is a simplified matching
// language that enforces a forward slash-delimited schema.
func NewContainerIDFinder(patterns []string) (ContainerIDFinder, error) {
	if len(patterns) < 1 {
		return nil, errors.New("dockerfinder: at least 1 pattern must be supplied")
	}

	if ambiguousPatterns := findAmbiguousPatterns(patterns); len(ambiguousPatterns) != 0 {
		return nil, fmt.Errorf("dockerfinder: patterns must not be ambiguous: %q", ambiguousPatterns)
	}
	var finders []ContainerIDFinder
	for _, pattern := range patterns {
		finder, err := newContainerIDFinder(pattern)
		if err != nil {
			return nil, err
		}
		finders = append(finders, finder)
	}
	return &containerIDFinders{
		finders: finders,
	}, nil
}

type containerIDFinder struct {
	re *regexp.Regexp
}

func (f *containerIDFinder) FindContainerID(cgroup string) (string, bool) {
	matches := f.re.FindStringSubmatch(cgroup)
	if len(matches) == 0 {
		return "", false
	}
	return string(matches[submatchIndex]), true
}

type containerIDFinders struct {
	finders []ContainerIDFinder
}

func (f *containerIDFinders) FindContainerID(cgroup string) (string, bool) {
	for _, finder := range f.finders {
		id, ok := finder.FindContainerID(cgroup)
		if ok {
			return id, ok
		}
	}
	return "", false
}

// There must be exactly 0 or 1 pattern that matches a given input. Enforcing
// this at startup, instead of at runtime (e.g. in `FindContainerID`) ensures that
// a bad configuration is found immediately during rollout, rather than once a
// specific cgroup input is encountered.
//
// Given the restricted grammar of wildcardToken and containerIDToken and
// the goal of protecting a user from invalid configuration, detecting ambiguous patterns
// is done as follows:
//
// 1. If the number of path components in two patterns differ, they cannot match identical inputs.
// This assertions follows from the path focused grammar and the fact that the regex
// wildcards (regexpWildcard and regexpContainerID) cannot match "/".
// 2. If the number of path components in two patterns are the same, we test "component
// equivalence". wildcardToken and containerIDToken are equivalent to anything other
// string, else string equivalence is required.
// From this and the fact the regex wildcards cannot match "/" follows that a single
// non-equivalent path component means the two patterns cannot match the same inputs.
func findAmbiguousPatterns(patterns []string) []string {
	p := patterns[0]
	rest := patterns[1:]
	foundPatterns := make(map[string]struct{})

	// generate all combinations except for equivalent
	// index combinations which will always match.
	for len(rest) > 0 {
		for _, p2 := range rest {
			if equivalentPatterns(p, p2) {
				foundPatterns[p] = struct{}{}
				foundPatterns[p2] = struct{}{}
			}
		}

		p = rest[0]
		rest = rest[1:]
	}

	out := make([]string, 0, len(foundPatterns))
	for foundPattern := range foundPatterns {
		out = append(out, foundPattern)
	}

	return out
}

func equivalentPatterns(a, b string) bool {
	if a == b {
		return true
	}

	aComponents := strings.Split(a, "/")
	bComponents := strings.Split(b, "/")
	if len(aComponents) != len(bComponents) {
		return false
	}

	for i, comp := range aComponents {
		switch {
		case comp == bComponents[i]:
		case comp == wildcardToken || bComponents[i] == wildcardToken:
		case comp == containerIDToken || bComponents[i] == containerIDToken:
		default:
			return false
		}
	}
	return true
}
