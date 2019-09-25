package cgroup

import (
	"fmt"
	"regexp"
	"strings"
)

// Token is a character or set of characters that are used during parsing of a cgroup entry.
type Token string

const (
	// WildcardToken is used to match a variable number of any character, excluding forward slash (`/`).
	//
	// This token MAY be provided any number of times.
	WildcardToken Token = "*"

	// ContainerIDToken is used to match the container id, which MUST not include a forward slash (`/`).
	//
	// This token MUST be provided exactly once in a pattern.
	ContainerIDToken Token = "<id>"

	// used for converting from our tokens to those understood by the regexp package
	regexpWildcard         = "[^\\/]*"
	regexpWildcardSubmatch = "([^\\/]*)"

	// index for slice returned by FindSubmatch
	// fullmatchIndex = 0
	submatchIndex = 1
)

// ContainerIDFinder finds a container id from a cgroup entry.
type ContainerIDFinder interface {
	// FindContainerID returns a container id and true if the known pattern is matched, false otherwise.
	FindContainerID(cgroup string) (containerID string, found bool)
}

func newContainerIDFinder(pattern string) (ContainerIDFinder, error) {
	if strings.Count(pattern, string(ContainerIDToken)) != 1 {
		return nil, fmt.Errorf("pattern %q must contain the container id token %q exactly once", pattern, ContainerIDToken)
	}
	pattern = strings.ReplaceAll(pattern, string(WildcardToken), regexpWildcard)
	pattern = strings.Replace(pattern, string(ContainerIDToken), regexpWildcardSubmatch, 1)
	pattern = "^" + pattern + "$"
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
// to describe how a container id should be extracted from a cgroup entry.
//
// Examples:
//     "/docker/<id>"
//     "/my.slice/*/<id>/*"
//
// Note: The pattern provided is *not* a regular expression. It is a simplified matching
// language that enforces a forward slash-delimited schema.
func NewContainerIDFinder(patterns []string) (ContainerIDFinder, error) {
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
	matches := f.re.FindSubmatch([]byte(cgroup))
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
