//go:build !windows

package containerinfo

import (
	"fmt"
	"os"
	"strings"
)

// mountInfo holds the subset of /proc/<pid>/mountinfo fields that the
// container info extractor consumes. The full mountinfo line format is
// documented in proc(5).
type mountInfo struct {
	// Root is the pathname of the directory in the filesystem which forms the
	// root of this mount (field 4).
	Root string
	// FsType is the filesystem type (the first field after the "-" separator).
	FsType string
}

// parseMountInfo parses /proc/<pid>/mountinfo.
//
// It exists because k8s.io/mount-utils ParseMountInfo splits each line with
// strings.Fields, which collapses runs of whitespace and therefore drops an
// empty mount source field. Per proc(5) the mount source (the field after the
// filesystem type) may be empty (for example a tmpfs mount has no source), and
// the kernel escapes any real whitespace in a path as octal (\040). A line
// like:
//
//	119 206 0:68 / /local rw,relatime - tmpfs  rw,size=8192k
//
// is therefore valid: the double space between "tmpfs" and "rw,size=8192k"
// unambiguously means an empty source. The upstream parser counts that as 9
// fields (it expects at least 10) and rejects the entire file, which made the
// docker and k8s workload attestors fail attestation outright. This parser is
// position-aware around the "-" separator so an empty source is tolerated.
func parseMountInfo(filename string) ([]mountInfo, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var infos []mountInfo
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		info, err := parseMountInfoLine(line)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// parseMountInfoLine parses a single mountinfo line. The format (see proc(5))
// is, in order:
//
//	(1) mount ID  (2) parent ID  (3) major:minor  (4) root  (5) mount point
//	(6) mount options  (7..) zero or more optional fields  (8) a "-" separator
//	(9) filesystem type  (10) mount source  (11) super options
//
// Only the fields the extractor needs (root and filesystem type) are returned.
// Fields up to the "-" separator are whitespace-separated and never empty, so
// strings.Fields is safe there. The three fields after the separator are taken
// by position so an empty source (field 10) is preserved rather than collapsed.
func parseMountInfoLine(line string) (mountInfo, error) {
	// Split the line into the part before the "-" separator and the part after
	// it. The separator is a standalone "-" token, so it is surrounded by
	// spaces. Splitting on " - " keeps it unambiguous: optional-field tags
	// before the separator never equal a bare "-", and the post-separator
	// fields are matched by position below.
	sep := strings.Index(line, " - ")
	if sep < 0 {
		return mountInfo{}, fmt.Errorf("missing separator in mountinfo line: %s", line)
	}

	before := strings.Fields(line[:sep])
	// Fields before the separator: mount ID, parent ID, major:minor, root,
	// mount point, mount options, then zero or more optional fields. The root
	// is field index 3 (zero-based).
	if len(before) < 6 {
		return mountInfo{}, fmt.Errorf("expected at least 6 fields before separator in mountinfo line: %s", line)
	}

	// After the separator there are exactly three positional fields:
	// filesystem type, mount source, and super options. The source may be
	// empty, so parse by splitting into at most three fields and keeping the
	// first (filesystem type). Trailing whitespace from an empty source does
	// not affect the filesystem type, which is the first non-empty token.
	after := strings.Fields(line[sep+len(" - "):])
	if len(after) < 1 {
		return mountInfo{}, fmt.Errorf("missing filesystem type in mountinfo line: %s", line)
	}

	return mountInfo{
		Root:   before[3],
		FsType: after[0],
	}, nil
}
