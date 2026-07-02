//go:build !windows

package containerinfo

import (
	"bufio"
	"fmt"
	"os"
	"slices"
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
// docker and k8s workload attestors fail attestation outright. This parser
// uses strings.Split (single-space delimiter) so the empty source field is
// preserved as an empty string rather than collapsed.
func parseMountInfo(filename string) ([]mountInfo, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var infos []mountInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		info, err := parseMountInfoLine(line)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
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
// The line is split on single spaces so that an empty mount source (field 10)
// is preserved as an empty string rather than collapsed by strings.Fields.
func parseMountInfoLine(line string) (mountInfo, error) {
	// Split on single spaces so empty fields (e.g. an empty mount source
	// between "tmpfs" and the super options) survive as empty strings.
	fields := strings.Split(line, " ")

	// Locate the "-" separator. Everything before it is the fixed +
	// optional-tag fields; everything after is fstype, source, super options.
	sepIdx := slices.Index(fields, "-")
	if sepIdx < 0 {
		return mountInfo{}, fmt.Errorf("missing separator in mountinfo line: %s", line)
	}

	// Before the separator: mount ID (0), parent ID (1), major:minor (2),
	// root (3), mount point (4), mount options (5), then zero or more
	// optional fields. We need at least 6.
	if sepIdx < 6 {
		return mountInfo{}, fmt.Errorf("expected at least 6 fields before separator in mountinfo line: %s", line)
	}

	// After the separator: filesystem type (sepIdx+1), mount source
	// (sepIdx+2, may be empty), super options (sepIdx+3). We only need
	// the filesystem type.
	if sepIdx+1 >= len(fields) || fields[sepIdx+1] == "" {
		return mountInfo{}, fmt.Errorf("missing filesystem type in mountinfo line: %s", line)
	}

	return mountInfo{
		Root:   fields[3],
		FsType: fields[sepIdx+1],
	}, nil
}
