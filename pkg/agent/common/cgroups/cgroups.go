package cgroups

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Filesystem abstracts filesystem operations.
type FileSystem interface {
	// Open opens the named file for reading.
	Open(name string) (io.ReadCloser, error)
}

// Cgroup represents a linux cgroup.
type Cgroup struct {
	HierarchyID    string
	ControllerList string
	GroupPath      string
}

// GetCGroups returns a slice of cgroups for pid using fs for filesystem calls.
//
// The expected cgroup format is "hierarchy-ID:controller-list:cgroup-path", and
// this function will return an error if every cgroup does not meet that format.
//
// For more information, see:
//  - http://man7.org/linux/man-pages/man7/cgroups.7.html
//  - https://www.kernel.org/doc/Documentation/cgroup-v2.txt
func GetCgroups(pid int32, fs FileSystem) ([]Cgroup, error) {
	path := fmt.Sprintf("/proc/%v/cgroup", pid)
	file, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cgroups []Cgroup
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		token := scanner.Text()
		substrings := strings.SplitN(token, ":", 3)
		if len(substrings) < 3 {
			return nil, fmt.Errorf("cgroup entry contains %v colons, but expected at least 2 colons: %q", len(substrings), token)
		}
		cgroups = append(cgroups, Cgroup{
			HierarchyID:    substrings[0],
			ControllerList: substrings[1],
			GroupPath:      substrings[2],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cgroups, nil
}
