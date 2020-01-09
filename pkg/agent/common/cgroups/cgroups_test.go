package cgroups

import (
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// cgSimple is a good set of cgroup entries
	cgSimple = `11:hugetlb:/
10:devices:/user.slice
9:pids:/user.slice/user-1000.slice
8:perf_event:/
7:net_cls,net_prio:/
6:cpuset:/
5:memory:/user.slice
4:cpu,cpuacct:/user.slice
3:freezer:/
2:blkio:/user.slice
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
`
	// cgBadFormat is a malformed set of cgroup entries (no slash separator)
	cgBadFormat = `11:hugetlb
`
)

var (
	expectSimpleCgroup = []Cgroup{
		{"11", "hugetlb", "/"},
		{"10", "devices", "/user.slice"},
		{"9", "pids", "/user.slice/user-1000.slice"},
		{"8", "perf_event", "/"},
		{"7", "net_cls,net_prio", "/"},
		{"6", "cpuset", "/"},
		{"5", "memory", "/user.slice"},
		{"4", "cpu,cpuacct", "/user.slice"},
		{"3", "freezer", "/"},
		{"2", "blkio", "/user.slice"},
		{"1", "name=systemd", "/user.slice/user-1000.slice/session-2.scope"},
	}
)

func TestCgroups(t *testing.T) {
	cgroups, err := GetCgroups(123, FakeFileSystem{
		Files: map[string]string{
			"/proc/123/cgroup": cgSimple,
		},
	})
	require.NoError(t, err)
	require.Len(t, cgroups, 11)
	require.Equal(t, expectSimpleCgroup, cgroups)
}

func TestCgroupsNotFound(t *testing.T) {
	cgroups, err := GetCgroups(123, FakeFileSystem{})
	require.True(t, os.IsNotExist(err))
	require.Nil(t, cgroups)
}

func TestCgroupsBadFormat(t *testing.T) {
	cgroups, err := GetCgroups(123, FakeFileSystem{
		Files: map[string]string{
			"/proc/123/cgroup": cgBadFormat,
		},
	})
	require.EqualError(t, err, `cgroup entry contains 2 colons, but expected at least 2 colons: "11:hugetlb"`)
	require.Nil(t, cgroups)
}

type FakeFileSystem struct {
	Files map[string]string
}

func (fs FakeFileSystem) Open(path string) (io.ReadCloser, error) {
	data, ok := fs.Files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return ioutil.NopCloser(strings.NewReader(data)), nil
}
