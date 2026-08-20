//go:build !windows

package containerinfo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMountInfoLine(t *testing.T) {
	for _, tt := range []struct {
		name     string
		line     string
		wantRoot string
		wantType string
		wantErr  string
	}{
		{
			name:     "normal cgroup2 line",
			line:     "1543 1542 0:32 /some/root /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate",
			wantRoot: "/some/root",
			wantType: "cgroup2",
		},
		{
			name:     "optional fields before separator",
			line:     "573 572 0:33 /docker/abc /sys/fs/cgroup/systemd ro,nosuid,nodev,noexec,relatime master:11 - cgroup cgroup rw,name=systemd",
			wantRoot: "/docker/abc",
			wantType: "cgroup",
		},
		{
			// Regression for #7036: a tmpfs mount has no source, so the field
			// after the filesystem type is empty. strings.Fields would collapse
			// it and the upstream parser rejected the whole file.
			name:     "tmpfs with empty source",
			line:     "119 206 0:68 / /local rw,relatime - tmpfs  rw,size=8192k",
			wantRoot: "/",
			wantType: "tmpfs",
		},
		{
			name:    "missing separator",
			line:    "1543 1542 0:32 /some/root /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime cgroup2 cgroup rw",
			wantErr: "missing separator",
		},
		{
			name:    "too few fields before separator",
			line:    "1543 1542 0:32 - cgroup2 cgroup rw",
			wantErr: "expected at least 6 fields before separator",
		},
		{
			name:    "missing filesystem type after separator",
			line:    "1543 1542 0:32 /some/root /sys/fs/cgroup rw - ",
			wantErr: "missing filesystem type",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseMountInfoLine(tt.line)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRoot, info.Root)
			assert.Equal(t, tt.wantType, info.FsType)
		})
	}
}

func TestParseMountInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mountinfo")
	content := "" +
		"2356 2355 0:30 /../containerid /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n" +
		"119 206 0:68 / /local rw,relatime - tmpfs  rw,size=8192k\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	infos, err := parseMountInfo(path)
	require.NoError(t, err)
	require.Len(t, infos, 2)

	assert.Equal(t, "/../containerid", infos[0].Root)
	assert.Equal(t, "cgroup2", infos[0].FsType)

	// The tmpfs line with an empty source must still parse.
	assert.Equal(t, "/", infos[1].Root)
	assert.Equal(t, "tmpfs", infos[1].FsType)
}
