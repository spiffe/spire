package diskutil

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAtomicWriteFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	tests := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{
			name: "basic test",
			data: []byte("Hello, World"),
			mode: 0600,
		},
		{
			name: "empty",
			data: []byte{},
			mode: 0440,
		},
		{
			name: "binary",
			data: []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			mode: 0644,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(dir, "file")
			err := AtomicWriteFile(file, tt.data, tt.mode)
			require.NoError(t, err)

			info, err := os.Stat(file)
			require.NoError(t, err)
			require.EqualValues(t, tt.mode, info.Mode())

			content, err := ioutil.ReadFile(file)
			require.NoError(t, err)
			require.Equal(t, tt.data, content)

			require.NoError(t, os.Remove(file))
		})
	}
}
