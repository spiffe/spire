//go:build !windows

package diskutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestWriteFile(t *testing.T) {
	dir := spiretest.TempDir(t)

	tests := []struct {
		name            string
		data            []byte
		atomicWriteFunc func(string, []byte) error
		expectMode      os.FileMode
	}{
		{
			name:            "basic - AtomicWritePrivateFile",
			data:            []byte("Hello, World"),
			atomicWriteFunc: AtomicWritePrivateFile,
			expectMode:      0600,
		},
		{
			name:            "empty - AtomicWritePrivateFile",
			data:            []byte{},
			atomicWriteFunc: AtomicWritePrivateFile,
			expectMode:      0600,
		},
		{
			name:            "binary - AtomicWritePrivateFile",
			data:            []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			atomicWriteFunc: AtomicWritePrivateFile,
			expectMode:      0600,
		},
		{
			name:            "basic - AtomicWritePubliclyReadableFile",
			data:            []byte("Hello, World"),
			atomicWriteFunc: AtomicWritePubliclyReadableFile,
			expectMode:      0644,
		},
		{
			name:            "empty - AtomicWritePubliclyReadableFile",
			data:            []byte{},
			atomicWriteFunc: AtomicWritePubliclyReadableFile,
			expectMode:      0644,
		},
		{
			name:            "binary - AtomicWritePubliclyReadableFile",
			data:            []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			atomicWriteFunc: AtomicWritePubliclyReadableFile,
			expectMode:      0644,
		},
		{
			name:            "basic - WritePrivateFile",
			data:            []byte("Hello, World"),
			atomicWriteFunc: WritePrivateFile,
			expectMode:      0600,
		},
		{
			name:            "empty - WritePrivateFile",
			data:            []byte{},
			atomicWriteFunc: WritePrivateFile,
			expectMode:      0600,
		},
		{
			name:            "binary - WritePrivateFile",
			data:            []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			atomicWriteFunc: WritePrivateFile,
			expectMode:      0600,
		},
		{
			name:            "basic - WritePubliclyReadableFile",
			data:            []byte("Hello, World"),
			atomicWriteFunc: WritePubliclyReadableFile,
			expectMode:      0644,
		},
		{
			name:            "empty - WritePubliclyReadableFile",
			data:            []byte{},
			atomicWriteFunc: WritePubliclyReadableFile,
			expectMode:      0644,
		},
		{
			name:            "binary - WritePubliclyReadableFile",
			data:            []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			atomicWriteFunc: WritePubliclyReadableFile,
			expectMode:      0644,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(dir, "file")
			err := tt.atomicWriteFunc(file, tt.data)
			require.NoError(t, err)

			info, err := os.Stat(file)
			require.NoError(t, err)
			require.EqualValues(t, tt.expectMode, info.Mode())

			content, err := os.ReadFile(file)
			require.NoError(t, err)
			require.Equal(t, tt.data, content)

			require.NoError(t, os.Remove(file))
		})
	}
}
