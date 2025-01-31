//go:build windows

package diskutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/sddl"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWriteFile(t *testing.T) {
	dir := spiretest.TempDir(t)

	tests := []struct {
		name                     string
		data                     []byte
		expectSecurityDescriptor string
		atomicWriteFunc          func(string, []byte) error
	}{
		{
			name:                     "basic - AtomicWritePrivateFile",
			data:                     []byte("Hello, World"),
			expectSecurityDescriptor: sddl.PrivateFile,
			atomicWriteFunc:          AtomicWritePrivateFile,
		},
		{
			name:                     "empty - AtomicWritePrivateFile",
			data:                     []byte{},
			expectSecurityDescriptor: sddl.PrivateFile,
			atomicWriteFunc:          AtomicWritePrivateFile,
		},
		{
			name:                     "binary - AtomicWritePrivateFile",
			data:                     []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			expectSecurityDescriptor: sddl.PrivateFile,
			atomicWriteFunc:          AtomicWritePrivateFile,
		},
		{
			name:                     "basic - AtomicWritePubliclyReadableFile",
			data:                     []byte("Hello, World"),
			expectSecurityDescriptor: sddl.PubliclyReadableFile,
			atomicWriteFunc:          AtomicWritePubliclyReadableFile,
		},
		{
			name:                     "empty - AtomicWritePubliclyReadableFile",
			data:                     []byte{},
			expectSecurityDescriptor: sddl.PubliclyReadableFile,
			atomicWriteFunc:          AtomicWritePubliclyReadableFile,
		},
		{
			name:                     "binary - AtomicWritePubliclyReadableFile",
			data:                     []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			expectSecurityDescriptor: sddl.PubliclyReadableFile,
			atomicWriteFunc:          AtomicWritePubliclyReadableFile,
		},
		{
			name:                     "basic - WritePrivateFile",
			data:                     []byte("Hello, World"),
			expectSecurityDescriptor: sddl.PrivateFile,
			atomicWriteFunc:          WritePrivateFile,
		},
		{
			name:                     "empty - WritePrivateFile",
			data:                     []byte{},
			expectSecurityDescriptor: sddl.PrivateFile,
			atomicWriteFunc:          WritePrivateFile,
		},
		{
			name:                     "binary - WritePrivateFile",
			data:                     []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			expectSecurityDescriptor: sddl.PrivateFile,
			atomicWriteFunc:          WritePrivateFile,
		},
		{
			name:                     "basic - WritePubliclyReadableFile",
			data:                     []byte("Hello, World"),
			expectSecurityDescriptor: sddl.PubliclyReadableFile,
			atomicWriteFunc:          WritePubliclyReadableFile,
		},
		{
			name:                     "empty - WritePubliclyReadableFile",
			data:                     []byte{},
			expectSecurityDescriptor: sddl.PubliclyReadableFile,
			atomicWriteFunc:          WritePubliclyReadableFile,
		},
		{
			name:                     "binary - WritePubliclyReadableFile",
			data:                     []byte{0xFF, 0, 0xFF, 0x3D, 0xD8, 0xA9, 0xDC, 0xF0, 0x9F, 0x92, 0xA9},
			expectSecurityDescriptor: sddl.PubliclyReadableFile,
			atomicWriteFunc:          WritePubliclyReadableFile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(dir, "file")
			err := tt.atomicWriteFunc(file, tt.data)
			require.NoError(t, err)

			pathUTF16Ptr, err := windows.UTF16PtrFromString(file)
			require.NoError(t, err)

			handle, err := windows.CreateFile(pathUTF16Ptr,
				windows.GENERIC_WRITE,
				0,
				nil,
				windows.OPEN_EXISTING,
				windows.FILE_ATTRIBUTE_NORMAL,
				0)

			require.NoError(t, err)
			sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			require.NoError(t, windows.CloseHandle(handle))
			require.NoError(t, err)

			require.Equal(t, sd.String(), tt.expectSecurityDescriptor)

			content, err := os.ReadFile(file)
			require.NoError(t, err)
			require.Equal(t, tt.data, content)

			require.NoError(t, os.Remove(file))
		})
	}
}
