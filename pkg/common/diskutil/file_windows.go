//go:build windows
// +build windows

package diskutil

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/spiffe/spire/pkg/common/sddl"
	"golang.org/x/sys/windows"
)

const (
	movefileReplaceExisting = 0x1
	movefileWriteThrough    = 0x8
)

// AtomicWriteFile writes data out.  It writes to a temp file first, fsyncs that file,
// then swaps the file in. Rename file using a custom MoveFileEx that uses 'MOVEFILE_WRITE_THROUGH' witch waits until
// file is synced to disk.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, mode); err != nil {
		return err
	}

	return atomicRename(tmpPath, path)
}

func CreateDataDirectory(path string) error {
	return MkdirAll(path, sddl.PrivateFile)
}

// MkdirAll is a modified version of os.MkdirAll for use on Windows
// so that it creates the directory with the specified security descriptor.
func MkdirAll(path string, sddl string) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = MkdirAll(path[:j-1], sddl)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = mkdir(path, sddl)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

func write(tmpPath string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}

	return file.Close()
}

func atomicRename(oldPath, newPath string) error {
	if err := rename(oldPath, newPath); err != nil {
		return &os.LinkError{
			Op:  "rename",
			Old: oldPath,
			New: newPath,
			Err: err,
		}
	}

	return nil
}

func rename(oldPath, newPath string) error {
	from, err := syscall.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(from, to, movefileReplaceExisting|movefileWriteThrough)
}

// mkdir creates a new directory with a specific security descriptor.
// The security descriptor must be specified using the Security Descriptor
// Definition Language (SDDL).
//
// In the same way as os.MkDir, errors returned are of type *os.PathError.
func mkdir(path string, sddl string) error {
	sa := windows.SecurityAttributes{Length: 0}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1
	sa.SecurityDescriptor = sd

	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}

	e := windows.CreateDirectory(pathUTF16, &sa)
	if e != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: e}
	}
	return nil
}
