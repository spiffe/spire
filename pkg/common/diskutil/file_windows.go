//go:build windows
// +build windows

package diskutil

import (
	"fmt"
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

type fileAttribs struct {
	pathUTF16Ptr *uint16
	sa           *windows.SecurityAttributes
}

// AtomicWritePrivateFile writes data out to a private file.
// It writes to a temp file first, fsyncs that file, then swaps the file in.
// It renames the file using MoveFileEx with  'MOVEFILE_WRITE_THROUGH',
// which waits until the file is synced to disk.
func AtomicWritePrivateFile(path string, data []byte) error {
	return atomicWrite(path, data, sddl.PrivateFile)
}

// AtomicWritePubliclyReadableFile writes data out to a publicly readable file.
// It writes to a temp file first, fsyncs that file, then swaps the file in.
// It renames the file using MoveFileEx with  'MOVEFILE_WRITE_THROUGH',
// which waits until the file is synced to disk.
func AtomicWritePubliclyReadableFile(path string, data []byte) error {
	return atomicWrite(path, data, sddl.PubliclyReadableFile)
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

// WritePrivateFile writes data out to a private file. The file is created if it
// does not exist. If exists, it's overwritten.
func WritePrivateFile(path string, data []byte) error {
	return write(path, data, sddl.PrivateFile, false)
}

// WritePubliclyReadableFile writes data out to a publicly readable file. The
// file is created if it does not exist. If exists, it's overwritten.
func WritePubliclyReadableFile(path string, data []byte) error {
	return write(path, data, sddl.PubliclyReadableFile, false)
}

func atomicWrite(path string, data []byte, sddl string) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, sddl, true); err != nil {
		return err
	}

	return atomicRename(tmpPath, path)
}

// write writes to a file in the specified path with the specified
// security descriptor using the provided data. The sync boolean
// argument is used to indicate whether flushing to disk is required
// or not.
func write(path string, data []byte, sddl string, sync bool) error {
	handle, err := createFileForWriting(path, sddl)
	if err != nil {
		return err
	}

	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return fmt.Errorf("invalid file descriptor for file %q", path)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("failed to write to file %q: %w", path, err)
	}

	if sync {
		if err := file.Sync(); err != nil {
			file.Close()
			return fmt.Errorf("failed to sync file %q: %w", path, err)
		}
	}

	return file.Close()
}

func createFileForWriting(path string, sddl string) (windows.Handle, error) {
	file, err := getFileWithSecurityAttr(path, sddl)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateFile(file.pathUTF16Ptr,
		windows.GENERIC_WRITE,
		0,
		file.sa,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)

	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("could not create file %q: %w", path, err)
	}
	return handle, nil
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
	file, err := getFileWithSecurityAttr(path, sddl)
	if err != nil {
		return err
	}

	err = windows.CreateDirectory(file.pathUTF16Ptr, file.sa)
	if err != nil {
		return fmt.Errorf("could not create directory: %w", err)
	}
	return nil
}

func getFileWithSecurityAttr(path, sddl string) (*fileAttribs, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("could not convert SDDL %q into a self-relative security descriptor object: %w", sddl, err)
	}

	pathUTF16Ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("could not get pointer to the UTF-16 encoding of path %q: %w", path, err)
	}

	return &fileAttribs{
		pathUTF16Ptr: pathUTF16Ptr,
		sa: &windows.SecurityAttributes{
			InheritHandle:      1,
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		},
	}, nil
}
