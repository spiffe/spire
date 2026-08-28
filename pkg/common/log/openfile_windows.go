package log

import (
	"os"

	"golang.org/x/sys/windows"
)

// openLogFile opens the log file for appending. It does not use os.OpenFile
// because Go opens files with FILE_SHARE_READ and FILE_SHARE_WRITE only, and
// without FILE_SHARE_DELETE our own handle is what denies an external rename.
func openLogFile(name string) (*os.File, error) {
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}

	// The rights Go grants for os.O_APPEND. GENERIC_WRITE is deliberately absent
	// since it would append at the start of the file rather than the end.
	const access = windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_ATTRIBUTES |
		windows.FILE_WRITE_EA |
		windows.STANDARD_RIGHTS_WRITE |
		windows.SYNCHRONIZE

	handle, err := windows.CreateFile(
		namep,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS, // os.O_CREATE without os.O_EXCL or os.O_TRUNC
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}

	return os.NewFile(uintptr(handle), name), nil
}
