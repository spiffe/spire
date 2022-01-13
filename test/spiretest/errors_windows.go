//go:build windows
// +build windows

package spiretest

const (
	pathNotFound       = "The system cannot find the path specified."
	fileNotFound       = "The system cannot find the file specified."
	socketFileNotFound = "No connection could be made because the target machine actively refused it."
)

func FileNotFound() string {
	return fileNotFound
}

func PathNotFound() string {
	return pathNotFound
}

func SocketFileNotFound() string {
	return socketFileNotFound
}
