//go:build !windows

package spiretest

const (
	fileNotFound = "no such file or directory"
)

func PathNotFound() string {
	return fileNotFound
}

func FileNotFound() string {
	return fileNotFound
}

func SocketFileNotFound() string {
	return fileNotFound
}
