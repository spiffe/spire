//go:build !windows
// +build !windows

package sat

func getDefaultTokenPath() string {
	return defaultTokenPath
}
