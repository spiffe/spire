//go:build !windows
// +build !windows

package psat

func getDefaultTokenPath() string {
	return defaultTokenPath
}
