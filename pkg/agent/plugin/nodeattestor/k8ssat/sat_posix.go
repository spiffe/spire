//go:build !windows
// +build !windows

package k8ssat

func getDefaultTokenPath() string {
	return defaultTokenPath
}
