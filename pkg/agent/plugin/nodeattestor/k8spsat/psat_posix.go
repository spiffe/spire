//go:build !windows

package k8spsat

func getDefaultTokenPath() string {
	return defaultTokenPath
}
