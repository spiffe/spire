//go:build !windows

package k8ssat

func getDefaultTokenPath() string {
	return defaultTokenPath
}
