//go:build !windows

package trustbundlesources

func getServiceAccountNamespacePath() string {
	return serviceAccountNamespacePath
}
