package trustbundlesources

const (
	BundleFormatPEM    = "pem"
	BundleFormatSPIFFE = "spiffe"
)

type Config struct {
	InsecureBootstrap     bool
	TrustBundleFormat     string
	TrustBundlePath       string
	TrustBundleURL        string
	TrustBundleUnixSocket string
}
