package trustbundlesources

const (
	BundleFormatPEM    = "pem"
	BundleFormatSPIFFE = "spiffe"
	UseUnspecified     = 0
	UseBootstrap       = 1
	UseRebootstrap     = 2
)

type Config struct {
	InsecureBootstrap     bool
	TrustBundleFormat     string
	TrustBundlePath       string
	TrustBundleURL        string
	TrustBundleUnixSocket string
	TrustDomain           string
	ServerAddress         string
	ServerPort            int
}
