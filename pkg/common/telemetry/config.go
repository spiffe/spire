package telemetry

import (
	"crypto/x509"

	"github.com/hashicorp/hcl/hcl/token"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type MetricsConfig struct {
	FileConfig               FileConfig
	Logger                   logrus.FieldLogger
	ServiceName              string
	Sinks                    []Sink
	TrustDomain              string
	GetX509SVID              func() (*x509svid.SVID, error)
	GetX509BundleAuthorities func(spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

type FileConfig struct {
	Prometheus *PrometheusConfig `hcl:"Prometheus"`
	DogStatsd  []DogStatsdConfig `hcl:"DogStatsd"`
	Statsd     []StatsdConfig    `hcl:"Statsd"`
	M3         []M3Config        `hcl:"M3"`
	InMem      *InMem            `hcl:"InMem"`

	MetricPrefix           string   `hcl:"MetricPrefix"`
	EnableTrustDomainLabel *bool    `hcl:"EnableTrustDomainLabel"`
	EnableHostnameLabel    *bool    `hcl:"EnableHostnameLabel"`
	AllowedPrefixes        []string `hcl:"AllowedPrefixes"` // A list of metric prefixes to allow, with '.' as the separator
	BlockedPrefixes        []string `hcl:"BlockedPrefixes"` // A list of metric prefixes to block, with '.' as the separator
	AllowedLabels          []string `hcl:"AllowedLabels"`   // A list of metric labels to allow, with '.' as the separator
	BlockedLabels          []string `hcl:"BlockedLabels"`   // A list of metric labels to block, with '.' as the separator

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type DogStatsdConfig struct {
	Address            string                 `hcl:"address"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type PrometheusConfig struct {
	Host               string                 `hcl:"host"`
	Port               int                    `hcl:"port"`
	TLS                *TLSConfig             `hcl:"tls"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type TLSConfig struct {
	CertFile            string   `hcl:"cert_file"`
	KeyFile             string   `hcl:"key_file"`
	ClientCAFile        string   `hcl:"client_ca_file"` // optional
	UseSPIRESVID        bool     `hcl:"use_spire_svid"`
	AuthorizedSPIFFEIDs []string `hcl:"authorized_spiffe_ids"`
}

type StatsdConfig struct {
	Address            string                 `hcl:"address"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type M3Config struct {
	Address            string                 `hcl:"address"`
	Env                string                 `hcl:"env"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type InMem struct {
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}
