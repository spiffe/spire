package telemetry

import (
	"crypto/x509"

	"github.com/hashicorp/hcl/hcl/token"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
)

type MetricsConfig struct {
	FileConfig               FileConfig
	Logger                   logrus.FieldLogger
	ServiceName              string
	Sinks                    []Sink
	TrustDomain              string
	TLSPolicy                tlspolicy.Policy
	GetX509SVID              func() (*x509svid.SVID, error)
	GetX509BundleAuthorities func(spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

type FileConfig struct {
	Prometheus *PrometheusConfig `hcl:"Prometheus" yaml:"Prometheus"`
	DogStatsd  []DogStatsdConfig `hcl:"DogStatsd" yaml:"DogStatsd"`
	Statsd     []StatsdConfig    `hcl:"Statsd" yaml:"Statsd"`
	M3         []M3Config        `hcl:"M3" yaml:"M3"`
	InMem      *InMem            `hcl:"InMem" yaml:"InMem"`

	MetricPrefix           string   `hcl:"MetricPrefix" yaml:"MetricPrefix"`
	EnableTrustDomainLabel *bool    `hcl:"EnableTrustDomainLabel" yaml:"EnableTrustDomainLabel"`
	EnableHostnameLabel    *bool    `hcl:"EnableHostnameLabel" yaml:"EnableHostnameLabel"`
	AllowedPrefixes        []string `hcl:"AllowedPrefixes" yaml:"AllowedPrefixes"` // A list of metric prefixes to allow, with '.' as the separator
	BlockedPrefixes        []string `hcl:"BlockedPrefixes" yaml:"BlockedPrefixes"` // A list of metric prefixes to block, with '.' as the separator
	AllowedLabels          []string `hcl:"AllowedLabels" yaml:"AllowedLabels"`     // A list of metric labels to allow, with '.' as the separator
	BlockedLabels          []string `hcl:"BlockedLabels" yaml:"BlockedLabels"`     // A list of metric labels to block, with '.' as the separator

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

type DogStatsdConfig struct {
	Address            string                 `hcl:"address" yaml:"address"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

type PrometheusConfig struct {
	Host               string                 `hcl:"host" yaml:"host"`
	Port               int                    `hcl:"port" yaml:"port"`
	TLS                *TLSConfig             `hcl:"tls" yaml:"tls"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

type TLSConfig struct {
	CertFile            string   `hcl:"cert_file" yaml:"certFile"`
	KeyFile             string   `hcl:"key_file" yaml:"keyFile"`
	ClientCAFile        string   `hcl:"client_ca_file" yaml:"clientCaFile"` // optional
	UseSPIRESVID        bool     `hcl:"use_spire_svid" yaml:"useSpireSvid"`
	AuthorizedSPIFFEIDs []string `hcl:"authorized_spiffe_ids" yaml:"authorizedSpiffeIds"`
}

type StatsdConfig struct {
	Address            string                 `hcl:"address" yaml:"address"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

type M3Config struct {
	Address            string                 `hcl:"address" yaml:"address"`
	Env                string                 `hcl:"env" yaml:"env"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

type InMem struct {
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}
