package telemetry

import (
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/sirupsen/logrus"
)

type MetricsConfig struct {
	FileConfig  FileConfig
	Logger      logrus.FieldLogger
	ServiceName string
	Sinks       []Sink
	TrustDomain string
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
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
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
