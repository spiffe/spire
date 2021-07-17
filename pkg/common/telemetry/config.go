package telemetry

import (
	"github.com/sirupsen/logrus"
)

type MetricsConfig struct {
	FileConfig  FileConfig
	Logger      logrus.FieldLogger
	ServiceName string
	Sinks       []Sink
}

type MetricsConfigOptions struct {
	AllowedPrefixes []string // A list of metric prefixes to allow, with '.' as the separator
	BlockedPrefixes []string // A list of metric prefixes to block, with '.' as the separator
	AllowedLabels   []string // A list of metric labels to allow, with '.' as the separator
	BlockedLabels   []string // A list of metric labels to block, with '.' as the separator
}

type FileConfig struct {
	Options    MetricsConfigOptions
	Prometheus *PrometheusConfig `hcl:"Prometheus"`
	DogStatsd  []DogStatsdConfig `hcl:"DogStatsd"`
	Statsd     []StatsdConfig    `hcl:"Statsd"`
	M3         []M3Config        `hcl:"M3"`
	InMem      *InMem            `hcl:"InMem"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type DogStatsdConfig struct {
	Address    string   `hcl:"address"`
	UnusedKeys []string `hcl:",unusedKeys"`
}

type PrometheusConfig struct {
	Host       string   `hcl:"host"`
	Port       int      `hcl:"port"`
	UnusedKeys []string `hcl:",unusedKeys"`
}

type StatsdConfig struct {
	Address    string   `hcl:"address"`
	UnusedKeys []string `hcl:",unusedKeys"`
}

type M3Config struct {
	Address    string   `hcl:"address"`
	Env        string   `hcl:"env"`
	UnusedKeys []string `hcl:",unusedKeys"`
}

type InMem struct {
	Enabled    *bool    `hcl:"enabled"`
	UnusedKeys []string `hcl:",unusedKeys"`
}
