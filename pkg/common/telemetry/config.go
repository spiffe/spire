package telemetry

import (
	"github.com/sirupsen/logrus"
	"time"
)

type MetricsConfig struct {
	FileConfig       FileConfig
	Logger           logrus.FieldLogger
	ServiceName      string
	Sinks            []Sink
	TimerGranularity time.Duration
}

type MetricsConfigBuilder struct {
	MetricsConfig
	timerGranularitySet bool
}

func (mcb *MetricsConfigBuilder) SetFileConfig(fileConfig FileConfig) {
	mcb.MetricsConfig.FileConfig = fileConfig
}

func (mcb *MetricsConfigBuilder) SetLogger(logger logrus.FieldLogger) {
	mcb.MetricsConfig.Logger = logger
}

func (mcb *MetricsConfigBuilder) SetServiceName(serviceName string) {
	mcb.MetricsConfig.ServiceName = serviceName
}

func (mcb *MetricsConfigBuilder) SetSinks(sinks []Sink) {
	mcb.MetricsConfig.Sinks = sinks
}

func (mcb *MetricsConfigBuilder) SetTimerGranularity(timerGranularity time.Duration) {
	mcb.MetricsConfig.TimerGranularity = timerGranularity
	mcb.timerGranularitySet = true
}

func (mcb *MetricsConfigBuilder) Build() MetricsConfig {
	if !mcb.timerGranularitySet {
		mcb.MetricsConfig.TimerGranularity = time.Millisecond
	}

	return mcb.MetricsConfig
}

type FileConfig struct {
	EnableTypePrefix  bool              `hcl:"EnableTypePrefix"`
	Prometheus        *PrometheusConfig `hcl:"Prometheus"`
	DogStatsd         []DogStatsdConfig `hcl:"DogStatsd"`
	Statsd            []StatsdConfig    `hcl:"Statsd"`
	M3                []M3Config        `hcl:"M3"`
}

type DogStatsdConfig struct {
	Address string `hcl:"address"`
}

type PrometheusConfig struct {
	Host string `hcl:"host"`
	Port int    `hcl:"port"`
}

type StatsdConfig struct {
	Address string `hcl:"address"`
}

type M3Config struct {
	Address string `hcl:"address"`
	Env     string `hcl:"env"`
}
