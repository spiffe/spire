package main

import (
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultLogLevel   = "info"
	defaultAddr       = ":8443"
	defaultCertPath   = "cert.pem"
	defaultKeyPath    = "key.pem"
	defaultCaCertPath = "cacert.pem"
)

type Config struct {
	LogFormat                      string `hcl:"log_format"`
	LogLevel                       string `hcl:"log_level"`
	LogPath                        string `hcl:"log_path"`
	Addr                           string `hcl:"addr" mode:"admission"`
	CertPath                       string `hcl:"cert_path" mode:"admission"`
	KeyPath                        string `hcl:"key_path" mode:"admission"`
	CaCertPath                     string `hcl:"cacert_path" mode:"admission"`
	InsecureSkipClientVerification bool   `hcl:"insecure_skip_client_verification" mode:"admission"`
	TrustDomain                    string `hcl:"trust_domain"`
	ServerSocketPath               string `hcl:"server_socket_path"`
	Cluster                        string `hcl:"cluster"`
	PodLabel                       string `hcl:"pod_label"`
	PodAnnotation                  string `hcl:"pod_annotation"`
	Mode                           string `hcl:"mode"`
	InformerResyncInterval         string `hcl:"informer_resync_interval" mode:"informer"`
	KubeConfig                     string `hcl:"kubeconfig" mode:"informer"`
}

func LoadConfig(path string) (*Config, error) {
	hclBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errs.New("unable to load configuration: %v", err)
	}
	return ParseConfig(string(hclBytes))
}

func ParseConfig(hclConfig string) (*Config, error) {
	c := new(Config)
	if err := hcl.Decode(c, hclConfig); err != nil {
		return nil, errs.New("unable to decode configuration: %v", err)
	}

	if c.Mode == "" {
		c.Mode = "admission"
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	c.setDefault()

	return c, nil
}

func (c *Config) validate() error {
	var errGroup errs.Group

	switch c.Mode {
	case "admission":
	case "informer":
		// Note that time.ParseDuration does not accept "" as zero
		if c.InformerResyncInterval != "" {
			if _, err := time.ParseDuration(c.InformerResyncInterval); err != nil {
				errGroup.Add(errs.New("invalid informer_resync_interval %s: %v", c.InformerResyncInterval, err))
			}
		}
	default:
		errGroup.Add(errs.New("invalid mode %s", c.Mode))
	}

	// Validate the 'mode' tag on the struct: can only be set in this mode
	v := reflect.Indirect(reflect.ValueOf(c))
	ty := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		fty := ty.Field(i)

		if f.IsZero() {
			// Unset fields are okay
			continue
		}

		name := fty.Name
		if hclName, ok := fty.Tag.Lookup("hcl"); ok {
			name = hclName
		}
		if mode, ok := fty.Tag.Lookup("mode"); ok {
			if c.Mode != mode {
				errGroup.Add(errs.New("%s not valid in %s mode", name, c.Mode))
			}
		}
	}

	if c.ServerSocketPath == "" {
		errGroup.Add(errs.New("server_socket_path must be specified"))
	}
	if c.TrustDomain == "" {
		errGroup.Add(errs.New("trust_domain must be specified"))
	}
	if c.Cluster == "" {
		errGroup.Add(errs.New("cluster must be specified"))
	}
	if c.PodLabel != "" && c.PodAnnotation != "" {
		errGroup.Add(errs.New("workload registration mode specification is incorrect, can't specify both pod_label and pod_annotation"))
	}

	return errGroup.Err()
}

func (c *Config) setDefault() {
	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}

	switch c.Mode {
	case "admission":
		if c.Addr == "" {
			c.Addr = defaultAddr
		}
		if c.CertPath == "" {
			c.CertPath = defaultCertPath
		}
		if c.CaCertPath == "" {
			c.CaCertPath = defaultCaCertPath
		}
		if c.KeyPath == "" {
			c.KeyPath = defaultKeyPath
		}
	case "informer":
		if c.KubeConfig == "" {
			// If this environment variable (KUBECONFIG) is set, it is the default
			c.KubeConfig = os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
		}
		if c.InformerResyncInterval == "" {
			c.InformerResyncInterval = "0"
		}
	default:
	}
}
