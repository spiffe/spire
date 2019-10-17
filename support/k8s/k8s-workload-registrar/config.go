package main

import (
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"
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
	Addr                           string `hcl:"addr"`
	CertPath                       string `hcl:"cert_path"`
	KeyPath                        string `hcl:"key_path"`
	CaCertPath                     string `hcl:"cacert_path"`
	InsecureSkipClientVerification bool   `hcl:"insecure_skip_client_verification"`
	TrustDomain                    string `hcl:"trust_domain"`
	ServerSocketPath               string `hcl:"server_socket_path"`
	Cluster                        string `hcl:"cluster"`
	PodLabel                       string `hcl:"pod_label"`
	PodAnnotation                  string `hcl:"pod_annotation"`
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

	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
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
	if c.ServerSocketPath == "" {
		return nil, errs.New("server_socket_path must be specified")
	}
	if c.TrustDomain == "" {
		return nil, errs.New("trust_domain must be specified")
	}
	if c.Cluster == "" {
		return nil, errs.New("cluster must be specified")
	}
	if c.PodLabel != "" && c.PodAnnotation != "" {
		return nil, errs.New("workload registration mode specification is incorrect, can't specify both pod_label and pod_annotation")
	}

	return c, nil
}
