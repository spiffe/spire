package main

import (
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"
)

const (
	defaultLogLevel = "info"
	defaultAddr     = ":8443"
	defaultCertPath = "cert.pem"
	defaultKeyPath  = "key.pem"
)

type Config struct {
	Log              LogConfig `hcl:"log"`
	Addr             string    `hcl:"addr"`
	CertPath         string    `hcl:"cert_path"`
	KeyPath          string    `hcl:"key_path"`
	TrustDomain      string    `hcl:"trust_domain"`
	ServerSocketPath string    `hcl:"server_socket_path"`
	Cluster          string    `hcl:"cluster"`
	PodLabel         string    `hcl:"pod_label"`
}

type LogConfig struct {
	Path  string `hcl:"path"`
	Level string `hcl:"level"`
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

	if c.Log.Level == "" {
		c.Log.Level = defaultLogLevel
	}
	if c.Addr == "" {
		c.Addr = defaultAddr
	}
	if c.CertPath == "" {
		c.CertPath = defaultCertPath
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

	return c, nil
}
