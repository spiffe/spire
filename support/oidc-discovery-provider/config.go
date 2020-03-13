package main

import (
	"io/ioutil"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"
)

const (
	defaultLogLevel     = "info"
	defaultPollInterval = time.Second * 10
	defaultCacheDir     = "./.acme-cache"
)

type Config struct {
	LogFormat string `hcl:"log_format"`
	LogLevel  string `hcl:"log_level"`
	LogPath   string `hcl:"log_path"`

	// LogRequests is a debug option that logs all incoming requests
	LogRequests bool `hcl:"log_requests"`

	// Domain is the domain this provider will be hosted under. It is used
	// as the domain when building the JWKS URI. It is also used when obtaining
	// obtaining certs via ACME (unless InsecureAddr is specified).
	Domain string

	// InsecureAddr is the insecure HTTP address. When set, the server does not
	// perform ACME to obtain certificates and serves HTTP instead of HTTPS.
	// It is only intended for testing purposes or if the server is
	// going to be deployed behind an HTTPS proxy.
	InsecureAddr string `hcl:"insecure_addr"`

	// ListenSocketPath specifies a unix socket to listen for plaintext HTTP
	// on, for when deployed behind another webserver or sidecar.
	ListenSocketPath string `hcl:"listen_socket_path"`

	// ACME is the ACME configuration. It is required unless InsecureAddr or
	// ListenSocketPath is set.
	ACME *ACMEConfig `hcl:"acme"`

	// RegistrationAPI is the configuration for using the SPIRE Registration
	// API as the source for the public keys. Only one source can be configured.
	RegistrationAPI *RegistrationAPIConfig `hcl:"registration_api"`

	// Workload API is the configuration for using the SPIFFE Workload API
	// as the source for the public keys. Only one source can be configured.
	WorkloadAPI *WorkloadAPIConfig `hcl:"workload_api"`
}

type ACMEConfig struct {
	// DirectoryURL is the ACME directory URL. If unset, the LetsEncrypt
	// directory is used.
	DirectoryURL string `hcl:"directory_url"`

	// Email is the email address used in ACME registration
	Email string `hcl:"email"`

	// ToSAccepted is an explicit indication that the ACME Terms Of Service
	// have been accepted. It MUST be set to true.
	ToSAccepted bool `hcl:"tos_accepted"`

	// Cache is the directory used to cache ACME certificates and private keys.
	// This value is calculated in LoadConfig()/ParseConfig() from RawCacheDir.
	CacheDir string `hcl:"-"`

	// RawCacheDir is used to determine whether the cache was explicitly disabled
	// (by setting to an empty) string. Consumers should use CacheDir instead.
	RawCacheDir *string `hcl:"cache_dir"`
}

type RegistrationAPIConfig struct {
	// SocketPath is the path to the Registration API Unix Domain socket.
	SocketPath string `hcl:"socket_path"`

	// PollInterval controls how frequently the service polls the Registration
	// API for the bundle containing the JWT public keys. This value is calculated
	// by LoadConfig()/ParseConfig() from RawPollInterval.
	PollInterval time.Duration `hcl:"-"`

	// RawPollInterval holds the string version of the PollInterval. Consumers
	// should use PollInterval instead.
	RawPollInterval string `hcl:"poll_interval"`
}

type WorkloadAPIConfig struct {
	// SocketPath is the path to the Workload API Unix Domain socket.
	SocketPath string `hcl:"socket_path"`

	// TrustDomain of the workload. Used to look up the JWT bundle in the
	// Workload API response.
	TrustDomain string `hcl:"trust_domain"`

	// PollInterval controls how frequently the service polls the Registration
	// API for the bundle containing the JWT public keys. This value is calculated
	// by LoadConfig()/ParseConfig() from RawPollInterval.
	PollInterval time.Duration `hcl:"-"`

	// RawPollInterval holds the string version of the PollInterval. Consumers
	// should use PollInterval instead.
	RawPollInterval string `hcl:"poll_interval"`
}

func LoadConfig(path string) (*Config, error) {
	hclBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errs.New("unable to load configuration: %v", err)
	}
	return ParseConfig(string(hclBytes))
}

func ParseConfig(hclConfig string) (_ *Config, err error) {
	c := new(Config)
	if err := hcl.Decode(c, hclConfig); err != nil {
		return nil, errs.New("unable to decode configuration: %v", err)
	}

	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}

	if c.Domain == "" {
		return nil, errs.New("domain must be configured")
	}

	if c.ACME != nil {
		c.ACME.CacheDir = defaultCacheDir
		if c.ACME.RawCacheDir != nil {
			c.ACME.CacheDir = *c.ACME.RawCacheDir
		}
	}

	switch {
	case c.ACME == nil:
		if c.InsecureAddr == "" && c.ListenSocketPath == "" {
			return nil, errs.New("either acme or listen_socket_path must be configured")
		}
		if c.InsecureAddr != "" && c.ListenSocketPath != "" {
			return nil, errs.New("insecure_addr and listen_socket_path are mutually exclusive")
		}
	case c.InsecureAddr != "":
		return nil, errs.New("insecure_addr and the acme section are mutually exclusive")
	case c.ListenSocketPath != "":
		return nil, errs.New("listen_socket_path and the acme section are mutually exclusive")
	case !c.ACME.ToSAccepted:
		return nil, errs.New("tos_accepted must be set to true in the acme configuration section")
	case c.ACME.Email == "":
		return nil, errs.New("email must be configured in the acme configuration section")
	}

	switch {
	case c.RegistrationAPI == nil && c.WorkloadAPI == nil:
		return nil, errs.New("one of registration_api or workload_api section must be configured")
	case c.RegistrationAPI != nil && c.WorkloadAPI != nil:
		return nil, errs.New("registration_api and workload_api configuration sections are mutually exclusive")
	case c.RegistrationAPI != nil:
		if c.RegistrationAPI.SocketPath == "" {
			return nil, errs.New("socket_path must be configured in the registration_api configuration section")
		}
		if c.RegistrationAPI.RawPollInterval != "" {
			c.RegistrationAPI.PollInterval, err = time.ParseDuration(c.RegistrationAPI.RawPollInterval)
			if err != nil {
				return nil, errs.New("invalid poll_interval in the registration_api configuration section: %v", err)
			}
		}
		if c.RegistrationAPI.PollInterval <= 0 {
			c.RegistrationAPI.PollInterval = defaultPollInterval
		}
	case c.WorkloadAPI != nil:
		if c.WorkloadAPI.SocketPath == "" {
			return nil, errs.New("socket_path must be configured in the workload_api configuration section")
		}
		if c.WorkloadAPI.TrustDomain == "" {
			return nil, errs.New("trust_domain must be configured in the workload_api configuration section")
		}
		if c.WorkloadAPI.RawPollInterval != "" {
			c.WorkloadAPI.PollInterval, err = time.ParseDuration(c.WorkloadAPI.RawPollInterval)
			if err != nil {
				return nil, errs.New("invalid poll_interval in the workload_api configuration section: %v", err)
			}
		}
		if c.WorkloadAPI.PollInterval <= 0 {
			c.WorkloadAPI.PollInterval = defaultPollInterval
		}
	}

	return c, nil
}
