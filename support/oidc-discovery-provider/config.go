package main

import (
	"os"
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

	// Domains are the domains this provider will be hosted under. Incoming requests
	// that are not received on (or proxied through) one of the domains specified by this list
	// are rejected.
	Domains []string `hcl:"domains"`

	// Set the 'use' field on all keys. Required for some non-conformant JWKS clients.
	SetKeyUse bool `hcl:"set_key_use"`

	// AllowInsecureScheme, if true, causes HTTP URLs to be rendered in the
	// returned discovery document. This option should only be used for testing purposes as HTTP does
	// not provide the security guarantees necessary for conveying trusted public key material. In general this
	// option is only appropriate for a local development environment.
	// Do NOT use this in online or production environments.
	// This option only takes effect when used alongside the InsecureAddr or ListenSocketPath option.
	AllowInsecureScheme bool `hcl:"allow_insecure_scheme"`

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

	// ServerAPI is the configuration for using the SPIRE Server API as the
	// source for the public keys. Only one source can be configured.
	ServerAPI *ServerAPIConfig `hcl:"server_api"`

	// Workload API is the configuration for using the SPIFFE Workload API
	// as the source for the public keys. Only one source can be configured.
	WorkloadAPI *WorkloadAPIConfig `hcl:"workload_api"`

	// Experimental options that are subject to change or removal.
	Experimental experimentalConfig `hcl:"experimental"`
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

type ServerAPIConfig struct {
	// Address is the target address of the SPIRE Server API as defined in
	// https://github.com/grpc/grpc/blob/master/doc/naming.md. Only the unix
	// name system is supported.
	Address string `hcl:"address"`

	// PollInterval controls how frequently the service polls the Server API
	// for the bundle containing the JWT public keys. This value is calculated
	// by LoadConfig()/ParseConfig() from RawPollInterval.
	PollInterval time.Duration `hcl:"-"`

	// RawPollInterval holds the string version of the PollInterval. Consumers
	// should use PollInterval instead.
	RawPollInterval string `hcl:"poll_interval"`

	// Experimental options that are subject to change or removal.
	Experimental experimentalServerAPIConfig `hcl:"experimental"`
}

type WorkloadAPIConfig struct {
	// SocketPath is the path to the Workload API Unix Domain socket.
	SocketPath string `hcl:"socket_path"`

	// TrustDomain of the workload. Used to look up the JWT bundle in the
	// Workload API response.
	TrustDomain string `hcl:"trust_domain"`

	// PollInterval controls how frequently the service polls the Workload
	// API for the bundle containing the JWT public keys. This value is calculated
	// by LoadConfig()/ParseConfig() from RawPollInterval.
	PollInterval time.Duration `hcl:"-"`

	// RawPollInterval holds the string version of the PollInterval. Consumers
	// should use PollInterval instead.
	RawPollInterval string `hcl:"poll_interval"`

	// Experimental options that are subject to change or removal.
	Experimental experimentalWorkloadAPIConfig `hcl:"experimental"`
}

type experimentalConfig struct {
	// ListenNamedPipeName specifies the pipe name of the named pipe
	// to listen for plaintext HTTP on, for when deployed behind another
	// webserver or sidecar.
	ListenNamedPipeName string `hcl:"listen_named_pipe_name" json:"listen_named_pipe_name"`
}

type experimentalServerAPIConfig struct {
	// Pipe name of the Server API named pipe.
	NamedPipeName string `hcl:"named_pipe_name" json:"named_pipe_name"`
}

type experimentalWorkloadAPIConfig struct {
	// Pipe name of the Workload API named pipe.
	NamedPipeName string `hcl:"named_pipe_name" json:"named_pipe_name"`
}

func LoadConfig(path string) (*Config, error) {
	hclBytes, err := os.ReadFile(path)
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

	if len(c.Domains) == 0 {
		return nil, errs.New("at least one domain must be configured")
	}
	c.Domains = dedupeList(c.Domains)

	if c.ACME != nil {
		c.ACME.CacheDir = defaultCacheDir
		if c.ACME.RawCacheDir != nil {
			c.ACME.CacheDir = *c.ACME.RawCacheDir
		}
	}

	switch {
	case c.ACME != nil && c.InsecureAddr != "":
		return nil, errs.New("insecure_addr and the acme section are mutually exclusive")
	case c.ACME != nil && !c.ACME.ToSAccepted:
		return nil, errs.New("tos_accepted must be set to true in the acme configuration section")
	case c.ACME != nil && c.ACME.Email == "":
		return nil, errs.New("email must be configured in the acme configuration section")
	}

	var methodCount int

	if c.ServerAPI != nil {
		c.ServerAPI.PollInterval, err = parsePollInterval(c.ServerAPI.RawPollInterval)
		if err != nil {
			return nil, errs.New("invalid poll_interval in the server_api configuration section: %v", err)
		}
		methodCount++
	}

	if c.WorkloadAPI != nil {
		if c.WorkloadAPI.TrustDomain == "" {
			return nil, errs.New("trust_domain must be configured in the workload_api configuration section")
		}
		c.WorkloadAPI.PollInterval, err = parsePollInterval(c.WorkloadAPI.RawPollInterval)
		if err != nil {
			return nil, errs.New("invalid poll_interval in the workload_api configuration section: %v", err)
		}
		methodCount++
	}

	if err := c.validateOS(); err != nil {
		return nil, err
	}

	switch methodCount {
	case 0:
		return nil, errs.New("either the server_api or workload_api section must be configured")
	case 1:
	default:
		return nil, errs.New("the server_api and workload_api sections are mutually exclusive")
	}

	return c, nil
}

func dedupeList(items []string) []string {
	keys := make(map[string]bool)
	var list []string

	for _, s := range items {
		if _, ok := keys[s]; !ok {
			keys[s] = true
			list = append(list, s)
		}
	}

	return list
}

func parsePollInterval(rawPollInterval string) (pollInterval time.Duration, err error) {
	if rawPollInterval != "" {
		pollInterval, err = time.ParseDuration(rawPollInterval)
		if err != nil {
			return 0, err
		}
	}
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	return pollInterval, nil
}
