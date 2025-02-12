package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/config"
)

const (
	defaultLogLevel              = "info"
	defaultPollInterval          = time.Second * 10
	defaultFileSyncInterval      = time.Minute
	defaultCacheDir              = "./.acme-cache"
	defaultHealthChecksBindPort  = 8008
	defaultHealthChecksReadyPath = "/ready"
	defaultHealthChecksLivePath  = "/live"
	defaultAddr                  = ":443"
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
	// ListenSocketPath is set, or if ServingCertFile is used.
	ACME *ACMEConfig `hcl:"acme"`

	// ServingCertFile is the configuration for using a serving certificate to serve HTTPS.
	// It is required unless InsecureAddr or ListenSocketPath is set, or if ACME configuration is used.
	ServingCertFile *ServingCertFileConfig `hcl:"serving_cert_file"`

	// ServerAPI is the configuration for using the SPIRE Server API as the
	// source for the public keys. Only one source can be configured.
	ServerAPI *ServerAPIConfig `hcl:"server_api"`

	// Workload API is the configuration for using the SPIFFE Workload API
	// as the source for the public keys. Only one source can be configured.
	WorkloadAPI *WorkloadAPIConfig `hcl:"workload_api"`

	// Health checks enable Liveness and Readiness probes.
	HealthChecks *HealthChecksConfig `hcl:"health_checks"`

	// Experimental options that are subject to change or removal.
	Experimental experimentalConfig `hcl:"experimental"`

	// JWTIssuer specifies the issuer for the OIDC provider configuration request.
	JWTIssuer string `hcl:"jwt_issuer"`

	// JWKSURI specifies the absolute uri to the jwks keys document. Use this if you are fronting the
	// discovery provider with a load balancer or reverse proxy
	JWKSURI string `hcl:"jwks_uri"`

	// ServerPathPrefix specifies the prefix to strip from the path of requests to route to the server.
	// Example: if ServerPathPrefix is /foo then a request to http://127.0.0.1/foo/.well-known/openid-configuration and
	// http://127.0.0.1/foo/keys will function with the server.
	ServerPathPrefix string `hcl:"server_path_prefix"`
}

type ServingCertFileConfig struct {
	// CertFilePath is the path to the certificate file. The provider will watch
	// this file for changes and reload the certificate when it changes.
	CertFilePath string `hcl:"cert_file_path"`
	// KeyFilePath is the path to the private key file. The provider will watch
	// this file for changes and reload the key when it changes.
	KeyFilePath string `hcl:"key_file_path"`
	// Addr is the address to listen on. This is optional and defaults to ":443".
	Addr *net.TCPAddr `hcl:"-"`
	// RawAddr holds the string version of the Addr. Consumers should use Addr instead.
	RawAddr string `hcl:"addr"`
	// FileSyncInterval controls how frequently the service polls the certificate for changes.
	FileSyncInterval time.Duration `hcl:"-"`
	// RawFileSyncInterval holds the string version of the FileSyncInterval. Consumers
	// should use FileSyncInterval instead.
	RawFileSyncInterval string `hcl:"file_sync_interval"`
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

type HealthChecksConfig struct {
	// Listener port binding
	BindPort int `hcl:"bind_port"`
	// Paths for /ready and /live
	LivePath  string `hcl:"live_path"`
	ReadyPath string `hcl:"ready_path"`
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

func LoadConfig(path string, expandEnv bool) (*Config, error) {
	hclBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to load configuration: %w", err)
	}
	hclString := string(hclBytes)
	if expandEnv {
		hclString = config.ExpandEnv(hclString)
	}
	return ParseConfig(hclString)
}

func ParseConfig(hclConfig string) (_ *Config, err error) {
	c := new(Config)
	if err := hcl.Decode(c, hclConfig); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %w", err)
	}

	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}

	if len(c.Domains) == 0 {
		return nil, errors.New("at least one domain must be configured")
	}
	c.Domains = dedupeList(c.Domains)

	if c.ACME != nil {
		c.ACME.CacheDir = defaultCacheDir
		if c.ACME.RawCacheDir != nil {
			c.ACME.CacheDir = *c.ACME.RawCacheDir
		}
		switch {
		case c.InsecureAddr != "":
			return nil, errors.New("insecure_addr and the acme section are mutually exclusive")
		case !c.ACME.ToSAccepted:
			return nil, errors.New("tos_accepted must be set to true in the acme configuration section")
		case c.ACME.Email == "":
			return nil, errors.New("email must be configured in the acme configuration section")
		}
	}

	if c.ServingCertFile != nil {
		if c.ServingCertFile.CertFilePath == "" {
			return nil, errors.New("cert_file_path must be configured in the serving_cert_file configuration section")
		}
		if c.ServingCertFile.KeyFilePath == "" {
			return nil, errors.New("key_file_path must be configured in the serving_cert_file configuration section")
		}

		if c.ServingCertFile.RawAddr == "" {
			c.ServingCertFile.RawAddr = defaultAddr
		}

		addr, err := net.ResolveTCPAddr("tcp", c.ServingCertFile.RawAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid addr in the serving_cert_file configuration section: %w", err)
		}
		c.ServingCertFile.Addr = addr

		c.ServingCertFile.FileSyncInterval, err = parseDurationField(c.ServingCertFile.RawFileSyncInterval, defaultFileSyncInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid file_sync_interval in the serving_cert_file configuration section: %w", err)
		}
	}

	var methodCount int

	if c.ServerAPI != nil {
		c.ServerAPI.PollInterval, err = parseDurationField(c.ServerAPI.RawPollInterval, defaultPollInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid poll_interval in the server_api configuration section: %w", err)
		}
		methodCount++
	}

	if c.WorkloadAPI != nil {
		if c.WorkloadAPI.TrustDomain == "" {
			return nil, errors.New("trust_domain must be configured in the workload_api configuration section")
		}
		c.WorkloadAPI.PollInterval, err = parseDurationField(c.WorkloadAPI.RawPollInterval, defaultPollInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid poll_interval in the workload_api configuration section: %w", err)
		}
		methodCount++
	}

	if c.HealthChecks != nil {
		if c.HealthChecks.BindPort <= 0 {
			c.HealthChecks.BindPort = defaultHealthChecksBindPort
		}
		if c.HealthChecks.ReadyPath == "" {
			c.HealthChecks.ReadyPath = defaultHealthChecksReadyPath
		}
		if c.HealthChecks.LivePath == "" {
			c.HealthChecks.LivePath = defaultHealthChecksLivePath
		}
	}

	if err := c.validateOS(); err != nil {
		return nil, err
	}

	switch methodCount {
	case 0:
		return nil, errors.New("either the server_api or workload_api section must be configured")
	case 1:
	default:
		return nil, errors.New("the server_api and workload_api sections are mutually exclusive")
	}
	if c.JWTIssuer != "" {
		jwtIssuer, err := url.Parse(c.JWTIssuer)
		switch {
		case err != nil:
			return nil, fmt.Errorf("the jwt_issuer url could not be parsed: %w", err)
		case jwtIssuer.Scheme == "":
			return nil, errors.New("the jwt_issuer url must contain a scheme")
		case jwtIssuer.Host == "":
			return nil, errors.New("the jwt_issuer url must contain a host")
		}
	}
	if c.JWKSURI != "" {
		jwksURI, err := url.Parse(c.JWKSURI)
		if err != nil || jwksURI.Scheme == "" || jwksURI.Host == "" {
			return nil, fmt.Errorf("the jwks_uri setting could not be parsed: %w", err)
		}
	}
	if c.JWKSURI == "" && c.JWTIssuer != "" {
		fmt.Printf("Warning: The jwt_issuer configuration will also affect the jwks_uri behavior when jwks_url is not set. This behaviour will be changed in 1.13.0.")
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

func parseDurationField(rawValue string, defaultValue time.Duration) (duration time.Duration, err error) {
	if rawValue != "" {
		duration, err = time.ParseDuration(rawValue)
		if err != nil {
			return 0, err
		}
	}
	if duration <= 0 {
		duration = defaultValue
	}
	return duration, nil
}
