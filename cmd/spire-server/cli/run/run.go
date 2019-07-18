package run

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/imdario/mergo"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server"
	bundleClient "github.com/spiffe/spire/pkg/server/bundle/client"
)

const (
	defaultConfigPath         = "conf/server/server.conf"
	defaultSocketPath         = "/tmp/spire-registration.sock"
	defaultLogLevel           = "INFO"
	defaultBundleEndpointPort = 443
)

// config contains all available configurables, arranged by section
type config struct {
	Server    *serverConfig               `hcl:"server"`
	Plugins   *catalog.HCLPluginConfigMap `hcl:"plugins"`
	Telemetry telemetry.FileConfig        `hcl:"telemetry"`
}

type serverConfig struct {
	BindAddress         string             `hcl:"bind_address"`
	BindPort            int                `hcl:"bind_port"`
	CASubject           *caSubjectConfig   `hcl:"ca_subject"`
	CATTL               string             `hcl:"ca_ttl"`
	DataDir             string             `hcl:"data_dir"`
	Experimental        experimentalConfig `hcl:"experimental"`
	LogFile             string             `hcl:"log_file"`
	LogLevel            string             `hcl:"log_level"`
	LogFormat           string             `hcl:"log_format"`
	RegistrationUDSPath string             `hcl:"registration_uds_path"`
	SVIDTTL             string             `hcl:"svid_ttl"`
	TrustDomain         string             `hcl:"trust_domain"`
	UpstreamBundle      bool               `hcl:"upstream_bundle"`

	ConfigPath string

	// Undocumented configurables
	ProfilingEnabled bool     `hcl:"profiling_enabled"`
	ProfilingPort    int      `hcl:"profiling_port"`
	ProfilingFreq    int      `hcl:"profiling_freq"`
	ProfilingNames   []string `hcl:"profiling_names"`
}

type experimentalConfig struct {
	AllowAgentlessNodeAttestors bool `hcl:"allow_agentless_node_attestors"`

	BundleEndpointEnabled bool                           `hcl:"bundle_endpoint_enabled"`
	BundleEndpointAddress string                         `hcl:"bundle_endpoint_address"`
	BundleEndpointPort    int                            `hcl:"bundle_endpoint_port"`
	FederatesWith         map[string]federatesWithConfig `hcl:"federates_with"`
}

type caSubjectConfig struct {
	Country      []string `hcl:"country"`
	Organization []string `hcl:"organization"`
	CommonName   string   `hcl:"common_name"`
}

type federatesWithConfig struct {
	BundleEndpointAddress  string `hcl:"bundle_endpoint_address"`
	BundleEndpointPort     int    `hcl:"bundle_endpoint_port"`
	BundleEndpointSpiffeID string `hcl:"bundle_endpoint_spiffe_id"`
}

// Run CLI struct
type RunCLI struct{}

//Help prints the server cmd usage
func (*RunCLI) Help() string {
	_, err := parseFlags([]string{"-h"})
	return err.Error()
}

// Run the SPIFFE Server
func (*RunCLI) Run(args []string) int {
	// First parse the CLI flags so we can get the config
	// file path, if set
	cliInput, err := parseFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// Load and parse the config file using either the default
	// path or CLI-specified value
	fileInput, err := parseFile(cliInput.ConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	input, err := mergeInput(fileInput, cliInput)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	c, err := newServerConfig(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// Set umask before starting up the server
	cli.SetUmask(c.Log)

	s := server.New(*c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	util.SignalListener(ctx, cancel)

	err = s.Run(ctx)
	if err != nil {
		c.Log.WithError(err).Error("server crashed")
		return 1
	}

	c.Log.Info("Server stopped gracefully")
	return 0
}

//Synopsis of the command
func (*RunCLI) Synopsis() string {
	return "Runs the server"
}

func parseFile(path string) (*config, error) {
	c := &config{}

	if path == "" {
		path = defaultConfigPath
	}

	// Return a friendly error if the file is missing
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			msg := "could not determine CWD; config file not found at %s: use -config"
			return nil, fmt.Errorf(msg, path)
		}

		msg := "could not find config file %s: please use the -config flag"
		return nil, fmt.Errorf(msg, absPath)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to read configuration at %q: %v", path, err)
	}

	if err := hcl.Decode(&c, string(data)); err != nil {
		return nil, fmt.Errorf("unable to decode configuration %q: %v", path, err)
	}

	return c, nil
}

func parseFlags(args []string) (*serverConfig, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &serverConfig{}

	flags.StringVar(&c.BindAddress, "bindAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.BindPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.StringVar(&c.ConfigPath, "config", "", "Path to a SPIRE config file")
	flags.StringVar(&c.DataDir, "dataDir", "", "Directory to store runtime data to")
	flags.StringVar(&c.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.LogFormat, "logFormat", "", "'text' or 'json'")
	flags.StringVar(&c.LogLevel, "logLevel", "", "'debug', 'info', 'warn', or 'error'")
	flags.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", "", "UDS Path to bind registration API")
	flags.StringVar(&c.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.BoolVar(&c.UpstreamBundle, "upstreamBundle", false, "Include upstream CA certificates in the bundle")

	err := flags.Parse(args)
	if err != nil {
		return c, err
	}

	return c, nil
}

func mergeInput(fileInput *config, cliInput *serverConfig) (*config, error) {
	c := &config{Server: &serverConfig{}}

	// Highest precedence first
	err := mergo.Merge(c.Server, cliInput)
	if err != nil {
		return nil, err
	}

	err = mergo.Merge(c, fileInput)
	if err != nil {
		return nil, err
	}

	err = mergo.Merge(c, defaultConfig())
	if err != nil {
		return nil, err
	}

	return c, nil
}

func newServerConfig(c *config) (*server.Config, error) {
	sc := &server.Config{}

	if err := validateConfig(c); err != nil {
		return nil, err
	}

	ip := net.ParseIP(c.Server.BindAddress)
	if ip == nil {
		return nil, fmt.Errorf("could not parse bind_adress %q", c.Server.BindAddress)
	}
	sc.BindAddress = &net.TCPAddr{
		IP:   ip,
		Port: c.Server.BindPort,
	}

	sc.BindUDSAddress = &net.UnixAddr{
		Name: c.Server.RegistrationUDSPath,
		Net:  "unix",
	}

	sc.DataDir = c.Server.DataDir

	td, err := idutil.ParseSpiffeID("spiffe://"+c.Server.TrustDomain, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, fmt.Errorf("could not parse trust_domain %q: %v", c.Server.TrustDomain, err)
	}
	sc.TrustDomain = *td

	ll := strings.ToUpper(c.Server.LogLevel)
	lf := strings.ToUpper(c.Server.LogFormat)
	logger, err := log.NewLogger(ll, lf, c.Server.LogFile)
	if err != nil {
		return nil, fmt.Errorf("could not start logger: %s", err)
	}
	sc.Log = logger

	sc.UpstreamBundle = c.Server.UpstreamBundle
	sc.Experimental.AllowAgentlessNodeAttestors = c.Server.Experimental.AllowAgentlessNodeAttestors
	sc.Experimental.BundleEndpointEnabled = c.Server.Experimental.BundleEndpointEnabled
	sc.Experimental.BundleEndpointAddress = &net.TCPAddr{
		IP:   net.ParseIP(c.Server.Experimental.BundleEndpointAddress),
		Port: c.Server.Experimental.BundleEndpointPort,
	}

	federatesWith := map[string]bundleClient.TrustDomainConfig{}
	for trustDomain, config := range c.Server.Experimental.FederatesWith {
		port := defaultBundleEndpointPort
		if config.BundleEndpointPort != 0 {
			port = config.BundleEndpointPort
		}

		federatesWith[trustDomain] = bundleClient.TrustDomainConfig{
			EndpointAddress:  fmt.Sprintf("%s:%d", config.BundleEndpointAddress, port),
			EndpointSpiffeID: config.BundleEndpointSpiffeID,
		}
	}
	sc.Experimental.FederatesWith = federatesWith

	sc.ProfilingEnabled = c.Server.ProfilingEnabled
	sc.ProfilingPort = c.Server.ProfilingPort
	sc.ProfilingFreq = c.Server.ProfilingFreq
	sc.ProfilingNames = c.Server.ProfilingNames

	if c.Server.SVIDTTL != "" {
		ttl, err := time.ParseDuration(c.Server.SVIDTTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse default SVID ttl %q: %v", c.Server.SVIDTTL, err)
		}
		sc.SVIDTTL = ttl
	}

	if c.Server.CATTL != "" {
		ttl, err := time.ParseDuration(c.Server.CATTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse default CA ttl %q: %v", c.Server.CATTL, err)
		}
		sc.CATTL = ttl
	}

	if subject := c.Server.CASubject; subject != nil {
		sc.CASubject = pkix.Name{
			Organization: subject.Organization,
			Country:      subject.Country,
			CommonName:   subject.CommonName,
		}
	}

	sc.PluginConfigs = *c.Plugins
	sc.Telemetry = c.Telemetry

	return sc, nil
}

func validateConfig(c *config) error {
	if c.Server == nil {
		return errors.New("server section must be configured")
	}

	if c.Server.BindAddress == "" || c.Server.BindPort == 0 {
		return errors.New("bind_address and bind_port must be configured")
	}

	if c.Server.RegistrationUDSPath == "" {
		return errors.New("registration_uds_path must be configured")
	}

	if c.Server.TrustDomain == "" {
		return errors.New("trust_domain must be configured")
	}

	if c.Server.DataDir == "" {
		return errors.New("data_dir must be configured")
	}

	if c.Plugins == nil {
		return errors.New("plugins section must be configured")
	}

	for td, tdConfig := range c.Server.Experimental.FederatesWith {
		if tdConfig.BundleEndpointAddress == "" {
			return fmt.Errorf("%s bundle_endpoint_address must be configured", td)
		}
	}

	return nil
}

func defaultConfig() *config {
	return &config{
		Server: &serverConfig{
			BindAddress:         "0.0.0.0",
			BindPort:            8081,
			LogLevel:            defaultLogLevel,
			LogFormat:           log.DefaultFormat,
			RegistrationUDSPath: defaultSocketPath,
			Experimental: experimentalConfig{
				BundleEndpointAddress: "0.0.0.0",
				BundleEndpointPort:    defaultBundleEndpointPort,
			},
		},
	}
}
