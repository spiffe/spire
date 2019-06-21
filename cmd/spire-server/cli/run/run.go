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
	"time"

	"github.com/hashicorp/hcl"
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

// runConfig represents available configurables for file and CLI options
type runConfig struct {
	Server        serverRunConfig            `hcl:"server"`
	PluginConfigs catalog.HCLPluginConfigMap `hcl:"plugins"`
	Telemetry     telemetry.FileConfig       `hcl:"telemetry"`
}

type serverRunConfig struct {
	BindAddress         string             `hcl:"bind_address"`
	BindPort            int                `hcl:"bind_port"`
	CASubject           *caSubjectConfig   `hcl:"ca_subject"`
	CATTL               string             `hcl:"ca_ttl"`
	DataDir             string             `hcl:"data_dir"`
	LogFile             string             `hcl:"log_file"`
	LogLevel            string             `hcl:"log_level"`
	LogFormat           string             `hcl:"log_format"`
	RegistrationUDSPath string             `hcl:"registration_uds_path"`
	SVIDTTL             string             `hcl:"svid_ttl"`
	TrustDomain         string             `hcl:"trust_domain"`
	UpstreamBundle      bool               `hcl:"upstream_bundle"`
	Experimental        experimentalConfig `hcl:"experimental"`

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

type serverConfig struct {
	server.Config
}

// Run CLI struct
type RunCLI struct {
}

//Help prints the server cmd usage
func (*RunCLI) Help() string {
	_, err := parseFlags([]string{"-h"})
	return err.Error()
}

//Run the SPIFFE Server
func (*RunCLI) Run(args []string) int {
	cliConfig, err := parseFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fileConfig, err := parseFile(cliConfig.Server.ConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	c := newDefaultConfig()

	// Get the plugin and telemetry configurations from the file
	c.PluginConfigs = fileConfig.PluginConfigs
	c.Telemetry = fileConfig.Telemetry

	err = mergeConfigs(c, fileConfig, cliConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	err = validateConfig(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// set umask before starting up the server
	cli.SetUmask(c.Log)

	s := server.New(c.Config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	util.SignalListener(ctx, cancel)

	err = s.Run(ctx)
	if err != nil {
		c.Log.Error(err.Error())
		return 1
	}

	return 0
}

//Synopsis of the command
func (*RunCLI) Synopsis() string {
	return "Runs the server"
}

func parseFile(filePath string) (*runConfig, error) {
	c := &runConfig{}
	// Return a friendly error if the file is missing
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		msg := "could not find config file %s: please use the -config flag"
		p, err := filepath.Abs(filePath)
		if err != nil {
			p = filePath
			msg = "could not determine CWD; config file not found at %s: use -config"
		}
		return nil, fmt.Errorf(msg, p)
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read configuration: %v", err)
	}
	if err := hcl.Decode(&c, string(data)); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %v", err)
	}

	return c, nil
}

func parseFlags(args []string) (*runConfig, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &runConfig{}

	flags.StringVar(&c.Server.BindAddress, "bindAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.Server.BindPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.StringVar(&c.Server.RegistrationUDSPath, "registrationUDSPath", "", "UDS Path to bind registration API")
	flags.StringVar(&c.Server.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.StringVar(&c.Server.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.Server.LogLevel, "logLevel", "", "'debug', 'info', 'warn', or 'error'")
	flags.StringVar(&c.Server.LogFormat, "logFormat", "", "'text' or 'json'")
	flags.StringVar(&c.Server.DataDir, "dataDir", "", "Directory to store runtime data to")
	flags.StringVar(&c.Server.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.BoolVar(&c.Server.UpstreamBundle, "upstreamBundle", false, "Include upstream CA certificates in the bundle")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func mergeConfigs(c *serverConfig, fileConfig, cliConfig *runConfig) error {
	// CLI > File, merge fileConfig first
	err := mergeConfig(c, fileConfig)
	if err != nil {
		return err
	}

	return mergeConfig(c, cliConfig)
}

func mergeConfig(orig *serverConfig, cmd *runConfig) error {
	// Parse server address
	if cmd.Server.BindAddress != "" {
		ip := net.ParseIP(cmd.Server.BindAddress)
		if ip == nil {
			return fmt.Errorf("It was not possible to parse BindAdress: %v", cmd.Server.BindAddress)
		}
		orig.BindAddress.IP = ip
	}

	if cmd.Server.RegistrationUDSPath != "" {
		orig.BindUDSAddress.Name = cmd.Server.RegistrationUDSPath
	}

	if cmd.Server.BindPort != 0 {
		orig.BindAddress.Port = cmd.Server.BindPort
	}

	if cmd.Server.DataDir != "" {
		orig.DataDir = cmd.Server.DataDir
	}

	if cmd.Server.TrustDomain != "" {
		trustDomain, err := idutil.ParseSpiffeID("spiffe://"+cmd.Server.TrustDomain, idutil.AllowAnyTrustDomain())
		if err != nil {
			return err
		}
		orig.TrustDomain = *trustDomain
	}

	// Handle log file and level
	if cmd.Server.LogFile != "" || cmd.Server.LogLevel != "" || cmd.Server.LogFormat != "" {
		logLevel := defaultLogLevel
		if cmd.Server.LogLevel != "" {
			logLevel = strings.ToUpper(cmd.Server.LogLevel)
		}

		format := strings.ToUpper(cmd.Server.LogFormat)
		logger, err := log.NewLogger(logLevel, format, cmd.Server.LogFile)
		if err != nil {
			return fmt.Errorf("Could not open log file %s: %s", cmd.Server.LogFile, err)
		}

		orig.Log = logger
	}

	// TODO: CLI should be able to override with `false` value
	if cmd.Server.UpstreamBundle {
		orig.UpstreamBundle = cmd.Server.UpstreamBundle
	}

	if cmd.Server.Experimental.AllowAgentlessNodeAttestors {
		orig.Experimental.AllowAgentlessNodeAttestors = cmd.Server.Experimental.AllowAgentlessNodeAttestors
	}

	if cmd.Server.Experimental.BundleEndpointEnabled {
		orig.Experimental.BundleEndpointEnabled = cmd.Server.Experimental.BundleEndpointEnabled
	}
	if cmd.Server.Experimental.BundleEndpointAddress != "" {
		ip := net.ParseIP(cmd.Server.Experimental.BundleEndpointAddress)
		if ip == nil {
			return errors.New("bundle_endpoint_address must be a valid IP")
		}
		orig.Experimental.BundleEndpointAddress.IP = ip
	}
	if cmd.Server.Experimental.BundleEndpointPort != 0 {
		orig.Experimental.BundleEndpointAddress.Port = cmd.Server.Experimental.BundleEndpointPort
	}

	if cmd.Server.Experimental.FederatesWith != nil {
		federatesWith := map[string]bundleClient.TrustDomainConfig{}
		for trustDomain, config := range cmd.Server.Experimental.FederatesWith {
			if config.BundleEndpointAddress == "" {
				return fmt.Errorf("%s bundle_endpoint_address must be set", trustDomain)
			}
			port := defaultBundleEndpointPort
			if config.BundleEndpointPort != 0 {
				port = config.BundleEndpointPort
			}
			federatesWith[trustDomain] = bundleClient.TrustDomainConfig{
				EndpointAddress:  fmt.Sprintf("%s:%d", config.BundleEndpointAddress, port),
				EndpointSpiffeID: config.BundleEndpointSpiffeID,
			}
		}
		orig.Experimental.FederatesWith = federatesWith
	}

	if cmd.Server.ProfilingEnabled {
		orig.ProfilingEnabled = cmd.Server.ProfilingEnabled
	}

	if orig.ProfilingEnabled {
		if cmd.Server.ProfilingPort > 0 {
			orig.ProfilingPort = cmd.Server.ProfilingPort
		}

		if cmd.Server.ProfilingFreq > 0 {
			orig.ProfilingFreq = cmd.Server.ProfilingFreq
		}

		if len(cmd.Server.ProfilingNames) > 0 {
			orig.ProfilingNames = cmd.Server.ProfilingNames
		}
	}

	if cmd.Server.SVIDTTL != "" {
		ttl, err := time.ParseDuration(cmd.Server.SVIDTTL)
		if err != nil {
			return fmt.Errorf("unable to parse default ttl %q: %v", cmd.Server.SVIDTTL, err)
		}
		orig.SVIDTTL = ttl
	}

	if cmd.Server.CATTL != "" {
		ttl, err := time.ParseDuration(cmd.Server.CATTL)
		if err != nil {
			return fmt.Errorf("unable to parse default ttl %q: %v", cmd.Server.CATTL, err)
		}
		orig.CATTL = ttl
	}

	if subject := cmd.Server.CASubject; subject != nil {
		orig.CASubject = pkix.Name{
			Organization: subject.Organization,
			Country:      subject.Country,
			CommonName:   subject.CommonName,
		}
	}

	return nil
}

func validateConfig(c *serverConfig) error {
	if c.BindAddress.IP == nil || c.BindAddress.Port == 0 {
		return errors.New("BindAddress and BindPort are required")
	}

	if c.BindUDSAddress.Name == "" {
		return errors.New("BindUDSAddress Name is required")
	}

	if c.TrustDomain.String() == "" {
		return errors.New("TrustDomain is required")
	}

	if c.DataDir == "" {
		return errors.New("DataDir is required")
	}

	return nil
}

func newDefaultConfig() *serverConfig {
	// log.NewLogger() cannot return error when using STDOUT
	logger, _ := log.NewLogger(defaultLogLevel, log.DefaultFormat, "")
	bindAddress := &net.TCPAddr{}
	bindUDSAddress := &net.UnixAddr{Name: defaultSocketPath, Net: "unix"}

	return &serverConfig{
		Config: server.Config{
			Log:            logger,
			BindAddress:    bindAddress,
			BindUDSAddress: bindUDSAddress,
			Experimental: server.ExperimentalConfig{
				BundleEndpointAddress: &net.TCPAddr{Port: defaultBundleEndpointPort},
			},
		},
	}
}
