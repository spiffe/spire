package run

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/imdario/mergo"
	"github.com/mitchellh/cli"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
)

const (
	commandName = "run"

	defaultConfigPath = "conf/agent/agent.conf"

	// TODO: Make my defaults sane
	defaultDataDir           = "."
	defaultLogLevel          = "INFO"
	defaultDefaultSVIDName   = "default"
	defaultDefaultBundleName = "ROOTCA"
)

// Config contains all available configurables, arranged by section
type Config struct {
	Agent        *agentConfig                `hcl:"agent"`
	Plugins      *catalog.HCLPluginConfigMap `hcl:"plugins"`
	Telemetry    telemetry.FileConfig        `hcl:"telemetry"`
	HealthChecks health.Config               `hcl:"health_checks"`
	UnusedKeys   []string                    `hcl:",unusedKeys"`
}

type agentConfig struct {
	DataDir                       string    `hcl:"data_dir"`
	AdminSocketPath               string    `hcl:"admin_socket_path"`
	InsecureBootstrap             bool      `hcl:"insecure_bootstrap"`
	JoinToken                     string    `hcl:"join_token"`
	LogFile                       string    `hcl:"log_file"`
	LogFormat                     string    `hcl:"log_format"`
	LogLevel                      string    `hcl:"log_level"`
	SDS                           sdsConfig `hcl:"sds"`
	ServerAddress                 string    `hcl:"server_address"`
	ServerPort                    int       `hcl:"server_port"`
	SocketPath                    string    `hcl:"socket_path"`
	TrustBundlePath               string    `hcl:"trust_bundle_path"`
	TrustBundleURL                string    `hcl:"trust_bundle_url"`
	TrustDomain                   string    `hcl:"trust_domain"`
	AllowUnauthenticatedVerifiers bool      `hcl:"allow_unauthenticated_verifiers"`

	ConfigPath string
	ExpandEnv  bool

	// Undocumented configurables
	ProfilingEnabled bool               `hcl:"profiling_enabled"`
	ProfilingPort    int                `hcl:"profiling_port"`
	ProfilingFreq    int                `hcl:"profiling_freq"`
	ProfilingNames   []string           `hcl:"profiling_names"`
	Experimental     experimentalConfig `hcl:"experimental"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type sdsConfig struct {
	DefaultSVIDName   string `hcl:"default_svid_name"`
	DefaultBundleName string `hcl:"default_bundle_name"`
}

type experimentalConfig struct {
	SyncInterval string `hcl:"sync_interval"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type Command struct {
	logOptions         []log.Option
	env                *common_cli.Env
	allowUnknownConfig bool
}

func NewRunCommand(logOptions []log.Option, allowUnknownConfig bool) cli.Command {
	return newRunCommand(common_cli.DefaultEnv, logOptions, allowUnknownConfig)
}

func newRunCommand(env *common_cli.Env, logOptions []log.Option, allowUnknownConfig bool) *Command {
	return &Command{
		env:                env,
		logOptions:         logOptions,
		allowUnknownConfig: allowUnknownConfig,
	}
}

// Help prints the agent cmd usage
func (cmd *Command) Help() string {
	return Help(commandName, cmd.env.Stderr)
}

// Help is a standalone function that prints a help message to writer.
// It is used by both the run and validate commands, so they can share flag usage messages.
func Help(name string, writer io.Writer) string {
	_, err := parseFlags(name, []string{"-h"}, writer)
	// Error is always present because -h is passed
	return err.Error()
}

func LoadConfig(name string, args []string, logOptions []log.Option, output io.Writer, allowUnknownConfig bool) (*agent.Config, error) {
	// First parse the CLI flags so we can get the config
	// file path, if set
	cliInput, err := parseFlags(name, args, output)
	if err != nil {
		return nil, err
	}

	// Load and parse the config file using either the default
	// path or CLI-specified value
	fileInput, err := ParseFile(cliInput.ConfigPath, cliInput.ExpandEnv)
	if err != nil {
		return nil, err
	}

	input, err := mergeInput(fileInput, cliInput)
	if err != nil {
		return nil, err
	}

	return NewAgentConfig(input, logOptions, allowUnknownConfig)
}

func (cmd *Command) Run(args []string) int {
	c, err := LoadConfig(commandName, args, cmd.logOptions, cmd.env.Stderr, cmd.allowUnknownConfig)
	if err != nil {
		_, _ = fmt.Fprintln(cmd.env.Stderr, err)
		return 1
	}

	// Create uds dir and parents if not exists
	dir := filepath.Dir(c.BindAddress.String())
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		c.Log.WithField("dir", dir).Infof("Creating spire agent UDS directory")
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintln(cmd.env.Stderr, err)
			return 1
		}
	}

	// Set umask before starting up the agent
	common_cli.SetUmask(c.Log)

	if c.AdminBindAddress != nil {
		// Create uds dir and parents if not exists
		adminDir := filepath.Dir(c.AdminBindAddress.String())
		if _, statErr := os.Stat(adminDir); os.IsNotExist(statErr) {
			c.Log.WithField("dir", adminDir).Infof("Creating admin UDS directory")
			if err := os.MkdirAll(adminDir, 0755); err != nil {
				fmt.Fprintln(cmd.env.Stderr, err)
				return 1
			}
		}
	}

	a := agent.New(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	util.SignalListener(ctx, cancel)

	err = a.Run(ctx)
	if err != nil {
		c.Log.WithError(err).Error("Agent crashed")
		return 1
	}

	c.Log.Info("Agent stopped gracefully")
	return 0
}

func (*Command) Synopsis() string {
	return "Runs the agent"
}

func ParseFile(path string, expandEnv bool) (*Config, error) {
	c := &Config{}

	if path == "" {
		path = defaultConfigPath
	}

	// Return a friendly error if the file is missing
	byteData, err := ioutil.ReadFile(path)
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
	data := string(byteData)

	// If envTemplate flag is passed, substitute $VARIABLES in configuration file
	if expandEnv {
		data = os.ExpandEnv(data)
	}

	if err := hcl.Decode(&c, data); err != nil {
		return nil, fmt.Errorf("unable to decode configuration at %q: %v", path, err)
	}

	return c, nil
}

func parseFlags(name string, args []string, output io.Writer) (*agentConfig, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(output)
	c := &agentConfig{}

	flags.StringVar(&c.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.StringVar(&c.DataDir, "dataDir", "", "A directory the agent can use for its runtime data")
	flags.StringVar(&c.JoinToken, "joinToken", "", "An optional token which has been generated by the SPIRE server")
	flags.StringVar(&c.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.LogFormat, "logFormat", "", "'text' or 'json'")
	flags.StringVar(&c.LogLevel, "logLevel", "", "'debug', 'info', 'warn', or 'error'")
	flags.StringVar(&c.ServerAddress, "serverAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.ServerPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.StringVar(&c.SocketPath, "socketPath", "", "Path to bind the SPIRE Agent API socket to")
	flags.StringVar(&c.TrustDomain, "trustDomain", "", "The trust domain that this agent belongs to")
	flags.StringVar(&c.TrustBundlePath, "trustBundle", "", "Path to the SPIRE server CA bundle")
	flags.StringVar(&c.TrustBundleURL, "trustBundleUrl", "", "URL to download the SPIRE server CA bundle")
	flags.BoolVar(&c.AllowUnauthenticatedVerifiers, "allowUnauthenticatedVerifiers", false, "If true, the agent permits the retrieval of X509 certificate bundles by unregistered clients")
	flags.BoolVar(&c.InsecureBootstrap, "insecureBootstrap", false, "If true, the agent bootstraps without verifying the server's identity")
	flags.BoolVar(&c.ExpandEnv, "expandEnv", false, "Expand environment variables in SPIRE config file")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func mergeInput(fileInput *Config, cliInput *agentConfig) (*Config, error) {
	c := &Config{Agent: &agentConfig{}}

	// Highest precedence first
	err := mergo.Merge(c.Agent, cliInput)
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

func downloadTrustBundle(trustBundleURL string) ([]*x509.Certificate, error) {
	// Download the trust bundle URL from the user specified URL
	// We use gosec -- the annotation below will disable a security check that URLs are not tainted
	/* #nosec G107 */
	resp, err := http.Get(trustBundleURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch trust bundle URL %s: %v", trustBundleURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error downloading trust bundle: %s", resp.Status)
	}
	pemBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read from trust bundle URL %s: %v", trustBundleURL, err)
	}

	bundle, err := pemutil.ParseCertificates(pemBytes)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func setupTrustBundle(ac *agent.Config, c *Config) error {
	// Either download the turst bundle if TrustBundleURL is set, or read it
	// from disk if TrustBundlePath is set
	ac.InsecureBootstrap = c.Agent.InsecureBootstrap

	switch {
	case c.Agent.TrustBundleURL != "":
		bundle, err := downloadTrustBundle(c.Agent.TrustBundleURL)
		if err != nil {
			return err
		}
		ac.TrustBundle = bundle
	case c.Agent.TrustBundlePath != "":
		bundle, err := parseTrustBundle(c.Agent.TrustBundlePath)
		if err != nil {
			return fmt.Errorf("could not parse trust bundle: %v", err)
		}
		ac.TrustBundle = bundle
	}

	return nil
}

func NewAgentConfig(c *Config, logOptions []log.Option, allowUnknownConfig bool) (*agent.Config, error) {
	ac := &agent.Config{}

	if err := validateConfig(c); err != nil {
		return nil, err
	}

	if c.Agent.Experimental.SyncInterval != "" {
		var err error
		ac.SyncInterval, err = time.ParseDuration(c.Agent.Experimental.SyncInterval)
		if err != nil {
			return nil, fmt.Errorf("could not parse synchronization interval: %v", err)
		}
	}

	serverHostPort := net.JoinHostPort(c.Agent.ServerAddress, strconv.Itoa(c.Agent.ServerPort))
	ac.ServerAddress = fmt.Sprintf("dns:///%s", serverHostPort)

	logOptions = append(logOptions,
		log.WithLevel(c.Agent.LogLevel),
		log.WithFormat(c.Agent.LogFormat),
		log.WithOutputFile(c.Agent.LogFile))

	logger, err := log.NewLogger(logOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not start logger: %s", err)
	}
	ac.Log = logger

	td, err := common_cli.ParseTrustDomain(c.Agent.TrustDomain, logger)
	if err != nil {
		return nil, err
	}
	ac.TrustDomain = td

	ac.BindAddress = &net.UnixAddr{
		Name: c.Agent.SocketPath,
		Net:  "unix",
	}

	if c.Agent.AdminSocketPath != "" {
		socketPathAbs, err := filepath.Abs(c.Agent.SocketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for socket_path: %v", err)
		}
		adminSocketPathAbs, err := filepath.Abs(c.Agent.AdminSocketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for admin_socket_path: %v", err)
		}

		if strings.HasPrefix(adminSocketPathAbs, filepath.Dir(socketPathAbs)+"/") {
			return nil, errors.New("admin socket cannot be in the same directory or a subdirectory as that containing the Workload API socket")
		}

		ac.AdminBindAddress = &net.UnixAddr{
			Name: c.Agent.AdminSocketPath,
			Net:  "unix",
		}
	}
	ac.JoinToken = c.Agent.JoinToken
	ac.DataDir = c.Agent.DataDir
	ac.DefaultSVIDName = c.Agent.SDS.DefaultSVIDName
	ac.DefaultBundleName = c.Agent.SDS.DefaultBundleName

	err = setupTrustBundle(ac, c)
	if err != nil {
		return nil, err
	}

	ac.ProfilingEnabled = c.Agent.ProfilingEnabled
	ac.ProfilingPort = c.Agent.ProfilingPort
	ac.ProfilingFreq = c.Agent.ProfilingFreq
	ac.ProfilingNames = c.Agent.ProfilingNames

	ac.PluginConfigs = *c.Plugins
	ac.Telemetry = c.Telemetry
	ac.HealthChecks = c.HealthChecks

	if !allowUnknownConfig {
		if err := checkForUnknownConfig(c, logger); err != nil {
			return nil, err
		}
	}

	ac.AllowUnauthenticatedVerifiers = c.Agent.AllowUnauthenticatedVerifiers

	return ac, nil
}

func validateConfig(c *Config) error {
	if c.Agent == nil {
		return errors.New("agent section must be configured")
	}

	if c.Agent.ServerAddress == "" {
		return errors.New("server_address must be configured")
	}

	if c.Agent.ServerPort == 0 {
		return errors.New("server_port must be configured")
	}

	if c.Agent.TrustDomain == "" {
		return errors.New("trust_domain must be configured")
	}

	// If trust_bundle_url is set, download the trust bundle using HTTP and parse it from memory
	// If trust_bundle_path is set, parse the trust bundle file on disk
	// Both cannot be set
	// The trust bundle URL must start with HTTPS

	if c.Agent.TrustBundlePath == "" && c.Agent.TrustBundleURL == "" && !c.Agent.InsecureBootstrap {
		return errors.New("trust_bundle_path or trust_bundle_url must be configured unless insecure_bootstrap is set")
	}

	if c.Agent.TrustBundleURL != "" && c.Agent.TrustBundlePath != "" {
		return errors.New("only one of trust_bundle_url or trust_bundle_path can be specified, not both")
	}

	if c.Agent.TrustBundleURL != "" {
		u, err := url.Parse(c.Agent.TrustBundleURL)
		if err != nil {
			return fmt.Errorf("unable to parse trust bundle URL: %v", err)
		}
		if u.Scheme != "https" {
			return errors.New("trust bundle URL must start with https://")
		}
	}
	if c.Plugins == nil {
		return errors.New("plugins section must be configured")
	}

	return nil
}

func checkForUnknownConfig(c *Config, l logrus.FieldLogger) (err error) {
	detectedUnknown := func(section string, keys []string) {
		l.WithFields(logrus.Fields{
			"section": section,
			"keys":    strings.Join(keys, ","),
		}).Error("Unknown configuration detected")
		err = errors.New("unknown configuration detected")
	}

	if len(c.UnusedKeys) != 0 {
		detectedUnknown("top-level", c.UnusedKeys)
	}

	if a := c.Agent; a != nil && len(a.UnusedKeys) != 0 {
		detectedUnknown("agent", a.UnusedKeys)
	}

	// TODO: Re-enable unused key detection for telemetry. See
	// https://github.com/spiffe/spire/issues/1101 for more information
	//
	//if len(c.Telemetry.UnusedKeys) != 0 {
	//	detectedUnknown("telemetry", c.Telemetry.UnusedKeys)
	//}

	if p := c.Telemetry.Prometheus; p != nil && len(p.UnusedKeys) != 0 {
		detectedUnknown("Prometheus", p.UnusedKeys)
	}

	for _, v := range c.Telemetry.DogStatsd {
		if len(v.UnusedKeys) != 0 {
			detectedUnknown("DogStatsd", v.UnusedKeys)
		}
	}

	for _, v := range c.Telemetry.Statsd {
		if len(v.UnusedKeys) != 0 {
			detectedUnknown("Statsd", v.UnusedKeys)
		}
	}

	for _, v := range c.Telemetry.M3 {
		if len(v.UnusedKeys) != 0 {
			detectedUnknown("M3", v.UnusedKeys)
		}
	}

	if p := c.Telemetry.InMem; p != nil && len(p.UnusedKeys) != 0 {
		detectedUnknown("InMem", p.UnusedKeys)
	}

	if len(c.HealthChecks.UnusedKeys) != 0 {
		detectedUnknown("health check", c.HealthChecks.UnusedKeys)
	}

	return err
}

func defaultConfig() *Config {
	return &Config{
		Agent: &agentConfig{
			DataDir:    defaultDataDir,
			LogLevel:   defaultLogLevel,
			LogFormat:  log.DefaultFormat,
			SocketPath: common.DefaultSocketPath,
			SDS: sdsConfig{
				DefaultBundleName: defaultDefaultBundleName,
				DefaultSVIDName:   defaultDefaultSVIDName,
			},
		},
	}
}

func parseTrustBundle(path string) ([]*x509.Certificate, error) {
	bundle, err := pemutil.LoadCertificates(path)
	if err != nil {
		return nil, err
	}

	if len(bundle) == 0 {
		return nil, errors.New("no certificates found in trust bundle")
	}

	return bundle, nil
}
