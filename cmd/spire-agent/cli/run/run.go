package run

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/imdario/mergo"
	"github.com/mitchellh/cli"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/config"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
)

const (
	commandName = "run"

	defaultConfigPath = "conf/agent/agent.conf"

	// TODO: Make my defaults sane
	defaultDataDir                     = "."
	defaultLogLevel                    = "INFO"
	defaultDefaultSVIDName             = "default"
	defaultDefaultBundleName           = "ROOTCA"
	defaultDefaultAllBundlesName       = "ALL"
	defaultDisableSPIFFECertValidation = false

	bundleFormatPEM    = "pem"
	bundleFormatSPIFFE = "spiffe"

	minimumAvailabilityTarget = 24 * time.Hour
)

// Config contains all available configurables, arranged by section
type Config struct {
	Agent              *agentConfig           `hcl:"agent"`
	Plugins            ast.Node               `hcl:"plugins"`
	Telemetry          telemetry.FileConfig   `hcl:"telemetry"`
	HealthChecks       health.Config          `hcl:"health_checks"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type agentConfig struct {
	DataDir                       string    `hcl:"data_dir"`
	AdminSocketPath               string    `hcl:"admin_socket_path"`
	InsecureBootstrap             bool      `hcl:"insecure_bootstrap"`
	RetryBootstrap                bool      `hcl:"retry_bootstrap"`
	JoinToken                     string    `hcl:"join_token"`
	LogFile                       string    `hcl:"log_file"`
	LogFormat                     string    `hcl:"log_format"`
	LogLevel                      string    `hcl:"log_level"`
	LogSourceLocation             bool      `hcl:"log_source_location"`
	SDS                           sdsConfig `hcl:"sds"`
	ServerAddress                 string    `hcl:"server_address"`
	ServerPort                    int       `hcl:"server_port"`
	SocketPath                    string    `hcl:"socket_path"`
	WorkloadX509SVIDKeyType       string    `hcl:"workload_x509_svid_key_type"`
	TrustBundleFormat             string    `hcl:"trust_bundle_format"`
	TrustBundlePath               string    `hcl:"trust_bundle_path"`
	TrustBundleURL                string    `hcl:"trust_bundle_url"`
	TrustDomain                   string    `hcl:"trust_domain"`
	AllowUnauthenticatedVerifiers bool      `hcl:"allow_unauthenticated_verifiers"`
	AllowedForeignJWTClaims       []string  `hcl:"allowed_foreign_jwt_claims"`
	AvailabilityTarget            string    `hcl:"availability_target"`
	X509SVIDCacheMaxSize          int       `hcl:"x509_svid_cache_max_size"`
	JWTSVIDCacheMaxSize           int       `hcl:"jwt_svid_cache_max_size"`

	AuthorizedDelegates []string `hcl:"authorized_delegates"`

	ConfigPath string
	ExpandEnv  bool

	// Undocumented configurables
	ProfilingEnabled bool               `hcl:"profiling_enabled"`
	ProfilingPort    int                `hcl:"profiling_port"`
	ProfilingFreq    int                `hcl:"profiling_freq"`
	ProfilingNames   []string           `hcl:"profiling_names"`
	Experimental     experimentalConfig `hcl:"experimental"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type sdsConfig struct {
	DefaultSVIDName             string `hcl:"default_svid_name"`
	DefaultBundleName           string `hcl:"default_bundle_name"`
	DefaultAllBundlesName       string `hcl:"default_all_bundles_name"`
	DisableSPIFFECertValidation bool   `hcl:"disable_spiffe_cert_validation"`
}

type experimentalConfig struct {
	SyncInterval             string `hcl:"sync_interval"`
	NamedPipeName            string `hcl:"named_pipe_name"`
	AdminNamedPipeName       string `hcl:"admin_named_pipe_name"`
	UseSyncAuthorizedEntries *bool  `hcl:"use_sync_authorized_entries"`
	RequirePQKEM             bool   `hcl:"require_pq_kem"`

	Flags fflag.RawConfig `hcl:"feature_flags"`
}

type Command struct {
	ctx                context.Context
	logOptions         []log.Option
	env                *common_cli.Env
	allowUnknownConfig bool
}

func NewRunCommand(ctx context.Context, logOptions []log.Option, allowUnknownConfig bool) cli.Command {
	return newRunCommand(ctx, common_cli.DefaultEnv, logOptions, allowUnknownConfig)
}

func newRunCommand(ctx context.Context, env *common_cli.Env, logOptions []log.Option, allowUnknownConfig bool) *Command {
	return &Command{
		ctx:                ctx,
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

	err = fflag.Load(input.Agent.Experimental.Flags)
	if err != nil {
		return nil, fmt.Errorf("error loading feature flags: %w", err)
	}

	return NewAgentConfig(input, logOptions, allowUnknownConfig)
}

func (cmd *Command) Run(args []string) int {
	c, err := LoadConfig(commandName, args, cmd.logOptions, cmd.env.Stderr, cmd.allowUnknownConfig)
	if err != nil {
		_, _ = fmt.Fprintln(cmd.env.Stderr, err)
		return 1
	}

	if err := prepareEndpoints(c); err != nil {
		fmt.Fprintln(cmd.env.Stderr, err)
		return 1
	}

	a := agent.New(c)

	ctx := cmd.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

func (c *agentConfig) validate() error {
	if c == nil {
		return errors.New("agent section must be configured")
	}

	if c.ServerAddress == "" {
		return errors.New("server_address must be configured")
	}

	if c.ServerPort == 0 {
		return errors.New("server_port must be configured")
	}

	if c.TrustDomain == "" {
		return errors.New("trust_domain must be configured")
	}

	// If insecure_bootstrap is set, trust_bundle_path or trust_bundle_url cannot be set
	// If trust_bundle_url is set, download the trust bundle using HTTP and parse it from memory
	// If trust_bundle_path is set, parse the trust bundle file on disk
	// Both cannot be set
	// The trust bundle URL must start with HTTPS
	if c.InsecureBootstrap {
		switch {
		case c.TrustBundleURL != "" && c.TrustBundlePath != "":
			return errors.New("only one of insecure_bootstrap, trust_bundle_url, or trust_bundle_path can be specified, not the three options")
		case c.TrustBundleURL != "":
			return errors.New("only one of insecure_bootstrap or trust_bundle_url can be specified, not both")
		case c.TrustBundlePath != "":
			return errors.New("only one of insecure_bootstrap or trust_bundle_path can be specified, not both")
		}
	} else if c.TrustBundlePath == "" && c.TrustBundleURL == "" {
		return errors.New("trust_bundle_path or trust_bundle_url must be configured unless insecure_bootstrap is set")
	}

	if c.TrustBundleURL != "" && c.TrustBundlePath != "" {
		return errors.New("only one of trust_bundle_url or trust_bundle_path can be specified, not both")
	}

	if c.TrustBundleFormat != bundleFormatPEM && c.TrustBundleFormat != bundleFormatSPIFFE {
		return fmt.Errorf("invalid value for trust_bundle_format, expected %q or %q", bundleFormatPEM, bundleFormatSPIFFE)
	}

	if c.TrustBundleURL != "" {
		u, err := url.Parse(c.TrustBundleURL)
		if err != nil {
			return fmt.Errorf("unable to parse trust bundle URL: %w", err)
		}
		if u.Scheme != "https" {
			return errors.New("trust bundle URL must start with https://")
		}
	}

	return c.validateOS()
}

func ParseFile(path string, expandEnv bool) (*Config, error) {
	c := &Config{}

	if path == "" {
		path = defaultConfigPath
	}

	// Return a friendly error if the file is missing
	byteData, err := os.ReadFile(path)
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
		return nil, fmt.Errorf("unable to read configuration at %q: %w", path, err)
	}
	data := string(byteData)

	// If envTemplate flag is passed, substitute $VARIABLES in configuration file
	if expandEnv {
		data = config.ExpandEnv(data)
	}

	if err := hcl.Decode(&c, data); err != nil {
		return nil, fmt.Errorf("unable to decode configuration at %q: %w", path, err)
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
	flags.BoolVar(&c.LogSourceLocation, "logSourceLocation", false, "Include source file, line number and function name in log lines")
	flags.StringVar(&c.ServerAddress, "serverAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.ServerPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.StringVar(&c.TrustDomain, "trustDomain", "", "The trust domain that this agent belongs to")
	flags.StringVar(&c.TrustBundlePath, "trustBundle", "", "Path to the SPIRE server CA bundle")
	flags.StringVar(&c.TrustBundleURL, "trustBundleUrl", "", "URL to download the SPIRE server CA bundle")
	flags.StringVar(&c.TrustBundleFormat, "trustBundleFormat", "", fmt.Sprintf("Format of the bootstrap trust bundle, %q or %q", bundleFormatPEM, bundleFormatSPIFFE))
	flags.BoolVar(&c.AllowUnauthenticatedVerifiers, "allowUnauthenticatedVerifiers", false, "If true, the agent permits the retrieval of X509 certificate bundles by unregistered clients")
	flags.BoolVar(&c.InsecureBootstrap, "insecureBootstrap", false, "If true, the agent bootstraps without verifying the server's identity")
	flags.BoolVar(&c.RetryBootstrap, "retryBootstrap", false, "If true, the agent retries bootstrap with backoff")
	flags.BoolVar(&c.ExpandEnv, "expandEnv", false, "Expand environment variables in SPIRE config file")

	c.addOSFlags(flags)

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

func parseTrustBundle(bundleBytes []byte, trustBundleContentType string) ([]*x509.Certificate, error) {
	switch trustBundleContentType {
	case bundleFormatPEM:
		bundle, err := pemutil.ParseCertificates(bundleBytes)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	case bundleFormatSPIFFE:
		bundle, err := bundleutil.Unmarshal(spiffeid.TrustDomain{}, bundleBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse SPIFFE trust bundle: %w", err)
		}
		return bundle.X509Authorities(), nil
	}

	return nil, fmt.Errorf("unknown trust bundle format: %s", trustBundleContentType)
}

func downloadTrustBundle(trustBundleURL string) ([]byte, error) {
	// Download the trust bundle URL from the user specified URL
	// We use gosec -- the annotation below will disable a security check that URLs are not tainted
	/* #nosec G107 */
	resp, err := http.Get(trustBundleURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch trust bundle URL %s: %w", trustBundleURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error downloading trust bundle: %s", resp.Status)
	}
	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read from trust bundle URL %s: %w", trustBundleURL, err)
	}

	return pemBytes, nil
}

func setupTrustBundle(ac *agent.Config, c *Config) error {
	// Either download the trust bundle if TrustBundleURL is set, or read it
	// from disk if TrustBundlePath is set
	ac.InsecureBootstrap = c.Agent.InsecureBootstrap

	var bundleBytes []byte
	var err error

	switch {
	case c.Agent.TrustBundleURL != "":
		bundleBytes, err = downloadTrustBundle(c.Agent.TrustBundleURL)
		if err != nil {
			return err
		}
	case c.Agent.TrustBundlePath != "":
		bundleBytes, err = loadTrustBundle(c.Agent.TrustBundlePath)
		if err != nil {
			return fmt.Errorf("could not parse trust bundle: %w", err)
		}
	default:
		// If InsecureBootstrap is configured, the bundle is not required
		if ac.InsecureBootstrap {
			return nil
		}
	}

	bundle, err := parseTrustBundle(bundleBytes, c.Agent.TrustBundleFormat)
	if err != nil {
		return err
	}

	if len(bundle) == 0 {
		return errors.New("no certificates found in trust bundle")
	}

	ac.TrustBundle = bundle

	return nil
}

func NewAgentConfig(c *Config, logOptions []log.Option, allowUnknownConfig bool) (*agent.Config, error) {
	ac := &agent.Config{}

	if err := validateConfig(c); err != nil {
		return nil, err
	}

	ac.RetryBootstrap = c.Agent.RetryBootstrap

	if c.Agent.Experimental.SyncInterval != "" {
		var err error
		ac.SyncInterval, err = time.ParseDuration(c.Agent.Experimental.SyncInterval)
		if err != nil {
			return nil, fmt.Errorf("could not parse synchronization interval: %w", err)
		}
	}

	serverHostPort := net.JoinHostPort(c.Agent.ServerAddress, strconv.Itoa(c.Agent.ServerPort))
	ac.ServerAddress = fmt.Sprintf("dns:///%s", serverHostPort)

	logOptions = append(logOptions,
		log.WithLevel(c.Agent.LogLevel),
		log.WithFormat(c.Agent.LogFormat),
	)
	if c.Agent.LogSourceLocation {
		logOptions = append(logOptions, log.WithSourceLocation())
	}
	var reopenableFile *log.ReopenableFile
	if c.Agent.LogFile != "" {
		var err error
		reopenableFile, err = log.NewReopenableFile(c.Agent.LogFile)
		if err != nil {
			return nil, err
		}
		logOptions = append(logOptions, log.WithReopenableOutputFile(reopenableFile))
	}

	logger, err := log.NewLogger(logOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not start logger: %w", err)
	}
	ac.Log = logger
	if reopenableFile != nil {
		ac.LogReopener = log.ReopenOnSignal(logger, reopenableFile)
	}

	ac.UseSyncAuthorizedEntries = true
	if c.Agent.Experimental.UseSyncAuthorizedEntries != nil {
		ac.Log.Warn("The 'use_sync_authorized_entries' configuration is deprecated. The option to disable it will be removed in SPIRE 1.13.")
		ac.UseSyncAuthorizedEntries = *c.Agent.Experimental.UseSyncAuthorizedEntries
	}

	if c.Agent.X509SVIDCacheMaxSize < 0 {
		return nil, errors.New("x509_svid_cache_max_size should not be negative")
	}
	ac.X509SVIDCacheMaxSize = c.Agent.X509SVIDCacheMaxSize

	if c.Agent.JWTSVIDCacheMaxSize < 0 {
		return nil, errors.New("jwt_svid_cache_max_size should not be negative")
	}
	ac.JWTSVIDCacheMaxSize = c.Agent.JWTSVIDCacheMaxSize

	td, err := common_cli.ParseTrustDomain(c.Agent.TrustDomain, logger)
	if err != nil {
		return nil, err
	}
	ac.TrustDomain = td

	addr, err := c.Agent.getAddr()
	if err != nil {
		return nil, err
	}
	ac.BindAddress = addr

	if c.Agent.hasAdminAddr() {
		adminAddr, err := c.Agent.getAdminAddr()
		if err != nil {
			return nil, err
		}
		ac.AdminBindAddress = adminAddr
	}
	ac.JoinToken = c.Agent.JoinToken
	ac.DataDir = c.Agent.DataDir
	ac.DefaultSVIDName = c.Agent.SDS.DefaultSVIDName
	ac.DefaultBundleName = c.Agent.SDS.DefaultBundleName
	ac.DefaultAllBundlesName = c.Agent.SDS.DefaultAllBundlesName
	if ac.DefaultAllBundlesName == ac.DefaultBundleName {
		logger.Warn(`The "default_bundle_name" and "default_all_bundles_name" configurables have the same value. "default_all_bundles_name" will be ignored. Please configure distinct values or use the defaults. This will be a configuration error in a future release.`)
	}
	ac.DisableSPIFFECertValidation = c.Agent.SDS.DisableSPIFFECertValidation

	err = setupTrustBundle(ac, c)
	if err != nil {
		return nil, err
	}

	ac.WorkloadKeyType = workloadkey.ECP256
	if c.Agent.WorkloadX509SVIDKeyType != "" {
		ac.WorkloadKeyType, err = workloadkey.KeyTypeFromString(c.Agent.WorkloadX509SVIDKeyType)
		if err != nil {
			return nil, err
		}
	}

	ac.ProfilingEnabled = c.Agent.ProfilingEnabled
	ac.ProfilingPort = c.Agent.ProfilingPort
	ac.ProfilingFreq = c.Agent.ProfilingFreq
	ac.ProfilingNames = c.Agent.ProfilingNames

	ac.AllowedForeignJWTClaims = c.Agent.AllowedForeignJWTClaims

	ac.PluginConfigs, err = catalog.PluginConfigsFromHCLNode(c.Plugins)
	if err != nil {
		return nil, err
	}

	ac.Telemetry = c.Telemetry
	ac.HealthChecks = c.HealthChecks

	if !allowUnknownConfig {
		if err := checkForUnknownConfig(c, logger); err != nil {
			return nil, err
		}
	}

	ac.AllowUnauthenticatedVerifiers = c.Agent.AllowUnauthenticatedVerifiers

	for _, authorizedDelegate := range c.Agent.AuthorizedDelegates {
		if _, err := idutil.MemberFromString(ac.TrustDomain, authorizedDelegate); err != nil {
			return nil, fmt.Errorf("error validating authorized delegate: %w", err)
		}
	}

	ac.AuthorizedDelegates = c.Agent.AuthorizedDelegates

	if c.Agent.AvailabilityTarget != "" {
		t, err := time.ParseDuration(c.Agent.AvailabilityTarget)
		if err != nil {
			return nil, fmt.Errorf("unable to parse availability_target: %w", err)
		}
		if t < minimumAvailabilityTarget {
			return nil, fmt.Errorf("availability_target must be at least %s", minimumAvailabilityTarget.String())
		}
		ac.AvailabilityTarget = t
	}

	ac.TLSPolicy = tlspolicy.Policy{
		RequirePQKEM: c.Agent.Experimental.RequirePQKEM,
	}

	tlspolicy.LogPolicy(ac.TLSPolicy, log.NewHCLogAdapter(logger, "tlspolicy"))

	if cmp.Diff(experimentalConfig{}, c.Agent.Experimental) != "" {
		logger.Warn("Experimental features have been enabled. Please see doc/upgrading.md for upgrade and compatibility considerations for experimental features.")
	}

	for _, f := range c.Agent.Experimental.Flags {
		logger.Warnf("Developer feature flag %q has been enabled", f)
	}

	return ac, nil
}

func validateConfig(c *Config) error {
	if c.Plugins == nil {
		return errors.New("plugins section must be configured")
	}

	return c.Agent.validate()
}

func checkForUnknownConfig(c *Config, l logrus.FieldLogger) (err error) {
	detectedUnknown := func(section string, keyPositions map[string][]token.Pos) {
		var keys []string
		for k := range keyPositions {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		l.WithFields(logrus.Fields{
			"section": section,
			"keys":    strings.Join(keys, ","),
		}).Error("Unknown configuration detected")
		err = errors.New("unknown configuration detected")
	}

	if len(c.UnusedKeyPositions) != 0 {
		detectedUnknown("top-level", c.UnusedKeyPositions)
	}

	if a := c.Agent; a != nil && len(a.UnusedKeyPositions) != 0 {
		detectedUnknown("agent", a.UnusedKeyPositions)
	}

	// TODO: Re-enable unused key detection for telemetry. See
	// https://github.com/spiffe/spire/issues/1101 for more information
	//
	// if len(c.Telemetry.UnusedKeyPositions) != 0 {
	//	detectedUnknown("telemetry", c.Telemetry.UnusedKeyPositions)
	// }

	if p := c.Telemetry.Prometheus; p != nil && len(p.UnusedKeyPositions) != 0 {
		detectedUnknown("Prometheus", p.UnusedKeyPositions)
	}

	for _, v := range c.Telemetry.DogStatsd {
		if len(v.UnusedKeyPositions) != 0 {
			detectedUnknown("DogStatsd", v.UnusedKeyPositions)
		}
	}

	for _, v := range c.Telemetry.Statsd {
		if len(v.UnusedKeyPositions) != 0 {
			detectedUnknown("Statsd", v.UnusedKeyPositions)
		}
	}

	for _, v := range c.Telemetry.M3 {
		if len(v.UnusedKeyPositions) != 0 {
			detectedUnknown("M3", v.UnusedKeyPositions)
		}
	}

	if p := c.Telemetry.InMem; p != nil && len(p.UnusedKeyPositions) != 0 {
		detectedUnknown("InMem", p.UnusedKeyPositions)
	}

	if len(c.HealthChecks.UnusedKeyPositions) != 0 {
		detectedUnknown("health check", c.HealthChecks.UnusedKeyPositions)
	}

	return err
}

func defaultConfig() *Config {
	c := &Config{
		Agent: &agentConfig{
			DataDir:           defaultDataDir,
			LogLevel:          defaultLogLevel,
			LogFormat:         log.DefaultFormat,
			TrustBundleFormat: bundleFormatPEM,
			SDS: sdsConfig{
				DefaultBundleName:           defaultDefaultBundleName,
				DefaultSVIDName:             defaultDefaultSVIDName,
				DefaultAllBundlesName:       defaultDefaultAllBundlesName,
				DisableSPIFFECertValidation: defaultDisableSPIFFECertValidation,
			},
		},
	}
	c.Agent.setPlatformDefaults()

	return c
}

func loadTrustBundle(path string) ([]byte, error) {
	bundleBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bundleBytes, nil
}
