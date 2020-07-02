package run

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/imdario/mergo"
	"github.com/mitchellh/cli"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server"
	bundleClient "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

const (
	commandName = "run"

	defaultConfigPath         = "conf/server/server.conf"
	defaultSocketPath         = "/tmp/spire-registration.sock"
	defaultLogLevel           = "INFO"
	defaultBundleEndpointPort = 443
)

var (
	defaultCASubject = pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIFFE"},
	}
)

// Config contains all available configurables, arranged by section
type Config struct {
	Server       *serverConfig               `hcl:"server"`
	Plugins      *catalog.HCLPluginConfigMap `hcl:"plugins"`
	Telemetry    telemetry.FileConfig        `hcl:"telemetry"`
	HealthChecks health.Config               `hcl:"health_checks"`
	UnusedKeys   []string                    `hcl:",unusedKeys"`
}

type serverConfig struct {
	BindAddress         string             `hcl:"bind_address"`
	BindPort            int                `hcl:"bind_port"`
	CAKeyType           string             `hcl:"ca_key_type"`
	CASubject           *caSubjectConfig   `hcl:"ca_subject"`
	CATTL               string             `hcl:"ca_ttl"`
	DataDir             string             `hcl:"data_dir"`
	Experimental        experimentalConfig `hcl:"experimental"`
	Federation          *federationConfig  `hcl:"federation"`
	JWTIssuer           string             `hcl:"jwt_issuer"`
	LogFile             string             `hcl:"log_file"`
	LogLevel            string             `hcl:"log_level"`
	LogFormat           string             `hcl:"log_format"`
	RegistrationUDSPath string             `hcl:"registration_uds_path"`
	DeprecatedSVIDTTL   string             `hcl:"svid_ttl"`
	DefaultSVIDTTL      string             `hcl:"default_svid_ttl"`
	TrustDomain         string             `hcl:"trust_domain"`

	ConfigPath string
	ExpandEnv  bool

	// Undocumented configurables
	ProfilingEnabled bool     `hcl:"profiling_enabled"`
	ProfilingPort    int      `hcl:"profiling_port"`
	ProfilingFreq    int      `hcl:"profiling_freq"`
	ProfilingNames   []string `hcl:"profiling_names"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type experimentalConfig struct {
	AllowAgentlessNodeAttestors bool `hcl:"allow_agentless_node_attestors"`

	DeprecatedBundleEndpointEnabled bool                                     `hcl:"bundle_endpoint_enabled"`
	DeprecatedBundleEndpointAddress string                                   `hcl:"bundle_endpoint_address"`
	DeprecatedBundleEndpointPort    int                                      `hcl:"bundle_endpoint_port"`
	DeprecatedBundleEndpointACME    *bundleEndpointACMEConfig                `hcl:"bundle_endpoint_acme"`
	DeprecatedFederatesWith         map[string]deprecatedFederatesWithConfig `hcl:"federates_with"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type caSubjectConfig struct {
	Country      []string `hcl:"country"`
	Organization []string `hcl:"organization"`
	CommonName   string   `hcl:"common_name"`
	UnusedKeys   []string `hcl:",unusedKeys"`
}

type federationConfig struct {
	BundleEndpoint *bundleEndpointConfig          `hcl:"bundle_endpoint"`
	FederatesWith  map[string]federatesWithConfig `hcl:"federates_with"`
	UnusedKeys     []string                       `hcl:",unusedKeys"`
}

type bundleEndpointConfig struct {
	Address    string                    `hcl:"address"`
	Port       int                       `hcl:"port"`
	ACME       *bundleEndpointACMEConfig `hcl:"acme"`
	UnusedKeys []string                  `hcl:",unusedKeys"`
}

type bundleEndpointACMEConfig struct {
	DirectoryURL string   `hcl:"directory_url"`
	DomainName   string   `hcl:"domain_name"`
	Email        string   `hcl:"email"`
	ToSAccepted  bool     `hcl:"tos_accepted"`
	UnusedKeys   []string `hcl:",unusedKeys"`
}

type deprecatedFederatesWithConfig struct {
	BundleEndpointAddress  string   `hcl:"bundle_endpoint_address"`
	BundleEndpointPort     int      `hcl:"bundle_endpoint_port"`
	BundleEndpointSpiffeID string   `hcl:"bundle_endpoint_spiffe_id"`
	UseWebPKI              bool     `hcl:"use_web_pki"`
	UnusedKeys             []string `hcl:",unusedKeys"`
}

type federatesWithConfig struct {
	BundleEndpoint federatesWithBundleEndpointConfig `hcl:"bundle_endpoint"`
	UnusedKeys     []string                          `hcl:",unusedKeys"`
}

type federatesWithBundleEndpointConfig struct {
	Address    string   `hcl:"address"`
	Port       int      `hcl:"port"`
	SpiffeID   string   `hcl:"spiffe_id"`
	UseWebPKI  bool     `hcl:"use_web_pki"`
	UnusedKeys []string `hcl:",unusedKeys"`
}

func NewRunCommand(logOptions []log.Option) cli.Command {
	return newRunCommand(common_cli.DefaultEnv, logOptions)
}

func newRunCommand(env *common_cli.Env, logOptions []log.Option) *Command {
	return &Command{
		env:        env,
		LogOptions: logOptions,
	}
}

// Run Command struct
type Command struct {
	LogOptions []log.Option
	env        *common_cli.Env
}

// Help prints the server cmd usage
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

func LoadConfig(name string, args []string, logOptions []log.Option, output io.Writer) (*server.Config, error) {
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

	return NewServerConfig(input, logOptions)
}

// Run the SPIFFE Server
func (cmd *Command) Run(args []string) int {
	c, err := LoadConfig(commandName, args, cmd.LogOptions, cmd.env.Stderr)
	if err != nil {
		_, _ = fmt.Fprintln(cmd.env.Stderr, err)
		return 1
	}

	// Set umask before starting up the server
	common_cli.SetUmask(c.Log)

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
func (*Command) Synopsis() string {
	return "Runs the server"
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

func parseFlags(name string, args []string, output io.Writer) (*serverConfig, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(output)
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
	flags.BoolVar(&c.ExpandEnv, "expandEnv", false, "Expand environment variables in SPIRE config file")

	err := flags.Parse(args)
	if err != nil {
		return c, err
	}

	return c, nil
}

func mergeInput(fileInput *Config, cliInput *serverConfig) (*Config, error) {
	c := &Config{Server: &serverConfig{}}

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

func NewServerConfig(c *Config, logOptions []log.Option) (*server.Config, error) {
	sc := &server.Config{}

	if err := validateConfig(c); err != nil {
		return nil, err
	}

	ip := net.ParseIP(c.Server.BindAddress)
	if ip == nil {
		return nil, fmt.Errorf("could not parse bind_address %q", c.Server.BindAddress)
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

	logOptions = append(logOptions,
		log.WithLevel(c.Server.LogLevel),
		log.WithFormat(c.Server.LogFormat),
		log.WithOutputFile(c.Server.LogFile))

	logger, err := log.NewLogger(logOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not start logger: %s", err)
	}
	sc.Log = logger

	sc.Experimental.AllowAgentlessNodeAttestors = c.Server.Experimental.AllowAgentlessNodeAttestors
	if c.Server.Federation != nil {
		if c.Server.Federation.BundleEndpoint != nil {
			sc.Federation.BundleEndpoint = &bundle.EndpointConfig{
				Address: &net.TCPAddr{
					IP:   net.ParseIP(c.Server.Federation.BundleEndpoint.Address),
					Port: c.Server.Federation.BundleEndpoint.Port,
				},
			}

			if acme := c.Server.Federation.BundleEndpoint.ACME; acme != nil {
				sc.Federation.BundleEndpoint.ACME = &bundle.ACMEConfig{
					DirectoryURL: acme.DirectoryURL,
					DomainName:   acme.DomainName,
					CacheDir:     filepath.Join(sc.DataDir, "bundle-acme"),
					Email:        acme.Email,
					ToSAccepted:  acme.ToSAccepted,
				}
			}
		}

		federatesWith := map[string]bundleClient.TrustDomainConfig{}
		for trustDomain, config := range c.Server.Federation.FederatesWith {
			port := defaultBundleEndpointPort
			if config.BundleEndpoint.Port != 0 {
				port = config.BundleEndpoint.Port
			}
			if config.BundleEndpoint.UseWebPKI && config.BundleEndpoint.SpiffeID != "" {
				return nil, errors.New("usage of `bundle_endpoint.spiffe_id` is not allowed when authenticating with Web PKI")
			}
			federatesWith[trustDomain] = bundleClient.TrustDomainConfig{
				EndpointAddress:  fmt.Sprintf("%s:%d", config.BundleEndpoint.Address, port),
				EndpointSpiffeID: config.BundleEndpoint.SpiffeID,
				UseWebPKI:        config.BundleEndpoint.UseWebPKI,
			}
		}
		sc.Federation.FederatesWith = federatesWith
	}

	sc.ProfilingEnabled = c.Server.ProfilingEnabled
	sc.ProfilingPort = c.Server.ProfilingPort
	sc.ProfilingFreq = c.Server.ProfilingFreq
	sc.ProfilingNames = c.Server.ProfilingNames

	if c.Server.DefaultSVIDTTL != "" {
		ttl, err := time.ParseDuration(c.Server.DefaultSVIDTTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse default SVID ttl %q: %v", c.Server.DefaultSVIDTTL, err)
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

	if !hasExpectedTTLs(sc.CATTL, sc.SVIDTTL) {
		sc.Log.Warnf("The configured SVID TTL cannot be guaranteed in all cases - SVIDs with shorter TTLs may be issued if the signing key is expiring soon. Set a CA TTL of at least 6x or reduce SVID TTL below 6x to avoid issuing SVIDs with a smaller TTL than specified.")
	}

	if c.Server.CAKeyType != "" {
		sc.CAKeyType, err = caKeyTypeFromString(c.Server.CAKeyType)
		if err != nil {
			return nil, err
		}
	}

	sc.JWTIssuer = c.Server.JWTIssuer

	if subject := c.Server.CASubject; subject != nil {
		sc.CASubject = pkix.Name{
			Organization: subject.Organization,
			Country:      subject.Country,
			CommonName:   subject.CommonName,
		}
		if isPKIXNameEmpty(sc.CASubject) {
			sc.Log.Warn("ca_subject configurable is set but empty; the default will be used")
		}
	}
	// RFC3280(4.1.2.4) requires the issuer DN be set.
	if isPKIXNameEmpty(sc.CASubject) {
		sc.CASubject = defaultCASubject
	}

	sc.PluginConfigs = *c.Plugins
	sc.Telemetry = c.Telemetry
	sc.HealthChecks = c.HealthChecks

	// Write out deprecation warnings
	warnOnDeprecatedConfig(c, sc.Log)

	// Warn if we detect unknown config options. We need a logger to do this. In
	// the future, we can move from warning to bailing out (once folks have had
	// ample time to detect any pre-existing errors)
	//
	// TODO: Move this check into validateConfig for 0.11.0
	warnOnUnknownConfig(c, sc.Log)

	return sc, nil
}

func validateConfig(c *Config) error {
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

	if c.Server.Federation != nil {
		// TODO: Remove this check once the deprecated experimental federation options are removed.
		if isDeprecatedFederationConfigUsed(c.Server.Experimental) {
			return errors.New("cannot configure federation section along with any of " +
				"the following deprecated experimental options: bundle_endpoint_acme, " +
				"bundle_endpoint_enabled, bundle_endpoint_address, bundle_endpoint_port, " +
				"federates_with")
		}

		if c.Server.Federation.BundleEndpoint != nil &&
			c.Server.Federation.BundleEndpoint.ACME != nil {
			acme := c.Server.Federation.BundleEndpoint.ACME

			if acme.DomainName == "" {
				return errors.New("federation.bundle_endpoint.acme.domain_name must be configured")
			}

			if acme.Email == "" {
				return errors.New("federation.bundle_endpoint.acme.email must be configured")
			}
		}

		for td, tdConfig := range c.Server.Federation.FederatesWith {
			if tdConfig.BundleEndpoint.Address == "" {
				return fmt.Errorf("federation.federates_with[\"%s\"].bundle_endpoint.address must be configured", td)
			}
		}
	} else { // TODO: Remove this else block once the deprecated experimental federation options are removed.
		if acme := c.Server.Experimental.DeprecatedBundleEndpointACME; acme != nil {
			if acme.DomainName == "" {
				return errors.New("bundle_endpoint_acme domain_name must be configured")
			}

			if acme.Email == "" {
				return errors.New("bundle_endpoint_acme email must be configured")
			}
		}

		for td, tdConfig := range c.Server.Experimental.DeprecatedFederatesWith {
			if tdConfig.BundleEndpointAddress == "" {
				return fmt.Errorf("%s bundle_endpoint_address must be configured", td)
			}
		}

		c.Server.Federation = federationConfigFromExperimentalConfig(c.Server.Experimental)
	}

	// TODO: Remove this check at 0.11.0 (after warnOnUnknownConfig bails out instead of only display a warning)
	if c.Server.DeprecatedSVIDTTL != "" {
		return errors.New(`the "svid_ttl" configurable has been deprecated and renamed to "default_svid_ttl"; please update your configuration`)
	}

	return nil
}

// TODO: Remove this function once the deprecated experimental federation options are removed.
func isDeprecatedFederationConfigUsed(ec experimentalConfig) bool {
	return ec.DeprecatedBundleEndpointACME != nil ||
		ec.DeprecatedBundleEndpointEnabled ||
		ec.DeprecatedBundleEndpointAddress != "" ||
		ec.DeprecatedBundleEndpointPort != 0 ||
		len(ec.DeprecatedFederatesWith) > 0
}

// TODO: Remove this function once the deprecated experimental federation options are removed.
func federationConfigFromExperimentalConfig(ec experimentalConfig) *federationConfig {
	if isDeprecatedFederationConfigUsed(ec) {
		fc := &federationConfig{}
		if ec.DeprecatedBundleEndpointEnabled {
			fc.BundleEndpoint = &bundleEndpointConfig{
				ACME:    ec.DeprecatedBundleEndpointACME,
				Address: ec.DeprecatedBundleEndpointAddress,
				Port:    ec.DeprecatedBundleEndpointPort,
			}
		}
		if len(ec.DeprecatedFederatesWith) > 0 {
			fc.FederatesWith = make(map[string]federatesWithConfig)
			for td, cfg := range ec.DeprecatedFederatesWith {
				fc.FederatesWith[td] = federatesWithConfig{
					BundleEndpoint: federatesWithBundleEndpointConfig{
						Address:   cfg.BundleEndpointAddress,
						Port:      cfg.BundleEndpointPort,
						SpiffeID:  cfg.BundleEndpointSpiffeID,
						UseWebPKI: cfg.UseWebPKI,
					},
				}
			}
		}
		return fc
	}

	return nil
}

func warnOnDeprecatedConfig(c *Config, l logrus.FieldLogger) {
	if isDeprecatedFederationConfigUsed(c.Server.Experimental) {
		l.Warn("The experimental federation configurables will be deprecated in a future release. Please see issue #1619 and the configuration documentation for more information.")
	}
}

func warnOnUnknownConfig(c *Config, l logrus.FieldLogger) {
	if len(c.UnusedKeys) != 0 {
		l.Warnf("Detected unknown top-level config options: %q; this will be fatal in a future release.", c.UnusedKeys)
	}

	if c.Server != nil {
		if len(c.Server.UnusedKeys) != 0 {
			l.Warnf("Detected unknown server config options: %q; this will be fatal in a future release.", c.Server.UnusedKeys)
		}

		if cs := c.Server.CASubject; cs != nil && len(cs.UnusedKeys) != 0 {
			l.Warnf("Detected unknown CA Subject config options: %q; this will be fatal in a future release.", cs.UnusedKeys)
		}

		// TODO: Re-enable unused key detection for experimental config. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		//if len(c.Server.Experimental.UnusedKeys) != 0 {
		//	l.Warnf("Detected unknown experimental config options: %q; this will be fatal in a future release.", c.Server.Experimental.UnusedKeys)
		//}

		if c.Server.Federation != nil {
			// TODO: Re-enable unused key detection for experimental config. See
			// https://github.com/spiffe/spire/issues/1101 for more information
			//
			//if len(c.Server.Federation.UnusedKeys) != 0 {
			//	l.Warnf("Detected unknown federation config options: %q; this will be fatal in a future release.", c.Server.Federation.UnusedKeys)
			//}

			if c.Server.Federation.BundleEndpoint != nil {
				if len(c.Server.Federation.BundleEndpoint.UnusedKeys) != 0 {
					l.Warnf("Detected unknown federation config options: %q; this will be fatal in a future release.", c.Server.Federation.BundleEndpoint.UnusedKeys)
				}

				if bea := c.Server.Federation.BundleEndpoint.ACME; bea != nil && len(bea.UnusedKeys) != 0 {
					l.Warnf("Detected unknown ACME config options: %q; this will be fatal in a future release.", bea.UnusedKeys)
				}
			}

			for k, v := range c.Server.Federation.FederatesWith {
				if len(v.UnusedKeys) != 0 {
					l.Warnf("Detected unknown federation config options for %q: %q; this will be fatal in a future release.", k, v.UnusedKeys)
				}
			}
		}
	}

	// TODO: Re-enable unused key detection for telemetry. See
	// https://github.com/spiffe/spire/issues/1101 for more information
	//
	//if len(c.Telemetry.UnusedKeys) != 0 {
	//	l.Warnf("Detected unknown telemetry config options: %q; this will be fatal in a future release.", c.Telemetry.UnusedKeys)
	//}

	if p := c.Telemetry.Prometheus; p != nil && len(p.UnusedKeys) != 0 {
		l.Warnf("Detected unknown Prometheus config options: %q; this will be fatal in a future release.", p.UnusedKeys)
	}

	for _, v := range c.Telemetry.DogStatsd {
		if len(v.UnusedKeys) != 0 {
			l.Warnf("Detected unknown DogStatsd config options: %q; this will be fatal in a future release.", v.UnusedKeys)
		}
	}

	for _, v := range c.Telemetry.Statsd {
		if len(v.UnusedKeys) != 0 {
			l.Warnf("Detected unknown Statsd config options: %q; this will be fatal in a future release.", v.UnusedKeys)
		}
	}

	for _, v := range c.Telemetry.M3 {
		if len(v.UnusedKeys) != 0 {
			l.Warnf("Detected unknown M3 config options: %q; this will be fatal in a future release.", v.UnusedKeys)
		}
	}

	if p := c.Telemetry.InMem; p != nil && len(p.UnusedKeys) != 0 {
		l.Warnf("Detected unknown InMem config options: %q; this will be fatal in a future release.", p.UnusedKeys)
	}

	if len(c.HealthChecks.UnusedKeys) != 0 {
		l.Warnf("Detected unknown health check config options: %q; this will be fatal in a future release.", c.HealthChecks.UnusedKeys)
	}
}

func defaultConfig() *Config {
	return &Config{
		Server: &serverConfig{
			BindAddress:         "0.0.0.0",
			BindPort:            8081,
			LogLevel:            defaultLogLevel,
			LogFormat:           log.DefaultFormat,
			RegistrationUDSPath: defaultSocketPath,
			Experimental:        experimentalConfig{},
		},
	}
}

func caKeyTypeFromString(s string) (keymanager.KeyType, error) {
	switch strings.ToLower(s) {
	case "rsa-2048":
		return keymanager.KeyType_RSA_2048, nil
	case "rsa-4096":
		return keymanager.KeyType_RSA_4096, nil
	case "ec-p256":
		return keymanager.KeyType_EC_P256, nil
	case "ec-p384":
		return keymanager.KeyType_EC_P384, nil
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("CA key type %q is unknown; must be one of [rsa-2048, rsa-4096, ec-p256, ec-p384]", s)
	}
}

// hasExpectedTTLs is a function that checks if ca_ttl is less than default_svid_ttl * 6. SPIRE Server prepares a new CA certificate when 1/2 of the CA lifetime has elapsed in order to give ample time for the new trust bundle to propagate. However, it does not start using it until 5/6th of the CA lifetime. So its normal for an SVID TTL to be capped to 1/6th of the CA TTL. In order to get the expected lifetime on SVID TTLs, the CA TTL should be 6x.
func hasExpectedTTLs(caTTL, svidTTL time.Duration) bool {
	if caTTL == 0 {
		caTTL = ca.DefaultCATTL
	}
	if svidTTL == 0 {
		svidTTL = ca.DefaultX509SVIDTTL
	}

	thresh := ca.KeyActivationThreshold(time.Now(), time.Now().Add(caTTL))
	return caTTL-time.Until(thresh) >= svidTTL
}

func isPKIXNameEmpty(name pkix.Name) bool {
	// pkix.Name contains slices which make it directly incomparable. We could
	// do a field by field check since it is unlikely that pkix.Name will grow,
	// but reflect.DeepEqual is more convenient and safe for this particular
	// use.
	return reflect.DeepEqual(name, pkix.Name{})
}
