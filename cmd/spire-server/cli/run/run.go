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
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server"
	bundleClient "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
)

const (
	defaultConfigPath         = "conf/server/server.conf"
	defaultSocketPath         = "/tmp/spire-registration.sock"
	defaultLogLevel           = "INFO"
	defaultBundleEndpointPort = 443
)

// config contains all available configurables, arranged by section
type config struct {
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
	JWTIssuer           string             `hcl:"jwt_issuer"`
	LogFile             string             `hcl:"log_file"`
	LogLevel            string             `hcl:"log_level"`
	LogFormat           string             `hcl:"log_format"`
	RegistrationUDSPath string             `hcl:"registration_uds_path"`
	DeprecatedSVIDTTL   string             `hcl:"svid_ttl"`
	DefaultSVIDTTL      string             `hcl:"default_svid_ttl"`
	TrustDomain         string             `hcl:"trust_domain"`
	UpstreamBundle      *bool              `hcl:"upstream_bundle"`

	ConfigPath string

	// Undocumented configurables
	ProfilingEnabled bool     `hcl:"profiling_enabled"`
	ProfilingPort    int      `hcl:"profiling_port"`
	ProfilingFreq    int      `hcl:"profiling_freq"`
	ProfilingNames   []string `hcl:"profiling_names"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type experimentalConfig struct {
	AllowAgentlessNodeAttestors bool `hcl:"allow_agentless_node_attestors"`

	BundleEndpointEnabled bool                           `hcl:"bundle_endpoint_enabled"`
	BundleEndpointAddress string                         `hcl:"bundle_endpoint_address"`
	BundleEndpointPort    int                            `hcl:"bundle_endpoint_port"`
	BundleEndpointACME    *bundleEndpointACMEConfig      `hcl:"bundle_endpoint_acme"`
	FederatesWith         map[string]federatesWithConfig `hcl:"federates_with"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type caSubjectConfig struct {
	Country      []string `hcl:"country"`
	Organization []string `hcl:"organization"`
	CommonName   string   `hcl:"common_name"`
	UnusedKeys   []string `hcl:",unusedKeys"`
}

type bundleEndpointACMEConfig struct {
	DirectoryURL string   `hcl:"directory_url"`
	DomainName   string   `hcl:"domain_name"`
	Email        string   `hcl:"email"`
	ToSAccepted  bool     `hcl:"tos_accepted"`
	UnusedKeys   []string `hcl:",unusedKeys"`
}

type federatesWithConfig struct {
	BundleEndpointAddress  string   `hcl:"bundle_endpoint_address"`
	BundleEndpointPort     int      `hcl:"bundle_endpoint_port"`
	BundleEndpointSpiffeID string   `hcl:"bundle_endpoint_spiffe_id"`
	UnusedKeys             []string `hcl:",unusedKeys"`
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
	flags.Var(newMaybeBoolValue(&c.UpstreamBundle), "upstreamBundle", "Include upstream CA certificates in the bundle")

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

	ll := strings.ToUpper(c.Server.LogLevel)
	lf := strings.ToUpper(c.Server.LogFormat)
	logger, err := log.NewLogger(ll, lf, c.Server.LogFile)
	if err != nil {
		return nil, fmt.Errorf("could not start logger: %s", err)
	}
	sc.Log = logger

	if c.Server.UpstreamBundle != nil {
		sc.UpstreamBundle = *c.Server.UpstreamBundle
	}
	sc.Experimental.AllowAgentlessNodeAttestors = c.Server.Experimental.AllowAgentlessNodeAttestors
	sc.Experimental.BundleEndpointEnabled = c.Server.Experimental.BundleEndpointEnabled
	sc.Experimental.BundleEndpointAddress = &net.TCPAddr{
		IP:   net.ParseIP(c.Server.Experimental.BundleEndpointAddress),
		Port: c.Server.Experimental.BundleEndpointPort,
	}

	if acme := c.Server.Experimental.BundleEndpointACME; acme != nil {
		sc.Experimental.BundleEndpointACME = &bundle.ACMEConfig{
			DirectoryURL: acme.DirectoryURL,
			DomainName:   acme.DomainName,
			CacheDir:     filepath.Join(sc.DataDir, "bundle-acme"),
			Email:        acme.Email,
			ToSAccepted:  acme.ToSAccepted,
		}
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

	if c.Server.DeprecatedSVIDTTL != "" {
		if c.Server.DefaultSVIDTTL != "" {
			sc.Log.Warn("Both `svid_ttl` and `default_svid_ttl` are set. `svid_ttl` will be ignored")
		} else {
			// TODO: remove in 0.10.0
			sc.Log.Warn("The `svid_ttl` configurable has been renamed to `default_svid_ttl`; please update your configuration.")
			ttl, err := time.ParseDuration(c.Server.DeprecatedSVIDTTL)
			if err != nil {
				return nil, fmt.Errorf("could not parse default SVID ttl %q: %v", c.Server.DeprecatedSVIDTTL, err)
			}
			sc.SVIDTTL = ttl
		}
	}

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
	}

	sc.PluginConfigs = *c.Plugins
	sc.Telemetry = c.Telemetry
	sc.HealthChecks = c.HealthChecks

	// Write out deprecation warnings
	switch {
	case len(sc.PluginConfigs[upstreamca.Type]) == 0:
		// no UpstreamCA configured
	case c.Server.UpstreamBundle == nil:
		// relying on the default upstream_bundle value of false
		sc.Log.Warn("The `upstream_bundle` configurable is not set, and you are using an UpstreamCA. The default value will be changed from `false` to `true` in a future release.  Please see issue #1095 and the configuration documentation for more information.")
	}

	// Warn if we detect unknown config options. We need a logger to do this. In
	// the future, we can move from warning to bailing out (once folks have had
	// ample time to detect any pre-existing errors)
	//
	// TODO: Move this check into validateConfig for 0.11.0
	warnOnUnknownConfig(c, sc.Log)

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

	if acme := c.Server.Experimental.BundleEndpointACME; acme != nil {
		if acme.DomainName == "" {
			return errors.New("bundle_endpoint_acme domain_name must be configured")
		}

		if acme.Email == "" {
			return errors.New("bundle_endpoint_acme email must be configured")
		}
	}

	for td, tdConfig := range c.Server.Experimental.FederatesWith {
		if tdConfig.BundleEndpointAddress == "" {
			return fmt.Errorf("%s bundle_endpoint_address must be configured", td)
		}
	}

	return nil
}

func warnOnUnknownConfig(c *config, l logrus.FieldLogger) {
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

		if bea := c.Server.Experimental.BundleEndpointACME; bea != nil && len(bea.UnusedKeys) != 0 {
			l.Warnf("Detected unknown ACME config options: %q; this will be fatal in a future release.", bea.UnusedKeys)
		}

		for k, v := range c.Server.Experimental.FederatesWith {
			if len(v.UnusedKeys) != 0 {
				l.Warnf("Detected unknown federation config options for %q: %q; this will be fatal in a future release.", k, v.UnusedKeys)
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

type maybeBoolValue struct {
	p **bool
}

func newMaybeBoolValue(p **bool) *maybeBoolValue {
	return &maybeBoolValue{p: p}
}

func (b *maybeBoolValue) Set(s string) error {
	if b.p == nil {
		// This should never happen, but just in case.
		return errors.New("cannot set a zero-valued maybeBoolValue")
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		err = errors.New("parse error")
	}
	*b.p = &v
	return err
}

func (b *maybeBoolValue) String() string {
	var v bool
	if b.p != nil && *b.p != nil {
		v = **b.p
	}
	return strconv.FormatBool(v)
}

func (b maybeBoolValue) IsBoolFlag() bool { return true }
