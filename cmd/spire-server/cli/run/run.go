package run

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/imdario/mergo"
	"github.com/mitchellh/cli"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/config"
	"github.com/spiffe/spire/pkg/common/diskcertmanager"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/server"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	bundleClient "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

const (
	commandName = "run"

	defaultConfigPath = "conf/server/server.conf"
	defaultLogLevel   = "INFO"
)

var defaultRateLimit = true

// Config contains all available configurables, arranged by section
type Config struct {
	Server             *serverConfig          `hcl:"server"`
	Plugins            ast.Node               `hcl:"plugins"`
	Telemetry          telemetry.FileConfig   `hcl:"telemetry"`
	HealthChecks       health.Config          `hcl:"health_checks"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type serverConfig struct {
	AdminIDs           []string           `hcl:"admin_ids"`
	AgentTTL           string             `hcl:"agent_ttl"`
	AuditLogEnabled    bool               `hcl:"audit_log_enabled"`
	BindAddress        string             `hcl:"bind_address"`
	BindPort           int                `hcl:"bind_port"`
	CAKeyType          string             `hcl:"ca_key_type"`
	CASubject          *caSubjectConfig   `hcl:"ca_subject"`
	CATTL              string             `hcl:"ca_ttl"`
	DataDir            string             `hcl:"data_dir"`
	DefaultX509SVIDTTL string             `hcl:"default_x509_svid_ttl"`
	DefaultJWTSVIDTTL  string             `hcl:"default_jwt_svid_ttl"`
	Experimental       experimentalConfig `hcl:"experimental"`
	Federation         *federationConfig  `hcl:"federation"`
	JWTIssuer          string             `hcl:"jwt_issuer"`
	JWTKeyType         string             `hcl:"jwt_key_type"`
	LogFile            string             `hcl:"log_file"`
	LogLevel           string             `hcl:"log_level"`
	LogFormat          string             `hcl:"log_format"`
	LogSourceLocation  bool               `hcl:"log_source_location"`
	RateLimit          rateLimitConfig    `hcl:"ratelimit"`
	SocketPath         string             `hcl:"socket_path"`
	TrustDomain        string             `hcl:"trust_domain"`

	ConfigPath string
	ExpandEnv  bool

	// Undocumented configurables
	ProfilingEnabled bool     `hcl:"profiling_enabled"`
	ProfilingPort    int      `hcl:"profiling_port"`
	ProfilingFreq    int      `hcl:"profiling_freq"`
	ProfilingNames   []string `hcl:"profiling_names"`

	// Temporary configurables
	// UseLegacyDownstreamX509CATTL is deprecated and should be removed in SPIRE 1.12.0.
	UseLegacyDownstreamX509CATTL *bool `hcl:"use_legacy_downstream_x509_ca_ttl"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type experimentalConfig struct {
	AuthOpaPolicyEngine   *authpolicy.OpaEngineConfig `hcl:"auth_opa_policy_engine"`
	CacheReloadInterval   string                      `hcl:"cache_reload_interval"`
	EventsBasedCache      bool                        `hcl:"events_based_cache"`
	PruneEventsOlderThan  string                      `hcl:"prune_events_older_than"`
	EventTimeout          string                      `hcl:"event_timeout"`
	SQLTransactionTimeout string                      `hcl:"sql_transaction_timeout"`
	RequirePQKEM          bool                        `hcl:"require_pq_kem"`

	Flags fflag.RawConfig `hcl:"feature_flags"`

	NamedPipeName string `hcl:"named_pipe_name"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type caSubjectConfig struct {
	Country            []string               `hcl:"country"`
	Organization       []string               `hcl:"organization"`
	CommonName         string                 `hcl:"common_name"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type federationConfig struct {
	BundleEndpoint     *bundleEndpointConfig          `hcl:"bundle_endpoint"`
	FederatesWith      map[string]federatesWithConfig `hcl:"federates_with"`
	UnusedKeyPositions map[string][]token.Pos         `hcl:",unusedKeyPositions"`
}

type bundleEndpointConfig struct {
	Address     string `hcl:"address"`
	Port        int    `hcl:"port"`
	RefreshHint string `hcl:"refresh_hint"`

	ACME    *bundleEndpointACMEConfig `hcl:"acme"`
	Profile ast.Node                  `hcl:"profile"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type bundleEndpointConfigProfile struct {
	HTTPSSPIFFE        *bundleEndpointProfileHTTPSSPIFFEConfig `hcl:"https_spiffe"`
	HTTPSWeb           *bundleEndpointProfileHTTPSWebConfig    `hcl:"https_web"`
	UnusedKeyPositions map[string][]token.Pos                  `hcl:",unusedKeyPositions"`
}

type bundleEndpointProfileHTTPSWebConfig struct {
	ACME            *bundleEndpointACMEConfig      `hcl:"acme"`
	ServingCertFile *bundleEndpointServingCertFile `hcl:"serving_cert_file"`
}

type bundleEndpointProfileHTTPSSPIFFEConfig struct{}

type bundleEndpointServingCertFile struct {
	CertFilePath        string        `hcl:"cert_file_path"`
	KeyFilePath         string        `hcl:"key_file_path"`
	FileSyncInterval    time.Duration `hcl:"-"`
	RawFileSyncInterval string        `hcl:"file_sync_interval"`
}

type bundleEndpointACMEConfig struct {
	DirectoryURL       string                 `hcl:"directory_url"`
	DomainName         string                 `hcl:"domain_name"`
	Email              string                 `hcl:"email"`
	ToSAccepted        bool                   `hcl:"tos_accepted"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type federatesWithConfig struct {
	BundleEndpointURL     string                 `hcl:"bundle_endpoint_url"`
	BundleEndpointProfile ast.Node               `hcl:"bundle_endpoint_profile"`
	UnusedKeyPositions    map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type bundleEndpointProfileConfig struct {
	HTTPSSPIFFE        *httpsSPIFFEProfileConfig `hcl:"https_spiffe"`
	HTTPSWeb           *httpsWebProfileConfig    `hcl:"https_web"`
	UnusedKeyPositions map[string][]token.Pos    `hcl:",unusedKeyPositions"`
}

type httpsSPIFFEProfileConfig struct {
	EndpointSPIFFEID   string                 `hcl:"endpoint_spiffe_id"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}

type httpsWebProfileConfig struct{}

type rateLimitConfig struct {
	Attestation        *bool                  `hcl:"attestation"`
	Signing            *bool                  `hcl:"signing"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
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

// Run Command struct
type Command struct {
	ctx                context.Context
	logOptions         []log.Option
	env                *common_cli.Env
	allowUnknownConfig bool
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

func LoadConfig(name string, args []string, logOptions []log.Option, output io.Writer, allowUnknownConfig bool) (*server.Config, error) {
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

	err = fflag.Load(input.Server.Experimental.Flags)
	if err != nil {
		return nil, fmt.Errorf("error loading feature flags: %w", err)
	}

	return NewServerConfig(input, logOptions, allowUnknownConfig)
}

// Run the SPIFFE Server
func (cmd *Command) Run(args []string) int {
	c, err := LoadConfig(commandName, args, cmd.logOptions, cmd.env.Stderr, cmd.allowUnknownConfig)
	if err != nil {
		_, _ = fmt.Fprintln(cmd.env.Stderr, err)
		return 1
	}

	// Set umask before starting up the server
	common_cli.SetUmask(c.Log)

	s := server.New(*c)

	ctx := cmd.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = s.Run(ctx)
	if err != nil {
		c.Log.WithError(err).Error("Server crashed")
		return 1
	}

	c.Log.Info("Server stopped gracefully")
	return 0
}

// Synopsis of the command
func (*Command) Synopsis() string {
	return "Runs the server"
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
	flags.BoolVar(&c.LogSourceLocation, "logSourceLocation", false, "Include source file, line number and function name in log lines")
	flags.StringVar(&c.LogLevel, "logLevel", "", "'debug', 'info', 'warn', or 'error'")
	flags.StringVar(&c.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.BoolVar(&c.ExpandEnv, "expandEnv", false, "Expand environment variables in SPIRE config file")
	c.addOSFlags(flags)

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

func NewServerConfig(c *Config, logOptions []log.Option, allowUnknownConfig bool) (*server.Config, error) {
	sc := &server.Config{}

	if err := validateConfig(c); err != nil {
		return nil, err
	}

	logOptions = append(logOptions,
		log.WithLevel(c.Server.LogLevel),
		log.WithFormat(c.Server.LogFormat),
	)
	if c.Server.LogSourceLocation {
		logOptions = append(logOptions, log.WithSourceLocation())
	}
	var reopenableFile *log.ReopenableFile
	if c.Server.LogFile != "" {
		var err error
		reopenableFile, err = log.NewReopenableFile(c.Server.LogFile)
		if err != nil {
			return nil, err
		}
		logOptions = append(logOptions, log.WithReopenableOutputFile(reopenableFile))
	}

	logger, err := log.NewLogger(logOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not start logger: %w", err)
	}
	sc.Log = logger

	if reopenableFile != nil {
		sc.LogReopener = log.ReopenOnSignal(logger, reopenableFile)
	}

	bindAddress, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(strings.Trim(c.Server.BindAddress, "[]"), strconv.Itoa(c.Server.BindPort)))
	if err != nil {
		return nil, fmt.Errorf(`could not resolve bind address "%s:%d": %w`, c.Server.BindAddress, c.Server.BindPort, err)
	}
	sc.BindAddress = bindAddress
	c.Server.setDefaultsIfNeeded()

	addr, err := c.Server.getAddr()
	if err != nil {
		return nil, err
	}
	sc.BindLocalAddress = addr

	sc.DataDir = c.Server.DataDir
	sc.AuditLogEnabled = c.Server.AuditLogEnabled

	td, err := spiffeid.TrustDomainFromString(c.Server.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("could not parse trust_domain %q: %w", c.Server.TrustDomain, err)
	}
	common_cli.WarnOnLongTrustDomainName(td, logger)
	sc.TrustDomain = td

	if c.Server.RateLimit.Attestation == nil {
		c.Server.RateLimit.Attestation = &defaultRateLimit
	}
	sc.RateLimit.Attestation = *c.Server.RateLimit.Attestation

	if c.Server.RateLimit.Signing == nil {
		c.Server.RateLimit.Signing = &defaultRateLimit
	}
	sc.RateLimit.Signing = *c.Server.RateLimit.Signing

	if c.Server.Federation != nil {
		if c.Server.Federation.BundleEndpoint != nil {
			sc.Federation.BundleEndpoint = &bundle.EndpointConfig{
				Address: &net.TCPAddr{
					IP:   net.ParseIP(c.Server.Federation.BundleEndpoint.Address),
					Port: c.Server.Federation.BundleEndpoint.Port,
				},
			}

			if c.Server.Federation.BundleEndpoint.RefreshHint != "" {
				refreshHint, err := time.ParseDuration(c.Server.Federation.BundleEndpoint.RefreshHint)
				if err != nil {
					return nil, fmt.Errorf("could not parse refresh_hint %q: %w", c.Server.Federation.BundleEndpoint.RefreshHint, err)
				}

				if refreshHint >= 24*time.Hour {
					sc.Log.Warn("Bundle endpoint refresh hint set to a high value. To cover " +
						"the case of unscheduled trust bundle updates, it's recommended to " +
						"have a smaller value, e.g. 5m")
				}

				if refreshHint < bundleutil.MinimumRefreshHint {
					sc.Log.Warn("Bundle endpoint refresh hint set too low. SPIRE will not " +
						"refresh more often than 1 minute")
				}

				sc.Federation.BundleEndpoint.RefreshHint = refreshHint
			} else {
				refreshHint := 5 * time.Minute
				sc.Federation.BundleEndpoint.RefreshHint = refreshHint
			}

			if c.Server.Federation.BundleEndpoint != nil {
				err := setBundleEndpointConfigProfile(c.Server.Federation.BundleEndpoint, sc.DataDir, sc.Log, &sc.Federation)
				if err != nil {
					return nil, err
				}
			}
		}

		federatesWith := map[spiffeid.TrustDomain]bundleClient.TrustDomainConfig{}

		for trustDomain, config := range c.Server.Federation.FederatesWith {
			td, err := spiffeid.TrustDomainFromString(trustDomain)
			if err != nil {
				return nil, err
			}

			var trustDomainConfig *bundleClient.TrustDomainConfig
			switch {
			case config.BundleEndpointProfile != nil:
				trustDomainConfig, err = parseBundleEndpointProfile(config)
				if err != nil {
					return nil, fmt.Errorf("error parsing federation relationship for trust domain %q: %w", trustDomain, err)
				}
			default:
				return nil, fmt.Errorf("federation configuration for trust domain %q: missing bundle endpoint configuration", trustDomain)
			}
			federatesWith[td] = *trustDomainConfig
		}
		sc.Federation.FederatesWith = federatesWith
	}

	sc.ProfilingEnabled = c.Server.ProfilingEnabled
	sc.ProfilingPort = c.Server.ProfilingPort
	sc.ProfilingFreq = c.Server.ProfilingFreq
	sc.ProfilingNames = c.Server.ProfilingNames

	sc.TLSPolicy = tlspolicy.Policy{
		RequirePQKEM: c.Server.Experimental.RequirePQKEM,
	}

	tlspolicy.LogPolicy(sc.TLSPolicy, log.NewHCLogAdapter(logger, "tlspolicy"))

	for _, adminID := range c.Server.AdminIDs {
		id, err := spiffeid.FromString(adminID)
		if err != nil {
			return nil, fmt.Errorf("could not parse admin ID %q: %w", adminID, err)
		}
		sc.AdminIDs = append(sc.AdminIDs, id)
	}

	if c.Server.AgentTTL != "" {
		ttl, err := time.ParseDuration(c.Server.AgentTTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse agent ttl %q: %w", c.Server.AgentTTL, err)
		}
		sc.AgentTTL = ttl
	}

	switch {
	case c.Server.DefaultX509SVIDTTL != "":
		ttl, err := time.ParseDuration(c.Server.DefaultX509SVIDTTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse default X509 SVID ttl %q: %w", c.Server.DefaultX509SVIDTTL, err)
		}
		sc.X509SVIDTTL = ttl
	default:
		// If neither new nor deprecated config value is set, then use hard-coded default TTL
		// Note, due to back-compat issues we cannot set this default inside defaultConfig() function
		sc.X509SVIDTTL = credtemplate.DefaultX509SVIDTTL
	}

	if c.Server.DefaultJWTSVIDTTL != "" {
		ttl, err := time.ParseDuration(c.Server.DefaultJWTSVIDTTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse default JWT SVID ttl %q: %w", c.Server.DefaultJWTSVIDTTL, err)
		}
		sc.JWTSVIDTTL = ttl
	} else {
		// If not set using new field then use hard-coded default TTL
		// Note, due to back-compat issues we cannot set this default inside defaultConfig() function
		sc.JWTSVIDTTL = credtemplate.DefaultJWTSVIDTTL
	}

	if c.Server.CATTL != "" {
		ttl, err := time.ParseDuration(c.Server.CATTL)
		if err != nil {
			return nil, fmt.Errorf("could not parse default CA ttl %q: %w", c.Server.CATTL, err)
		}
		sc.CATTL = ttl
	}

	if c.Server.UseLegacyDownstreamX509CATTL != nil {
		sc.Log.Warn("'use_legacy_downstream_x509_ca_ttl' is deprecated and will be removed in a future release")
		sc.UseLegacyDownstreamX509CATTL = *c.Server.UseLegacyDownstreamX509CATTL
		if sc.UseLegacyDownstreamX509CATTL {
			sc.Log.Warn("Using legacy downstream X509 CA TTL calculation; this option will be removed in a future release")
		} else {
			sc.Log.Info("Using preferred downstream X509 CA TTL calculation")
		}
	} else {
		// The flag should be removed in SPIRE 1.13.0.
		sc.UseLegacyDownstreamX509CATTL = false
		sc.Log.Info("Using preferred downstream X509 CA TTL calculation")
	}

	// If the configured TTLs can lead to surprises, then do our best to log an
	// accurate message and guide the user to resolution
	ttlChecks := []struct {
		name string
		ttl  time.Duration
	}{
		{
			name: "default_x509_svid_ttl",
			ttl:  sc.X509SVIDTTL,
		},
		{
			name: "default_jwt_svid_ttl",
			ttl:  sc.JWTSVIDTTL,
		},
	}

	for _, ttlCheck := range ttlChecks {
		if !hasCompatibleTTL(sc.CATTL, ttlCheck.ttl) {
			var message string

			switch {
			case ttlCheck.ttl < manager.MaxSVIDTTL():
				// TTL is smaller than our cap, but the CA TTL
				// is not large enough to accommodate it
				message = fmt.Sprintf("%s is too high for the configured "+
					"ca_ttl value. SVIDs with shorter lifetimes may "+
					"be issued. Please set %s to %v or less, or the ca_ttl "+
					"to %v or more, to guarantee the full %s lifetime "+
					"when CA rotations are scheduled.",
					ttlCheck.name, ttlCheck.name, printMaxSVIDTTL(sc.CATTL), printMinCATTL(ttlCheck.ttl), ttlCheck.name,
				)
			case sc.CATTL < manager.MinCATTLForSVIDTTL(manager.MaxSVIDTTL()):
				// TTL is larger than our cap, it needs to be
				// decreased no matter what. Additionally, the CA TTL is
				// too small to accommodate the maximum SVID TTL.
				message = fmt.Sprintf("%s is too high and "+
					"the ca_ttl is too low. SVIDs with shorter lifetimes "+
					"may be issued. Please set %s to %v or less, and the "+
					"ca_ttl to %v or more, to guarantee the full %s "+
					"lifetime when CA rotations are scheduled.",
					ttlCheck.name, ttlCheck.name, printDuration(manager.MaxSVIDTTL()), printMinCATTL(manager.MaxSVIDTTL()), ttlCheck.name,
				)
			default:
				// TTL is larger than our cap and needs to be
				// decreased.
				message = fmt.Sprintf("%s is too high. SVIDs with shorter "+
					"lifetimes may be issued. Please set %s to %v or less "+
					"to guarantee the full %s lifetime when CA rotations "+
					"are scheduled.",
					ttlCheck.name, ttlCheck.name, printMaxSVIDTTL(sc.CATTL), ttlCheck.name,
				)
			}
			sc.Log.Warn(message)
		}
	}

	if c.Server.CAKeyType != "" {
		keyType, err := keyTypeFromString(c.Server.CAKeyType)
		if err != nil {
			return nil, fmt.Errorf("error parsing ca_key_type: %w", err)
		}
		sc.CAKeyType = keyType
		sc.JWTKeyType = keyType
	} else {
		sc.CAKeyType = keymanager.ECP256
		sc.JWTKeyType = keymanager.ECP256
	}

	if c.Server.JWTKeyType != "" {
		sc.JWTKeyType, err = keyTypeFromString(c.Server.JWTKeyType)
		if err != nil {
			return nil, fmt.Errorf("error parsing jwt_key_type: %w", err)
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
		sc.CASubject = credtemplate.DefaultX509CASubject()
	}

	sc.PluginConfigs, err = catalog.PluginConfigsFromHCLNode(c.Plugins)
	if err != nil {
		return nil, err
	}
	sc.Telemetry = c.Telemetry
	sc.HealthChecks = c.HealthChecks

	if !allowUnknownConfig {
		if err := checkForUnknownConfig(c, sc.Log); err != nil {
			return nil, err
		}
	}

	if cmp.Diff(experimentalConfig{}, c.Server.Experimental) != "" {
		sc.Log.Warn("Experimental features have been enabled. Please see doc/upgrading.md for upgrade and compatibility considerations for experimental features.")
	}

	if c.Server.Experimental.CacheReloadInterval != "" {
		interval, err := time.ParseDuration(c.Server.Experimental.CacheReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("could not parse cache reload interval: %w", err)
		}
		sc.CacheReloadInterval = interval
	}

	if c.Server.Experimental.PruneEventsOlderThan != "" {
		interval, err := time.ParseDuration(c.Server.Experimental.PruneEventsOlderThan)
		if err != nil {
			return nil, fmt.Errorf("could not parse prune events interval: %w", err)
		}
		sc.PruneEventsOlderThan = interval
	}

	if c.Server.Experimental.SQLTransactionTimeout != "" {
		sc.Log.Warn("experimental.sql_transaction_timeout is deprecated, use experimental.event_timeout instead")
		interval, err := time.ParseDuration(c.Server.Experimental.SQLTransactionTimeout)
		if err != nil {
			return nil, fmt.Errorf("could not parse SQL transaction timeout interval: %w", err)
		}
		sc.EventTimeout = interval
	}

	if c.Server.Experimental.EventTimeout != "" {
		interval, err := time.ParseDuration(c.Server.Experimental.EventTimeout)
		if err != nil {
			return nil, fmt.Errorf("could not parse event timeout interval: %w", err)
		}
		sc.EventTimeout = interval
	}

	if c.Server.Experimental.EventsBasedCache {
		sc.Log.Info("Using events based cache")
	}

	sc.EventsBasedCache = c.Server.Experimental.EventsBasedCache
	sc.AuthOpaPolicyEngineConfig = c.Server.Experimental.AuthOpaPolicyEngine

	for _, f := range c.Server.Experimental.Flags {
		sc.Log.Warnf("Developer feature flag %q has been enabled", f)
	}

	return sc, nil
}

func setBundleEndpointConfigProfile(config *bundleEndpointConfig, dataDir string, log logrus.FieldLogger, federationConfig *server.FederationConfig) error {
	switch {
	case config.ACME != nil && config.Profile != nil:
		return errors.New("either bundle endpoint 'acme' or 'profile' can be set, but not both")

	case config.ACME != nil:
		log.Warn("ACME configuration within the bundle_endpoint is deprecated. Please use ACME configuration as part of the https_web profile instead.")
		federationConfig.BundleEndpoint.ACME = configToACMEConfig(config.ACME, dataDir)
		return nil

	case config.Profile == nil:
		log.Warn("Bundle endpoint is configured but has no profile set, using https_spiffe as default; please configure a profile explicitly. This will be fatal in a future release.")
		return nil
	}

	// Profile is set, parse it
	configString, err := parseBundleEndpointProfileASTNode(config.Profile)
	if err != nil {
		return err
	}

	profileConfig := new(bundleEndpointConfigProfile)
	if err := hcl.Decode(profileConfig, configString); err != nil {
		return fmt.Errorf("failed to decode configuration: %w", err)
	}

	switch {
	case profileConfig.HTTPSWeb != nil:
		switch {
		case profileConfig.HTTPSWeb.ACME != nil:
			federationConfig.BundleEndpoint.ACME = configToACMEConfig(profileConfig.HTTPSWeb.ACME, dataDir)
			return nil
		case profileConfig.HTTPSWeb.ServingCertFile != nil:
			federationConfig.BundleEndpoint.DiskCertManager, err = configToDiskCertManager(profileConfig.HTTPSWeb.ServingCertFile, log)
			return err
		default:
			return errors.New("malformed https_web profile configuration: 'acme' or 'serving_cert_file' is required")
		}

	// For now ignore SPIFFE configuration
	case profileConfig.HTTPSSPIFFE != nil:
		return nil

	default:
		return errors.New(`unknown bundle endpoint profile configured; current supported profiles are "https_spiffe" and 'https_web"`)
	}
}

func configToACMEConfig(acme *bundleEndpointACMEConfig, dataDir string) *bundle.ACMEConfig {
	return &bundle.ACMEConfig{
		DirectoryURL: acme.DirectoryURL,
		DomainName:   acme.DomainName,
		CacheDir:     filepath.Join(dataDir, "bundle-acme"),
		Email:        acme.Email,
		ToSAccepted:  acme.ToSAccepted,
	}
}

func configToDiskCertManager(serviceCertFile *bundleEndpointServingCertFile, log logrus.FieldLogger) (*diskcertmanager.DiskCertManager, error) {
	fileSyncInterval, err := time.ParseDuration(serviceCertFile.RawFileSyncInterval)
	if err != nil {
		return nil, err
	}

	serviceCertFile.FileSyncInterval = fileSyncInterval
	if serviceCertFile.FileSyncInterval == time.Duration(0) {
		serviceCertFile.FileSyncInterval = time.Hour
	}

	return diskcertmanager.New(
		&diskcertmanager.Config{
			CertFilePath:     serviceCertFile.CertFilePath,
			KeyFilePath:      serviceCertFile.KeyFilePath,
			FileSyncInterval: serviceCertFile.FileSyncInterval,
		},
		nil,
		log,
	)
}

func parseBundleEndpointProfile(config federatesWithConfig) (trustDomainConfig *bundleClient.TrustDomainConfig, err error) {
	configString, err := parseBundleEndpointProfileASTNode(config.BundleEndpointProfile)
	if err != nil {
		return nil, err
	}

	profileConfig := new(bundleEndpointProfileConfig)
	if err := hcl.Decode(profileConfig, configString); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	var endpointProfile bundleClient.EndpointProfileInfo
	switch {
	case profileConfig.HTTPSWeb != nil:
		endpointProfile = bundleClient.HTTPSWebProfile{}
	case profileConfig.HTTPSSPIFFE != nil:
		spiffeID, err := spiffeid.FromString(profileConfig.HTTPSSPIFFE.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("could not get endpoint SPIFFE ID: %w", err)
		}
		endpointProfile = bundleClient.HTTPSSPIFFEProfile{EndpointSPIFFEID: spiffeID}
	default:
		return nil, errors.New(`no bundle endpoint profile defined; current supported profiles are "https_spiffe" and 'https_web"`)
	}

	return &bundleClient.TrustDomainConfig{
		EndpointURL:     config.BundleEndpointURL,
		EndpointProfile: endpointProfile,
	}, nil
}

func parseBundleEndpointProfileASTNode(node ast.Node) (string, error) {
	// First check the number of bundle endpoint profiles in the config
	objectList, ok := node.(*ast.ObjectList)
	if !ok {
		return "", errors.New("malformed configuration")
	}
	if len(objectList.Items) != 1 {
		return "", errors.New("exactly one bundle endpoint profile is expected")
	}

	var data bytes.Buffer
	if err := printer.DefaultConfig.Fprint(&data, node); err != nil {
		return "", err
	}
	return data.String(), nil
}

func validateConfig(c *Config) error {
	if c.Server == nil {
		return errors.New("server section must be configured")
	}

	if c.Server.BindAddress == "" || c.Server.BindPort == 0 {
		return errors.New("bind_address and bind_port must be configured")
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
			switch {
			case tdConfig.BundleEndpointURL == "":
				return fmt.Errorf("federation.federates_with[\"%s\"].bundle_endpoint_url must be configured", td)
			case !strings.HasPrefix(strings.ToLower(tdConfig.BundleEndpointURL), "https://"):
				return fmt.Errorf("federation.federates_with[\"%s\"].bundle_endpoint_url must use the HTTPS protocol; URL found: %q", td, tdConfig.BundleEndpointURL)
			}
		}
	}

	if c.Server.Experimental.EventTimeout != "" && c.Server.Experimental.SQLTransactionTimeout != "" {
		return errors.New("both experimental sql_transaction_timeout and event_timeout set, only set event_timeout")
	}

	return c.validateOS()
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

	if c.Server != nil {
		if len(c.Server.UnusedKeyPositions) != 0 {
			detectedUnknown("server", c.Server.UnusedKeyPositions)
		}

		if cs := c.Server.CASubject; cs != nil && len(cs.UnusedKeyPositions) != 0 {
			detectedUnknown("ca_subject", cs.UnusedKeyPositions)
		}

		if rl := c.Server.RateLimit; len(rl.UnusedKeyPositions) != 0 {
			detectedUnknown("ratelimit", rl.UnusedKeyPositions)
		}

		// TODO: Re-enable unused key detection for experimental config. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		// if len(c.Server.Experimental.UnusedKeyPositions) != 0 {
		//	detectedUnknown("experimental", c.Server.Experimental.UnusedKeyPositions)
		// }

		if c.Server.Federation != nil {
			// TODO: Re-enable unused key detection for federation config. See
			// https://github.com/spiffe/spire/issues/1101 for more information
			//
			// if len(c.Server.Federation.UnusedKeyPositions) != 0 {
			//	detectedUnknown("federation", c.Server.Federation.UnusedKeyPositions)
			// }

			if c.Server.Federation.BundleEndpoint != nil {
				if len(c.Server.Federation.BundleEndpoint.UnusedKeyPositions) != 0 {
					detectedUnknown("bundle endpoint", c.Server.Federation.BundleEndpoint.UnusedKeyPositions)
				}

				if bea := c.Server.Federation.BundleEndpoint.ACME; bea != nil && len(bea.UnusedKeyPositions) != 0 {
					detectedUnknown("bundle endpoint ACME", bea.UnusedKeyPositions)
				}
			}

			// TODO: Re-enable unused key detection for bundle endpoint profile config. See
			// https://github.com/spiffe/spire/issues/1101 for more information
			//
			// for k, v := range c.Server.Federation.FederatesWith {
			//	if len(v.UnusedKeyPositions) != 0 {
			//		detectedUnknown(fmt.Sprintf("federates_with %q", k), v.UnusedKeyPositions)
			//	}
			// }
		}
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
	return &Config{
		Server: &serverConfig{
			BindAddress:  "0.0.0.0",
			BindPort:     8081,
			CATTL:        credtemplate.DefaultX509CATTL.String(),
			LogLevel:     defaultLogLevel,
			LogFormat:    log.DefaultFormat,
			Experimental: experimentalConfig{},
		},
	}
}

func keyTypeFromString(s string) (keymanager.KeyType, error) {
	switch strings.ToLower(s) {
	case "rsa-2048":
		return keymanager.RSA2048, nil
	case "rsa-4096":
		return keymanager.RSA4096, nil
	case "ec-p256":
		return keymanager.ECP256, nil
	case "ec-p384":
		return keymanager.ECP384, nil
	default:
		return keymanager.KeyTypeUnset, fmt.Errorf("key type %q is unknown; must be one of [rsa-2048, rsa-4096, ec-p256, ec-p384]", s)
	}
}

// hasCompatibleTTL checks if we can guarantee the configured SVID TTL given the
// configured CA TTL. If we detect that a new SVID TTL may be cut short due to
// a scheduled CA rotation, this function will return false. This method should
// be called for each SVID TTL we may use
func hasCompatibleTTL(caTTL time.Duration, svidTTL time.Duration) bool {
	return svidTTL <= manager.MaxSVIDTTLForCATTL(caTTL)
}

// printMaxSVIDTTL calculates the display string for a sufficiently short SVID TTL
func printMaxSVIDTTL(caTTL time.Duration) string {
	return printDuration(manager.MaxSVIDTTLForCATTL(caTTL))
}

// printMinCATTL calculates the display string for a sufficiently large CA TTL
func printMinCATTL(svidTTL time.Duration) string {
	return printDuration(manager.MinCATTLForSVIDTTL(svidTTL))
}

func printDuration(d time.Duration) string {
	s := d.Truncate(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func isPKIXNameEmpty(name pkix.Name) bool {
	// pkix.Name contains slices which make it directly incomparable. We could
	// do a field by field check since it is unlikely that pkix.Name will grow,
	// but reflect.DeepEqual is more convenient and safe for this particular
	// use.
	return reflect.DeepEqual(name, pkix.Name{})
}
