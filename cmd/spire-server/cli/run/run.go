package run

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server"
)

const (
	defaultConfigPath = "conf/server/server.conf"
	defaultLogLevel   = "INFO"
	defaultUmask      = 0077
)

// runConfig represents available configurables for file and CLI options
type runConfig struct {
	Server        serverConfig            `hcl:"server"`
	PluginConfigs catalog.PluginConfigMap `hcl:"plugins"`
}

type serverConfig struct {
	BindAddress      string `hcl:"bind_address"`
	BindPort         int    `hcl:"bind_port"`
	BindHTTPPort     int    `hcl:"bind_http_port"`
	TrustDomain      string `hcl:"trust_domain"`
	LogFile          string `hcl:"log_file"`
	LogLevel         string `hcl:"log_level"`
	BaseSVIDTtl      int    `hcl:"base_svid_ttl"`
	ServerSVIDTtl    int    `hcl:"server_svid_ttl"`
	ConfigPath       string
	Umask            string   `hcl:"umask"`
	UpstreamBundle   bool     `hcl:"upstream_bundle"`
	ProfilingEnabled bool     `hcl:"profiling_enabled"`
	ProfilingPort    int      `hcl:"profiling_port"`
	ProfilingFreq    int      `hcl:"profiling_freq"`
	ProfilingNames   []string `hcl:"profiling_names"`
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
		fmt.Println(err.Error())
		return 1
	}

	fileConfig, err := parseFile(cliConfig.Server.ConfigPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	c := newDefaultConfig()

	// Get the plugin configurations from the file
	c.PluginConfigs = fileConfig.PluginConfigs

	err = mergeConfigs(c, fileConfig, cliConfig)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = validateConfig(c)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	s := server.New(*c)

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
		return nil, err
	}
	hclTree, err := hcl.Parse(string(data))
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&c, hclTree); err != nil {
		return nil, err
	}

	return c, nil
}

func parseFlags(args []string) (*runConfig, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &runConfig{}

	flags.StringVar(&c.Server.BindAddress, "bindAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.Server.BindPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.IntVar(&c.Server.BindHTTPPort, "bindHTTPPort", 0, "HTTP Port number of the SPIRE server")
	flags.StringVar(&c.Server.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.StringVar(&c.Server.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.Server.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")
	flags.StringVar(&c.Server.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.StringVar(&c.Server.Umask, "umask", "", "Umask value to use for new files")
	flags.BoolVar(&c.Server.UpstreamBundle, "upstreamBundle", false, "Include upstream CA certificates in the bundle")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func mergeConfigs(c *server.Config, fileConfig, cliConfig *runConfig) error {
	// CLI > File, merge fileConfig first
	err := mergeConfig(c, fileConfig)
	if err != nil {
		return err
	}

	return mergeConfig(c, cliConfig)
}

func mergeConfig(orig *server.Config, cmd *runConfig) error {
	// Parse server address
	if cmd.Server.BindAddress != "" {
		ip := net.ParseIP(cmd.Server.BindAddress)
		if ip == nil {
			return fmt.Errorf("It was not possible to parse BindAdress: %v", cmd.Server.BindAddress)
		}
		orig.BindAddress.IP = ip
		orig.BindHTTPAddress.IP = ip
	}

	if cmd.Server.BindPort != 0 {
		orig.BindAddress.Port = cmd.Server.BindPort
	}

	if cmd.Server.BindHTTPPort != 0 {
		orig.BindHTTPAddress.Port = cmd.Server.BindHTTPPort
	}

	if cmd.Server.TrustDomain != "" {
		trustDomain := url.URL{
			Scheme: "spiffe",
			Host:   cmd.Server.TrustDomain,
		}

		orig.TrustDomain = trustDomain
	}

	// Handle log file and level
	if cmd.Server.LogFile != "" || cmd.Server.LogLevel != "" {
		logLevel := defaultLogLevel
		if cmd.Server.LogLevel != "" {
			logLevel = cmd.Server.LogLevel
		}

		logger, err := log.NewLogger(logLevel, cmd.Server.LogFile)
		if err != nil {
			return fmt.Errorf("Could not open log file %s: %s", cmd.Server.LogFile, err)
		}

		orig.Log = logger
	}

	if cmd.Server.Umask != "" {
		umask, err := strconv.ParseInt(cmd.Server.Umask, 0, 0)
		if err != nil {
			return fmt.Errorf("Could not parse umask %s: %s", cmd.Server.Umask, err)
		}
		orig.Umask = int(umask)
	}

	// TODO: CLI should be able to override with `false` value
	if cmd.Server.UpstreamBundle {
		orig.UpstreamBundle = cmd.Server.UpstreamBundle
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

	return nil
}

func validateConfig(c *server.Config) error {
	if c.BindAddress.IP == nil || c.BindAddress.Port == 0 {
		return errors.New("BindAddress and BindPort are required")
	}

	if c.BindHTTPAddress.IP == nil || c.BindHTTPAddress.Port == 0 {
		return errors.New("BindAddress and BindHTTPPort are required")
	}

	if c.TrustDomain.String() == "" {
		return errors.New("TrustDomain is required")
	}

	return nil
}

func newDefaultConfig() *server.Config {
	// log.NewLogger() cannot return error when using STDOUT
	logger, _ := log.NewLogger(defaultLogLevel, "")
	bindAddress := &net.TCPAddr{}
	serverHTTPAddress := &net.TCPAddr{}

	return &server.Config{
		Log:             logger,
		BindAddress:     bindAddress,
		BindHTTPAddress: serverHTTPAddress,
		Umask:           defaultUmask,
	}
}
