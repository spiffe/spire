package run

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
)

const (
	defaultConfigPath    = "conf/server/server.conf"
	defaultBindAddress   = "127.0.0.1"
	defaultBindPort      = 8081
	defaultBindHTTPPort  = 8080
	defaultLogLevel      = "INFO"
	defaultBaseSVIDTtl   = 999999
	defaultServerSVIDTtl = 999999
	defaultUmask         = 0077
)

// runConfig represents available configurables for file and CLI options
type runConfig struct {
	Server         serverConfig                                  `hcl:"server"`
	PluginsConfigs map[string]map[string]catalog.HclPluginConfig `hcl:"plugins"`
}

type serverConfig struct {
	BindAddress   string `hcl:"bind_address"`
	BindPort      int    `hcl:"bind_port"`
	BindHTTPPort  int    `hcl:"bind_http_port"`
	TrustDomain   string `hcl:"trust_domain"`
	LogFile       string `hcl:"log_file"`
	LogLevel      string `hcl:"log_level"`
	BaseSVIDTtl   int    `hcl:"base_svid_ttl"`
	ServerSVIDTtl int    `hcl:"server_svid_ttl"`
	ConfigPath    string `hcl:"config_path"`
	Umask         string `hcl:"umask"`
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
	err = mergeConfigs(c, fileConfig, cliConfig)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = validateConfig(c)
	if err != nil {
		fmt.Println(err.Error())
	}

	signalListener(c.ShutdownCh)

	server := &server.Server{Config: c}
	err = server.Run()
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

	flags.StringVar(&c.Server.BindAddress, "bindAddress", defaultBindAddress, "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.Server.BindPort, "serverPort", defaultBindPort, "Port number of the SPIRE server")
	flags.IntVar(&c.Server.BindHTTPPort, "bindHTTPPort", defaultBindHTTPPort, "HTTP Port number of the SPIRE server")
	flags.StringVar(&c.Server.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.StringVar(&c.Server.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.Server.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")
	flags.IntVar(&c.Server.BaseSVIDTtl, "baseSVIDTtl", 0, "TTL to use when creating the Base SVID")
	flags.IntVar(&c.Server.ServerSVIDTtl, "serverSVIDTtl", 0, "TTL to use when creating the Server SVID")
	flags.StringVar(&c.Server.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.StringVar(&c.Server.Umask, "umask", "", "Umask value to use for new files")

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

	if cmd.Server.BaseSVIDTtl != 0 {
		orig.BaseSVIDTtl = int32(cmd.Server.BaseSVIDTtl)
	}

	if cmd.Server.ServerSVIDTtl != 0 {
		orig.ServerSVIDTtl = int32(cmd.Server.ServerSVIDTtl)
	}

	if cmd.PluginsConfigs != nil {
		orig.PluginsConfigs = cmd.PluginsConfigs
	}
	if orig.PluginsConfigs != nil {
		cmd.PluginsConfigs = orig.PluginsConfigs
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
	errCh := make(chan error, 3)
	shutdownCh := make(chan struct{})

	// log.NewLogger() cannot return error when using STDOUT
	logger, _ := log.NewLogger(defaultLogLevel, "")
	bindAddress := &net.TCPAddr{}
	serverHTTPAddress := &net.TCPAddr{}

	return &server.Config{
		ErrorCh:         errCh,
		ShutdownCh:      shutdownCh,
		Log:             logger,
		BindAddress:     bindAddress,
		BindHTTPAddress: serverHTTPAddress,
		BaseSVIDTtl:     defaultBaseSVIDTtl,
		ServerSVIDTtl:   defaultServerSVIDTtl,
		Umask:           defaultUmask,
	}
}

func signalListener(ch chan struct{}) {
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

		var stop struct{}
		select {
		case <-signalCh:
			ch <- stop
		}
	}()
	return
}
