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
	defaultConfigPath   = "conf/server/server.conf"
	defaultBindAddress  = "127.0.0.1"
	defaultBindPort     = 8081
	defaultBindHTTPPort = 8080
	defaultLogLevel     = "INFO"
	defaultPluginDir    = "conf/server/plugin"
	defaultUmask        = 0077
)

// RunConfig represents available configurables for file and CLI options
type RunConfig struct {
	BindAddress   string                                        `hcl:"bind_address"`
	BindPort      int                                           `hcl:"bind_port"`
	BindHTTPPort  int                                           `hcl:"bind_http_port"`
	TrustDomain   string                                        `hcl:"trust_domain"`
	PluginDir     string                                        `hcl:"plugin_dir"`
	LogFile       string                                        `hcl:"log_file"`
	LogLevel      string                                        `hcl:"log_level"`
	BaseSVIDTtl   int                                           `hcl:"base_svid_ttl"`
	ServerSVIDTtl int                                           `hcl:"server_svid_ttl"`
	ConfigPath    string                                        `hcl:"config_path"`
	Umask         string                                        `hcl:"umask"`
	PluginConfigs map[string]map[string]catalog.HclPluginConfig `hcl:"plugins"`
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

	fileConfig, err := parseFile(cliConfig.ConfigPath)
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

	server := &server.Server{Config: c}
	signalListener(server)

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

func parseFile(filePath string) (*RunConfig, error) {
	c := &RunConfig{}

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

func parseFlags(args []string) (*RunConfig, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &RunConfig{}

	flags.StringVar(&c.BindAddress, "bindAddress", defaultBindAddress, "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.BindPort, "serverPort", defaultBindPort, "Port number of the SPIRE server")
	flags.IntVar(&c.BindHTTPPort, "bindHTTPPort", defaultBindHTTPPort, "HTTP Port number of the SPIRE server")
	flags.StringVar(&c.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.StringVar(&c.PluginDir, "pluginDir", "", "Plugin conf.d configuration directory")
	flags.StringVar(&c.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")
	flags.StringVar(&c.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.StringVar(&c.Umask, "umask", "", "Umask value to use for new files")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func mergeConfigs(c *server.Config, fileConfig, cliConfig *RunConfig) error {
	// CLI > File, merge fileConfig first
	err := mergeConfig(c, fileConfig)
	if err != nil {
		return err
	}

	return mergeConfig(c, cliConfig)
}

func mergeConfig(orig *server.Config, cmd *RunConfig) error {
	// Parse server address
	if cmd.BindAddress != "" {
		ip := net.ParseIP(cmd.BindAddress)
		if ip == nil {
			return fmt.Errorf("It was not possible to parse BindAdress: %v", cmd.BindAddress)
		}
		orig.BindAddress.IP = ip
		orig.BindHTTPAddress.IP = ip
	}

	if cmd.BindPort != 0 {
		orig.BindAddress.Port = cmd.BindPort
	}

	if cmd.BindHTTPPort != 0 {
		orig.BindHTTPAddress.Port = cmd.BindHTTPPort
	}

	if cmd.TrustDomain != "" {
		trustDomain := url.URL{
			Scheme: "spiffe",
			Host:   cmd.TrustDomain,
		}

		orig.TrustDomain = trustDomain
	}

	if cmd.PluginDir != "" {
		orig.PluginDir = cmd.PluginDir
	}

	// Handle log file and level
	if cmd.LogFile != "" || cmd.LogLevel != "" {
		logLevel := defaultLogLevel
		if cmd.LogLevel != "" {
			logLevel = cmd.LogLevel
		}

		logger, err := log.NewLogger(logLevel, cmd.LogFile)
		if err != nil {
			return fmt.Errorf("Could not open log file %s: %s", cmd.LogFile, err)
		}

		orig.Log = logger
	}

	if cmd.Umask != "" {
		umask, err := strconv.ParseInt(cmd.Umask, 0, 0)
		if err != nil {
			return fmt.Errorf("Could not parse umask %s: %s", cmd.Umask, err)
		}
		orig.Umask = int(umask)
	}

	if cmd.BaseSVIDTtl != 0 {
		orig.BaseSVIDTtl = int32(cmd.BaseSVIDTtl)
	}

	if cmd.ServerSVIDTtl != 0 {
		orig.ServerSVIDTtl = int32(cmd.ServerSVIDTtl)
	}

	if cmd.PluginConfigs != nil {
		orig.PluginConfigs = cmd.PluginConfigs
	}
	if orig.PluginConfigs != nil {
		cmd.PluginConfigs = orig.PluginConfigs
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
		PluginDir:       defaultPluginDir,
		Log:             logger,
		BindAddress:     bindAddress,
		BindHTTPAddress: serverHTTPAddress,
		Umask:           defaultUmask,
	}
}

func signalListener(s *server.Server) {
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-signalCh:
			s.Shutdown()
		}
	}()
	return
}
