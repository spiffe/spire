package command

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/helpers"
	"github.com/spiffe/spire/pkg/server"
)

const (
	defaultConfigPath     = ".conf/default_server_config.hcl"
	defaultServerAddress  = "127.0.0.1"
	defaultServerPort     = "8081"
	defaultServerHTTPPort = "8080"
	defaultDataDir        = "."
	defaultLogLevel       = "INFO"
	defaultPluginDir      = "../../plugin/server/.conf"
)

// CmdConfig represents available configurables for file and CLI options
type CmdConfig struct {
	ServerAddress   string
	ServerPort      int
	ServerHTTPPort  int
	TrustDomain     string
	PluginDir       string
	LogFile         string
	LogLevel        string
	BaseSpiffeIDTTL int
}

//RunCommand itself
type RunCommand struct {
}

//Help prints the server cmd usage
func (*RunCommand) Help() string {
	return setOptsFromCLI(newDefaultConfig(), []string{"-h"}).Error()
}

//Run the SPIFFE Server
func (*RunCommand) Run(args []string) int {
	config := newDefaultConfig()

	err := setOptsFromFile(config, defaultConfigPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = setOptsFromCLI(config, args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	err = validateConfig(config)
	if err != nil {
		fmt.Println(err.Error())
	}

	// TODO: Handle graceful shutdown?
	signalListener(config.ErrorCh)

	server := &server.Server{Config: config}
	err = server.Run()
	if err != nil {
		config.Logger.Log("msg", err.Error())
		return 1
	}

	return 0
}

//Synopsis of the command
func (*RunCommand) Synopsis() string {
	return "Runs the server"
}

func setOptsFromFile(c *server.Config, filePath string) error {
	fileConfig := &CmdConfig{}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	hclTree, err := hcl.Parse(string(data))
	if err != nil {
		return err
	}
	if err := hcl.DecodeObject(&fileConfig, hclTree); err != nil {
		return err
	}

	return mergeServerConfig(c, fileConfig)
}

func setOptsFromCLI(c *server.Config, args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	cmdConfig := &CmdConfig{}

	flags.StringVar(&cmdConfig.ServerAddress, "serverAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&cmdConfig.ServerPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.IntVar(&cmdConfig.ServerHTTPPort, "serverHTTPPort", 0, "HTTP Port number of the SPIRE server")
	flags.StringVar(&cmdConfig.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.StringVar(&cmdConfig.PluginDir, "pluginDir", "", "Plugin conf.d configuration directory")
	flags.StringVar(&cmdConfig.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&cmdConfig.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")

	err := flags.Parse(args)
	if err != nil {
		return err
	}

	return mergeServerConfig(c, cmdConfig)
}

func mergeServerConfig(orig *server.Config, cmd *CmdConfig) error {
	// Parse server address
	if cmd.ServerAddress != "" {
		ips, err := net.LookupIP(cmd.ServerAddress)
		if err != nil {
			return err
		}

		if len(ips) == 0 {
			return fmt.Errorf("Could not resolve ServerAddress %s", cmd.ServerAddress)
		}
		serverAddress := ips[0]

		orig.ServerAddress.IP = serverAddress
		orig.ServerHTTPAddress.IP = serverAddress
	}

	if cmd.ServerPort != 0 {
		orig.ServerAddress.Port = cmd.ServerPort
	}

	if cmd.ServerHTTPPort != 0 {
		orig.ServerHTTPAddress.Port = cmd.ServerHTTPPort
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

		logger, err := helpers.NewLogger(logLevel, cmd.LogFile)
		if err != nil {
			return fmt.Errorf("Could not open log file %s: %s", cmd.LogFile, err)
		}

		orig.Logger = logger
	}

	return nil
}

func validateConfig(c *server.Config) error {
	if c.ServerAddress.IP == nil || c.ServerAddress.Port == 0 {
		return errors.New("ServerAddress and ServerPort are required")
	}

	if c.ServerHTTPAddress.IP == nil || c.ServerHTTPAddress.Port == 0 {
		return errors.New("ServerAddress and ServerHTTPPort are required")
	}

	if c.TrustDomain.String() == "" {
		return errors.New("TrustDomain is required")
	}

	return nil
}

func newDefaultConfig() *server.Config {
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	// helpers.NewLogger() cannot return error when using STDOUT
	logger, _ := helpers.NewLogger(defaultLogLevel, "")
	serverAddress := &net.TCPAddr{}
	serverHTTPAddress := &net.TCPAddr{}

	return &server.Config{
		PluginDir:         defaultPluginDir,
		ErrorCh:           errCh,
		ShutdownCh:        shutdownCh,
		Logger:            logger,
		ServerAddress:     serverAddress,
		ServerHTTPAddress: serverHTTPAddress,
	}
}

func signalListener(ch chan error) {
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		ch <- fmt.Errorf("%s", <-signalCh)
	}()
	return
}
