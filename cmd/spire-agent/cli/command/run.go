package command

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/pkg/agent"
)

const (
	defaultConfigPath = ".conf/default_agent_config.hcl"

	defaultBindAddress = "127.0.0.1"
	defaultBindPort    = "8081"

	// TODO: Make my defaults sane
	defaultDataDir   = "."
	defaultLogLevel  = "INFO"
	defaultPluginDir = "../../plugin/agent/.conf"
)

// Struct representing available configurables for file and CLI
// options
type CmdConfig struct {
	ServerAddress   string
	ServerPort      int
	TrustDomain     string
	TrustBundlePath string

	BindAddress string
	BindPort    int
	DataDir     string
	PluginDir   string
	LogFile     string
	LogLevel    string
}

type RunCommand struct {
}

func (*RunCommand) Help() string {
	return setOptsFromCLI(newDefaultConfig(), []string{"-h"}).Error()
}

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

	agt := &agent.Agent{Config: config}
	err = agt.Run()
	if err != nil {
		config.Logger.Log("msg", err.Error())
		return 1
	}

	return 0
}

func (*RunCommand) Synopsis() string {
	return "Runs the agent"
}

func setOptsFromFile(c *agent.Config, filePath string) error {
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

	return mergeAgentConfig(c, fileConfig)
}

func setOptsFromCLI(c *agent.Config, args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	cmdConfig := &CmdConfig{}

	flags.StringVar(&cmdConfig.ServerAddress, "serverAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&cmdConfig.ServerPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.StringVar(&cmdConfig.TrustDomain, "trustDomain", "", "The trust domain that this agent belongs to")
	flags.StringVar(&cmdConfig.TrustBundlePath, "trustBundle", "", "Path to the SPIRE server CA bundle")
	flags.StringVar(&cmdConfig.BindAddress, "bindAddress", "", "Address that the workload API should bind to")
	flags.IntVar(&cmdConfig.BindPort, "bindPort", 0, "Port number that the workload API should listen on")
	flags.StringVar(&cmdConfig.DataDir, "dataDir", "", "A directory the agent can use for its runtime data")
	flags.StringVar(&cmdConfig.PluginDir, "pluginDir", "", "Plugin conf.d configuration directory")
	flags.StringVar(&cmdConfig.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&cmdConfig.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")

	err := flags.Parse(args)
	if err != nil {
		return err
	}

	return mergeAgentConfig(c, cmdConfig)
}

func mergeAgentConfig(orig *agent.Config, cmd *CmdConfig) error {
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
	}

	if cmd.ServerPort != 0 {
		orig.ServerAddress.Port = cmd.ServerPort
	}

	if cmd.TrustDomain != "" {
		trustDomain := url.URL{
			Scheme: "spiffe",
			Host:   cmd.TrustDomain,
		}

		orig.TrustDomain = trustDomain
	}

	// Parse trust bundle
	if cmd.TrustBundlePath != "" {
		bundle, err := parseTrustBundle(cmd.TrustBundlePath)
		if err != nil {
			return fmt.Errorf("Error parsing trust bundle: %s", err)
		}

		orig.TrustBundle = bundle
	}

	// Parse bind address
	if cmd.BindAddress != "" {
		ip := net.ParseIP(cmd.BindAddress)
		if ip == nil {
			return fmt.Errorf("BindAddress %s is not a valid IP", cmd.BindAddress)
		}

		orig.BindAddress.IP = ip
	}

	if cmd.BindPort != 0 {
		orig.BindAddress.Port = cmd.BindPort
	}

	if cmd.DataDir != "" {
		orig.DataDir = cmd.DataDir
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

func validateConfig(c *agent.Config) error {
	if c.ServerAddress.IP == nil || c.ServerAddress.Port == 0 {
		return errors.New("ServerAddress and ServerPort are required")
	}

	if c.TrustDomain.String() == "" {
		return errors.New("TrustDomain is required")
	}

	if c.TrustBundle == nil {
		return errors.New("TrustBundle is required")
	}

	return nil
}

func newDefaultConfig() *agent.Config {
	addr := net.ParseIP(defaultBindAddress)
	port, _ := strconv.Atoi(defaultBindPort)
	bindAddr := &net.TCPAddr{IP: addr, Port: port}

	certDN := &pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	// helpers.NewLogger() cannot return error when using STDOUT
	logger, _ := helpers.NewLogger(defaultLogLevel, "")
	serverAddress := &net.TCPAddr{}

	return &agent.Config{
		BindAddress:   bindAddr,
		CertDN:        certDN,
		DataDir:       defaultDataDir,
		PluginDir:     defaultPluginDir,
		ErrorCh:       errCh,
		ShutdownCh:    shutdownCh,
		Logger:        logger,
		ServerAddress: serverAddress,
	}
}

func parseTrustBundle(path string) (*x509.CertPool, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("No valid certificates found at %s", path)
	}
	return certPool, nil
}

func stringDefault(option string, defaultValue string) string {
	if option == "" {
		return defaultValue
	}

	return option
}

func signalListener(ch chan error) {
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		ch <- fmt.Errorf("%s", <-signalCh)
	}()
	return
}
