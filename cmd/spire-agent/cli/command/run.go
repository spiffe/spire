package command

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
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
type CliConfig struct {
	ServerAddress   string
	ServerPort      string
	TrustDomain     string
	TrustBundlePath string

	BindAddress string
	BindPort    string
	DataDir     string
	PluginDir   string
	LogFile     string
	LogLevel    string
}

type RunCommand struct {
}

func (*RunCommand) Help() string {
	return "Usage: spire-agent run"
}

func (*RunCommand) Run(args []string) int {
	config := newDefaultConfig()

	err := setOptsFromFile(config, defaultConfigPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	setOptsFromCLI(config)

	err = validateConfig(config)
	if err != nil {
		fmt.Println(err.Error())
	}

	// TODO: Handle graceful shutdown?
	signalListener(config.ErrorCh)

	a := &agent.Agent{Config: config}
	err = a.Run()
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
	fileConfig := &CliConfig{}

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

func setOptsFromCLI(*agent.Config) {
	// TODO
	return
}

func mergeAgentConfig(orig *agent.Config, new *CliConfig) error {
	// Parse server address
	if new.ServerAddress != "" {
		serverAddress := net.ParseIP(new.ServerAddress)
		if serverAddress == nil {
			// ServerAddress is not an IP, try to look it up
			ips, err := net.LookupIP(new.ServerAddress)
			if err != nil {
				return err
			}

			if len(ips) == 0 {
				return fmt.Errorf("Could not resolve ServerAddress %s", new.ServerAddress)
			}
			serverAddress = ips[0]
		}

		orig.ServerAddress.IP = serverAddress
	}

	// Parse server port
	if new.ServerPort != "" {
		serverPort, err := strconv.Atoi(new.ServerPort)
		if err != nil {
			return fmt.Errorf("ServerPort %s is not a valid port number", new.ServerPort)
		}

		orig.ServerAddress.Port = serverPort
	}

	if new.TrustDomain != "" {
		orig.TrustDomain = new.TrustDomain
	}

	// Parse trust bundle
	if new.TrustBundlePath != "" {
		bundle, err := parseTrustBundle(new.TrustBundlePath)
		if err != nil {
			return fmt.Errorf("Error parsing trust bundle: %s", err)
		}

		orig.TrustBundle = bundle
	}

	// Parse bind address
	if new.BindAddress != "" {
		ip := net.ParseIP(new.BindAddress)
		if ip == nil {
			return fmt.Errorf("BindAddress %s is not a valid IP", new.BindAddress)
		}

		orig.BindAddress.IP = ip
	}

	// Parse bind port
	if new.BindPort != "" {
		port, err := strconv.Atoi(new.BindPort)
		if err != nil {
			return fmt.Errorf("BindPort %s is not a valid port number", new.BindPort)
		}

		orig.BindAddress.Port = port
	}

	if new.DataDir != "" {
		orig.DataDir = new.DataDir
	}

	if new.PluginDir != "" {
		orig.PluginDir = new.PluginDir
	}

	// Handle log file and level
	if new.LogFile != "" || new.LogLevel != "" {
		logLevel := defaultLogLevel
		if new.LogLevel != "" {
			logLevel = new.LogLevel
		}

		logger, err := helpers.NewLogger(logLevel, new.LogFile)
		if err != nil {
			return fmt.Errorf("Could not open log file %s: %s", new.LogFile, err)
		}

		orig.Logger = logger
	}

	return nil
}

func validateConfig(c *agent.Config) error {
	if c.ServerAddress.IP == nil || c.ServerAddress.Port == 0 {
		return errors.New("ServerAddress and ServerPort are required")
	}

	if c.TrustDomain == "" {
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
