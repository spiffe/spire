package command

import (
	"crypto/x509"
	"crypto/x509/pkix"
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
	defaultDataDir     = "."
	defaultLogFile     = "spire-server.log"
	defaultLogLevel    = "INFO"
	defaultPluginDir   = "../../plugin/agent/.conf"
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
	config := newAgentConfig()

	err := setOptsFromFile(config, defaultConfigPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	setOptsFromCLI(config)

	// TODO: Handle graceful shutdown?
	signalListener(config.ErrorCh)

	a := &agent.Agent{Config: config}
	err = a.Run()
	if err != nil {
		config.Log.Log("msg", err.Error)
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
	if new.ServerAddress == "" || new.ServerPort == "" {
		return fmt.Errorf("ServerAddress and ServerPort are required")
	}
	serverAddress := net.ParseIP(new.ServerAddress)
	serverPort, err := strconv.Atoi(new.ServerPort)
	if serverAddress == nil {
		return fmt.Errorf("ServerAddress %s is not a valid IP", new.ServerAddress)
	}
	if err != nil {
		return fmt.Errorf("ServerPort %s is not a valid port number", new.ServerPort)
	}
	orig.ServerAddress = &net.TCPAddr{IP: serverAddress, Port: serverPort}

	// Handle trust domain
	if new.TrustDomain == "" {
		return fmt.Errorf("TrustDomain is required")
	}
	orig.TrustDomain = new.TrustDomain

	// Parse trust bundle
	if new.TrustBundlePath == "" {
		return fmt.Errorf("TrustBundlePath is required")
	}
	bundle, err := parseTrustBundle(new.TrustBundlePath)
	if err != nil {
		return fmt.Errorf("Error parsing trust bundle: %s", err)
	}
	orig.TrustBundle = bundle

	// Parse bind address
	bindAddr := stringDefault(new.BindAddress, defaultBindAddress)
	bindPort := stringDefault(new.BindPort, defaultBindPort)
	addr := net.ParseIP(bindAddr)
	port, err := strconv.Atoi(bindPort)
	if addr == nil {
		return fmt.Errorf("BindAddress %s is not a valid IP", bindAddr)
	}
	if err != nil {
		return fmt.Errorf("BindPort %s is not a valid port number", bindPort)
	}
	orig.BindAddress = &net.TCPAddr{IP: addr, Port: port}

	// TODO: Make my default sane
	orig.DataDir = stringDefault(new.DataDir, defaultDataDir)
	orig.PluginDir = stringDefault(new.PluginDir, defaultPluginDir)

	logFile := stringDefault(new.LogFile, defaultLogFile)
	logLevel := stringDefault(new.LogLevel, defaultLogLevel)
	log, err := helpers.NewLogger(logLevel, logFile)
	if err != nil {
		return fmt.Errorf("Could not access log file: %s", err)
	}
	orig.Log = log

	return nil
}

func newAgentConfig() *agent.Config {
	certDN := &pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	return &agent.Config{
		CertDN:     certDN,
		ErrorCh:    errCh,
		ShutdownCh: shutdownCh,
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
