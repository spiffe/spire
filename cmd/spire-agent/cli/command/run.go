package command

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/sri/helpers"
	"github.com/spiffe/sri/pkg/agent"
)

const (
	defaultConfigPath = ".conf/default_agent_config.hcl"

	defaultBindAddress = "127.0.0.1:8081"
	defaultDataDir     = "."
	defaultLogFile     = "spire-server.log"
	defaultLogLevel    = "INFO"
	defaultPluginDir   = "../../plugin/agent/.conf"
)

// Struct representing available configurables for file and CLI
// options
type CliConfig struct {
	ServerAddress   string
	TrustDomain     string
	TrustBundlePath string

	BindAddress string
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

	err := setOptsFromFile(&config, defaultConfigPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	setOptsFromCLI(&config)

	// TODO: Handle graceful shutdown?
	signalListener(config.ErrorCh)

	a := &agent.Agent{Config: config}
	err = a.Run()
	if err != nil {
		config.Log.Error(err.Error)
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

	return mergeAgentConfig(&c, fileConfig)
}

func setOptsFromCLI(*agent.Config) {
	// TODO
	return
}

func mergeAgentConfig(orig *agent.Config, new CliConfig) error {
	if new.ServerAddress == "" {
		return fmt.Errorf("ServerAddress is required")
	}
	addr := &net.Addr{Network: "tcp", String: new.ServerAddress}
	orig.ServerAddress = addr

	if new.TrustDomain == "" {
		return fmt.Errorf("TrustDomain is required")
	}
	orig.TrustDomain = new.TrustDomain

	if new.TrustBundlePath == "" {
		return fmt.Errorf("TrustBundlePath is required")
	}
	bundle, err = parseTrustBundle(new.TrustBundlePath)
	if err != nil {
		return fmt.Errorf("Error parsing trust bundle: %s", err)
	}
	orig.TrustBundle = bundle

	bindAddr := stringDefault(new.BindAddress, defaultBindAddress)
	orig.BindAddress = &net.Addr{Network: "tcp", String: bindAddr}

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
		Country:      "US",
		Organization: "SPIRE",
	}
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	return &agent.Config{
		CertDN:     certDN,
		ErrorCh:    errCh,
		ShutdownCh: shutdownCh,
	}
}

func parseTrustBundle(path string) *x509.CertPool {
	data, err := ioutil.ReadAll(path)
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AddCertsFromPEM(data); !ok {
		return fmt.Errorf("No valid certificates found at %s", path)
	}
	return certPool
}

func stringDefault(option string, defaultValue string) string {
	if opt == "" {
		return defaultValue
	}

	return option
}

func signalListener(ch chan error) {
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		errChannel <- fmt.Errorf("%s", <-signalCh)
	}()
	return
}
