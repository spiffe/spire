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
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
)

const (
	defaultConfigPath    = "conf/server/server.conf"
	defaultBindAddress   = "127.0.0.1"
	defaultBindPort      = "8081"
	defaultBindHTTPPort  = "8080"
	defaultLogLevel      = "INFO"
	defaultPluginDir     = "conf/server/plugin"
	defaultBaseSVIDTtl   = 999999
	defaultServerSVIDTtl = 999999
	defaultUmask         = 0077
)

// CmdConfig represents available configurables for file and CLI options
type CmdConfig struct {
	BindAddress   string
	BindPort      int
	BindHTTPPort  int
	TrustDomain   string
	PluginDir     string
	LogFile       string
	LogLevel      string
	BaseSVIDTtl   int
	ServerSVIDTtl int
	ConfigPath    string
	Umask         string
}

//RunCommand itself
type RunCommand struct {
}

//Help prints the server cmd usage
func (*RunCommand) Help() string {
	_, err := parseFlags([]string{"-h"})
	return err.Error()
}

//Run the SPIFFE Server
func (*RunCommand) Run(args []string) int {
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
func (*RunCommand) Synopsis() string {
	return "Runs the server"
}

func parseFile(filePath string) (*CmdConfig, error) {
	c := &CmdConfig{}

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

func parseFlags(args []string) (*CmdConfig, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &CmdConfig{}

	flags.StringVar(&c.BindAddress, "bindAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.BindPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.IntVar(&c.BindHTTPPort, "bindHTTPPort", 0, "HTTP Port number of the SPIRE server")
	flags.StringVar(&c.TrustDomain, "trustDomain", "", "The trust domain that this server belongs to")
	flags.StringVar(&c.PluginDir, "pluginDir", "", "Plugin conf.d configuration directory")
	flags.StringVar(&c.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")
	flags.IntVar(&c.BaseSVIDTtl, "baseSVIDTtl", 0, "TTL to use when creating the Base SVID")
	flags.IntVar(&c.ServerSVIDTtl, "serverSVIDTtl", 0, "TTL to use when creating the Server SVID")
	flags.StringVar(&c.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.StringVar(&c.Umask, "umask", "", "Umask value to use for new files")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func mergeConfigs(c *server.Config, fileConfig, cliConfig *CmdConfig) error {
	// CLI > File, merge fileConfig first
	err := mergeConfig(c, fileConfig)
	if err != nil {
		return err
	}

	return mergeConfig(c, cliConfig)
}

func mergeConfig(orig *server.Config, cmd *CmdConfig) error {
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
		PluginDir:       defaultPluginDir,
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
