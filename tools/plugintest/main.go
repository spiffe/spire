package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	agent_catalog "github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/agent/workloadattestor"
	"github.com/zeebo/errs"
)

var (
	logFlag    = flag.Bool("log", false, "enable logging")
	configFlag = flag.String("config", "", "configuration file for the plugin")
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %+v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "not enough arguments")
		flag.Usage()
		os.Exit(1)
	}
	if len(args) > 2 {
		fmt.Fprintln(os.Stderr, "ignoring extra arguments", args[2:])
	}

	pluginPath := args[0]
	pid, err := strconv.Atoi(args[1])
	if err != nil {
		return errors.New("pid argument is malformed")
	}
	pluginName := filepath.Base(pluginPath)

	var log logrus.FieldLogger
	if *logFlag {
		logger := logrus.New()
		logger.SetLevel(logrus.DebugLevel)
		log = logger
	}

	// TODO: provide a way to set global config
	var globalConfig catalog.GlobalConfig

	var config string
	if *configFlag != "" {
		configBytes, err := ioutil.ReadFile(*configFlag)
		if err != nil {
			return errs.New("unable load to config from %q: %v", *configFlag, err)
		}
		config = string(configBytes)
	}

	pluginConfig := []catalog.PluginConfig{
		{
			Name: pluginName,
			Type: workloadattestor.Type,
			Path: pluginPath,
			Data: config,
		},
	}

	var plugin workloadattestor.WorkloadAttestor
	closer, err := catalog.Fill(ctx, catalog.Config{
		Log:           log,
		KnownPlugins:  agent_catalog.KnownPlugins(),
		KnownServices: agent_catalog.KnownServices(),
		GlobalConfig:  globalConfig,
		PluginConfig:  pluginConfig,
	}, &plugin)
	if err != nil {
		return err
	}
	defer closer.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	res, err := plugin.Attest(ctx, &workloadattestor.AttestRequest{Pid: int32(pid)})
	if err != nil {
		return fmt.Errorf("failed to attest pid %d: %v", pid, err)
	}

	if res.Selectors == nil || len(res.Selectors) == 0 {
		return fmt.Errorf("attestation didn't return any selectors")
	}

	fmt.Printf("Workload Attestion Results (Pid %d)\n", pid)
	for _, s := range res.Selectors {
		fmt.Printf("  %s:%s\n", s.Type, s.Value)
	}
	return nil
}
