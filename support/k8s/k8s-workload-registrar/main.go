package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/spiffe/spire/pkg/common/version"
)

var (
	versionFlag = flag.Bool("version", false, "print version")
	configFlag  = flag.String("config", "k8s-workload-registrar.conf", "configuration file")
)

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Println(version.Version())
		os.Exit(0)
	}

	if err := run(context.Background(), *configFlag); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string) error {
	mode, err := LoadMode(configPath)
	if err != nil {
		return err
	}

	defer mode.Close()

	return mode.Run(ctx)
}
