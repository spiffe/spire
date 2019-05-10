package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

var (
	configFlag = flag.String("config", "k8s-workload-registrar.conf", "configuration file")
)

func main() {
	flag.Parse()
	if err := run(context.Background(), *configFlag); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string) error {
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}

	log, err := log.NewLogger(config.LogLevel, config.LogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	log.WithField("socket_path", config.ServerSocketPath).Info("Dialing server")
	serverConn, err := grpc.DialContext(ctx, "unix://"+config.ServerSocketPath, grpc.WithInsecure())
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}
	defer serverConn.Close()

	controller := NewController(ControllerConfig{
		Log:         log,
		R:           registration.NewRegistrationClient(serverConn),
		TrustDomain: config.TrustDomain,
		Cluster:     config.Cluster,
		PodLabel:    config.PodLabel,
	})

	log.Info("Initializing registrar")
	if err := controller.Initialize(ctx); err != nil {
		return err
	}

	server, err := NewServer(ServerConfig{
		Log:                    log,
		Addr:                   config.Addr,
		Handler:                NewWebhookHandler(controller),
		CertPath:               config.CertPath,
		KeyPath:                config.KeyPath,
		CaCertPath:             config.CaCertPath,
		SkipClientVerification: config.SkipClientVerification,
	})
	if err != nil {
		return err
	}
	return server.Run(ctx)
}
