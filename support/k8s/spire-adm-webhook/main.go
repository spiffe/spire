package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

var (
	configFlag = flag.String("config", "spire-adm-webhook.conf", "configuration file")
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

	log, err := log.NewLogger(config.Log.Level, config.Log.Path)
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

	webhook := NewWebhook(WebhookConfig{
		Log:         log,
		R:           registration.NewRegistrationClient(serverConn),
		TrustDomain: config.TrustDomain,
		Cluster:     config.Cluster,
		PodLabel:    config.PodLabel,
	})

	log.Info("Initializing webhook")
	if err := webhook.Initialize(ctx); err != nil {
		return err
	}

	log.WithField("addr", config.Addr).Info("Serving webhook")
	return http.ListenAndServeTLS(config.Addr, config.CertPath, config.KeyPath, NewHandler(webhook))
}
