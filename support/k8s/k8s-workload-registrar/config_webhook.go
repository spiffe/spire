package main

import (
	"context"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/zeebo/errs"
)

const (
	defaultAddr       = ":8443"
	defaultCertPath   = "cert.pem"
	defaultKeyPath    = "key.pem"
	defaultCaCertPath = "cacert.pem"
)

type WebhookMode struct {
	CommonMode
	Addr                           string `hcl:"addr"`
	CaCertPath                     string `hcl:"cacert_path"`
	CertPath                       string `hcl:"cert_path"`
	InsecureSkipClientVerification bool   `hcl:"insecure_skip_client_verification"`
	KeyPath                        string `hcl:"key_path"`
}

func (c *WebhookMode) ParseConfig(hclConfig string) error {
	if err := hcl.Decode(c, hclConfig); err != nil {
		return errs.New("unable to decode configuration: %v", err)
	}

	if c.Addr == "" {
		c.Addr = defaultAddr
	}
	if c.CertPath == "" {
		c.CertPath = defaultCertPath
	}
	if c.CaCertPath == "" {
		c.CaCertPath = defaultCaCertPath
	}
	if c.KeyPath == "" {
		c.KeyPath = defaultKeyPath
	}

	return nil
}

func (c *WebhookMode) Run(ctx context.Context) error {
	if err := c.SetupLogger(); err != nil {
		return errs.New("error setting up logging: %v", err)
	}
	defer c.log.Close()

	if err := c.Dial(ctx); err != nil {
		return errs.New("failed to dial server: %v", err)
	}
	defer c.serverConn.Close()

	controller := NewController(ControllerConfig{
		Log:           c.log,
		R:             registration.NewRegistrationClient(c.serverConn),
		TrustDomain:   c.TrustDomain,
		Cluster:       c.Cluster,
		PodLabel:      c.PodLabel,
		PodAnnotation: c.PodAnnotation,
	})

	c.log.Info("Initializing registrar")
	if err := controller.Initialize(ctx); err != nil {
		return err
	}

	server, err := NewServer(ServerConfig{
		Log:                            c.log,
		Addr:                           c.Addr,
		Handler:                        NewWebhookHandler(controller),
		CertPath:                       c.CertPath,
		KeyPath:                        c.KeyPath,
		CaCertPath:                     c.CaCertPath,
		InsecureSkipClientVerification: c.InsecureSkipClientVerification,
	})
	if err != nil {
		return err
	}

	return server.Run(ctx)
}
