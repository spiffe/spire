package main

import (
	"context"

	"github.com/hashicorp/hcl"
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
	log, err := c.SetupLogger()
	if err != nil {
		return errs.New("error setting up logging: %v", err)
	}
	defer log.Close()

	entryClient, err := c.EntryClient(ctx, log)
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}

	disabledNamespacesMap := make(map[string]bool, len(c.DisabledNamespaces))
	for _, ns := range c.DisabledNamespaces {
		disabledNamespacesMap[ns] = true
	}
	controller := NewController(ControllerConfig{
		Log:                log,
		E:                  entryClient,
		TrustDomain:        c.TrustDomain,
		Cluster:            c.Cluster,
		PodLabel:           c.PodLabel,
		PodAnnotation:      c.PodAnnotation,
		DisabledNamespaces: disabledNamespacesMap,
	})

	log.Info("Initializing registrar")
	if err := controller.Initialize(ctx); err != nil {
		return err
	}

	server, err := NewServer(ServerConfig{
		Log:                            log,
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
