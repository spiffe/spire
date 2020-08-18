package main

import (
	"context"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

const (
	defaultLogLevel = "info"

	modeCRD     = "crd"
	modeWebhook = "webhook"
	defaultMode = modeWebhook
)

type Mode interface {
	ParseConfig(hclConfig string) error
	Run(ctx context.Context) error
}

type CommonMode struct {
	LogFormat        string `hcl:"log_format"`
	LogLevel         string `hcl:"log_level"`
	LogPath          string `hcl:"log_path"`
	TrustDomain      string `hcl:"trust_domain"`
	ServerSocketPath string `hcl:"server_socket_path"`
	Cluster          string `hcl:"cluster"`
	PodLabel         string `hcl:"pod_label"`
	PodAnnotation    string `hcl:"pod_annotation"`
	Mode             string `hcl:"mode"`
	log              *log.Logger
	serverConn       *grpc.ClientConn
}

func (c *CommonMode) ParseConfig(hclConfig string) error {
	c.Mode = defaultMode
	if err := hcl.Decode(c, hclConfig); err != nil {
		return errs.New("unable to decode configuration: %v", err)
	}

	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
	if c.ServerSocketPath == "" {
		return errs.New("server_socket_path must be specified")
	}
	if c.TrustDomain == "" {
		return errs.New("trust_domain must be specified")
	}
	if c.Cluster == "" {
		return errs.New("cluster must be specified")
	}
	if c.PodLabel != "" && c.PodAnnotation != "" {
		return errs.New("workload registration mode specification is incorrect, can't specify both pod_label and pod_annotation")
	}
	if c.Mode != modeCRD && c.Mode != modeWebhook {
		return errs.New("invalid mode \"%s\", valid values are %s and %s", c.Mode, modeCRD, modeWebhook)
	}

	return nil
}

func (c *CommonMode) SetupLogger() error {
	log, err := log.NewLogger(log.WithLevel(c.LogLevel), log.WithFormat(c.LogFormat), log.WithOutputFile(c.LogPath))
	c.log = log
	return err
}

func (c *CommonMode) Dial(ctx context.Context) error {
	c.log.WithField("socket_path", c.ServerSocketPath).Info("Dialing server")
	serverConn, err := grpc.DialContext(ctx, "unix://"+c.ServerSocketPath, grpc.WithInsecure())
	c.serverConn = serverConn
	return err
}

func LoadMode(path string) (Mode, error) {
	hclBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errs.New("unable to load configuration: %v", err)
	}

	c := &CommonMode{}
	if err = c.ParseConfig(string(hclBytes)); err != nil {
		return nil, errs.New("error parsing common config: %v", err)
	}

	var mode Mode
	switch c.Mode {
	case modeCRD:
		mode = &CRDMode{
			CommonMode: *c,
		}
	default:
		mode = &WebhookMode{
			CommonMode: *c,
		}
	}

	err = mode.ParseConfig(string(hclBytes))
	return mode, err
}
