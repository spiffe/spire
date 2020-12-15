package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultLogLevel = "info"

	modeCRD       = "crd"
	modeWebhook   = "webhook"
	modeReconcile = "reconcile"
	defaultMode   = modeWebhook
)

type Mode interface {
	ParseConfig(hclConfig string) error
	Run(ctx context.Context) error
	Close() error
}

type CommonMode struct {
	LogFormat          string   `hcl:"log_format"`
	LogLevel           string   `hcl:"log_level"`
	LogPath            string   `hcl:"log_path"`
	TrustDomain        string   `hcl:"trust_domain"`
	ServerSocketPath   string   `hcl:"server_socket_path"`
	AgentSocketPath    string   `hcl:"agent_socket_path"`
	ServerAddress      string   `hcl:"server_address"`
	Cluster            string   `hcl:"cluster"`
	PodLabel           string   `hcl:"pod_label"`
	PodAnnotation      string   `hcl:"pod_annotation"`
	Mode               string   `hcl:"mode"`
	DisabledNamespaces []string `hcl:"disabled_namespaces"`
	serverAPI          ServerAPIClients
}

func (c *CommonMode) ParseConfig(hclConfig string) error {
	c.Mode = defaultMode
	if err := hcl.Decode(c, hclConfig); err != nil {
		return errs.New("unable to decode configuration: %v", err)
	}

	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
	if c.ServerAddress == "" {
		if c.ServerSocketPath != "" {
			c.ServerAddress = fmt.Sprintf("unix://%s", c.ServerSocketPath)
		} else {
			return errs.New("server_address or server_socket_path must be specified")
		}
	}
	if !strings.HasPrefix(c.ServerAddress, "unix://") && c.AgentSocketPath == "" {
		return errs.New("agent_socket_path must be specified if the server is not a local socket")
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
	if c.Mode != modeCRD && c.Mode != modeWebhook && c.Mode != modeReconcile {
		return errs.New("invalid mode \"%s\", valid values are %s, %s and %s", c.Mode, modeCRD, modeWebhook, modeReconcile)
	}
	if c.DisabledNamespaces == nil {
		c.DisabledNamespaces = defaultDisabledNamespaces()
	}

	return nil
}

func defaultDisabledNamespaces() []string {
	return []string{metav1.NamespaceSystem, metav1.NamespacePublic}
}

func (c *CommonMode) SetupLogger() (*log.Logger, error) {
	return log.NewLogger(log.WithLevel(c.LogLevel), log.WithFormat(c.LogFormat), log.WithOutputFile(c.LogPath))
}

func (c *CommonMode) EntryClient(ctx context.Context, dialLogger logger.Logger) (entry.EntryClient, error) {
	return c.serverAPI.EntryClient(ctx, dialLogger, c.ServerAddress, c.AgentSocketPath)
}

func (c *CommonMode) Close() error {
	return c.serverAPI.Close()
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
	case modeReconcile:
		mode = &ReconcileMode{
			CommonMode: *c,
		}
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

type ServerAPIClients struct {
	serverConn   *grpc.ClientConn
	workloadConn *workloadapi.X509Source
}

func (r *ServerAPIClients) dial(ctx context.Context, dialLog logger.Logger, serverAddress string, agentSocketPath string) error {
	var conn *grpc.ClientConn
	var err error

	if strings.HasPrefix(serverAddress, "unix://") {
		dialLog.Infof("Connecting to local registration server socket %s", serverAddress)
		conn, err = grpc.DialContext(ctx, serverAddress, grpc.WithInsecure())
		if err != nil {
			return err
		}
	} else {
		dialLog.Infof("Connecting to remote registration server %s with credentials from agent socket %s", serverAddress, agentSocketPath)
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+agentSocketPath), workloadapi.WithLogger(dialLog)))
		r.workloadConn = source
		if err != nil {
			return err
		}

		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		conn, err = grpc.DialContext(ctx, serverAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		if err != nil {
			return err
		}
	}
	r.serverConn = conn

	return nil
}

func (r *ServerAPIClients) EntryClient(ctx context.Context, dialLog logger.Logger, serverAddress string, agentSocketPath string) (entry.EntryClient, error) {
	if r.serverConn == nil {
		if err := r.dial(ctx, dialLog, serverAddress, agentSocketPath); err != nil {
			return nil, err
		}
	}
	return entry.NewEntryClient(r.serverConn), nil
}

func (r *ServerAPIClients) Close() error {
	var group errs.Group
	if r.serverConn != nil {
		group.Add(r.serverConn.Close())
	}
	if r.workloadConn != nil {
		group.Add(r.workloadConn.Close())
	}
	return group.Err()
}
