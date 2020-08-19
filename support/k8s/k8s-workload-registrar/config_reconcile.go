package main

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/go-logr/logr"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/api/registration"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/runtime"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-reconcile/controllers"
	"github.com/zeebo/errs"
)

const (
	defaultMetricsAddr    = ":8080"
	defaultControllerName = "spire-k8s-registrar"
	defaultClusterDNSZone = "cluster.local"
)

type ReconcileMode struct {
	CommonMode
	MetricsAddr     string `hcl:"metrics_addr"`
	AgentSocketPath string `hcl:"agent_socket_path"`
	ServerAddress   string `hcl:"server_address"`
	LeaderElection  bool   `hcl:"leader_election"`
	ControllerName  string `hcl:"controller_name"`
	AddPodDNSNames  bool   `hcl:"add_pod_dns_names"`
	ClusterDNSZone  string `hcl:"cluster_dns_zone"`
}

func (c *ReconcileMode) ParseConfig(hclConfig string) error {
	if err := hcl.Decode(&c, hclConfig); err != nil {
		return errs.New("unable to decode configuration: %v", err)
	}

	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = defaultMetricsAddr
	}
	if c.Cluster == "" {
		return errs.New("cluster must be specified")
	}
	if c.ServerAddress == "" {
		if c.ServerSocketPath != "" {
			c.ServerAddress = fmt.Sprintf("unix://%s", c.ServerSocketPath)
		} else {
			return errs.New("server_address must be specified")
		}
	}
	if !strings.HasPrefix(c.ServerAddress, "unix://") && c.AgentSocketPath == "" {
		return errs.New("agent_socket_path must be specified if the server is not a local socket")
	}
	if c.TrustDomain == "" {
		return errs.New("trust_domain must be specified")
	}
	if c.ControllerName == "" {
		c.ControllerName = defaultControllerName
	}
	if c.ClusterDNSZone == "" {
		c.ClusterDNSZone = defaultClusterDNSZone
	}

	return nil
}

func (c *ReconcileMode) Run(ctx context.Context) error {

	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = true
	}))
	setupLog := ctrl.Log.WithName("setup")

	//Connect to Spire Server
	spireClient, err := ConnectSpire(ctx, setupLog, c.ServerAddress, c.AgentSocketPath)
	if err != nil {
		setupLog.Error(err, "Unable to connect to SPIRE workload API")
		return err
	}
	setupLog.Info("Connected to spire server.")

	rootID := nodeID(c.TrustDomain, c.ControllerName, c.Cluster)

	// Setup all Controllers
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: c.MetricsAddr,
		LeaderElection:     c.LeaderElection,
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		return err
	}

	if err = controllers.NewNodeReconciler(
		mgr.GetClient(),
		ctrl.Log.WithName("controllers").WithName("Node"),
		mgr.GetScheme(),
		ServerID(c.TrustDomain),
		c.Cluster,
		rootID,
		spireClient,
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "Node")
		return err
	}

	mode := controllers.PodReconcilerModeServiceAccount
	value := ""
	if len(c.PodLabel) > 0 {
		mode = controllers.PodReconcilerModeLabel
		value = c.PodLabel
	}
	if len(c.PodAnnotation) > 0 {
		mode = controllers.PodReconcilerModeAnnotation
		value = c.PodAnnotation
	}
	if err = controllers.NewPodReconciler(
		mgr.GetClient(),
		ctrl.Log.WithName("controllers").WithName("Pod"),
		mgr.GetScheme(),
		c.TrustDomain,
		rootID,
		spireClient,
		mode,
		value,
		c.ClusterDNSZone,
		c.AddPodDNSNames,
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "Pod")
		return err
	}

	// +kubebuilder:scaffold:builder

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Problem running manager")
		return err
	}
	return nil
}

type SpiffeLogWrapper struct {
	delegate logr.Logger
}

func (slw SpiffeLogWrapper) Debugf(format string, args ...interface{}) {
	slw.delegate.V(1).Info(fmt.Sprintf(format, args...))
}
func (slw SpiffeLogWrapper) Infof(format string, args ...interface{}) {
	slw.delegate.Info(fmt.Sprintf(format, args...))
}
func (slw SpiffeLogWrapper) Warnf(format string, args ...interface{}) {
	slw.delegate.Info(fmt.Sprintf(format, args...))
}
func (slw SpiffeLogWrapper) Errorf(format string, args ...interface{}) {
	slw.delegate.Info(fmt.Sprintf(format, args...))
}

func ConnectSpire(ctx context.Context, log logr.Logger, serverAddress, agentSocketPath string) (registration.RegistrationClient, error) {
	var conn *grpc.ClientConn
	var err error

	if strings.HasPrefix(serverAddress, "unix://") {
		log.Info("Connecting to local workload API socket", "serverAddress", serverAddress)
		conn, err = grpc.DialContext(ctx, serverAddress, grpc.WithInsecure())
		if err != nil {
			return nil, err
		}
	} else {
		log.Info("Connecting to remote workload API", "serverAddress", serverAddress, "agentSocketPath", agentSocketPath)
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+agentSocketPath)), workloadapi.WithClientOptions(workloadapi.WithLogger(SpiffeLogWrapper{log})))
		if err != nil {
			return nil, err
		}

		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		conn, err = grpc.DialContext(ctx, serverAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

		if err != nil {
			return nil, err
		}
	}
	spireClient := registration.NewRegistrationClient(conn)
	return spireClient, nil
}

// ServerURI creates a server SPIFFE URI given a trustDomain.
func ServerURI(trustDomain string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "server"),
	}
}

// ServerID creates a server SPIFFE ID string given a trustDomain.
func ServerID(trustDomain string) string {
	return ServerURI(trustDomain).String()
}

func makeID(trustDomain string, pathFmt string, pathArgs ...interface{}) string {
	id := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Clean(fmt.Sprintf(pathFmt, pathArgs...)),
	}
	return id.String()
}

func nodeID(trustDomain string, controllerName string, cluster string) string {
	return makeID(trustDomain, "%s/%s/node", controllerName, cluster)
}
