package main

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/go-logr/logr"
	"github.com/hashicorp/hcl"

	"k8s.io/apimachinery/pkg/runtime"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
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
	MetricsAddr    string `hcl:"metrics_addr"`
	LeaderElection bool   `hcl:"leader_election"`
	ControllerName string `hcl:"controller_name"`
	AddPodDNSNames bool   `hcl:"add_pod_dns_names"`
	ClusterDNSZone string `hcl:"cluster_dns_zone"`
}

func (c *ReconcileMode) ParseConfig(hclConfig string) error {
	if err := hcl.Decode(&c, hclConfig); err != nil {
		return errs.New("unable to decode configuration: %v", err)
	}

	if c.MetricsAddr == "" {
		c.MetricsAddr = defaultMetricsAddr
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
	// controller-runtime uses the logr interface for its logging. We could write a wrapper around logrus, but
	// controller-runtime also ships with a zap encoder for k8s objects. This allows safe logging of k8s
	// objects. Rather than reimplement all of that for logrus, we instead use zap throughout this controller.
	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = true
	}))
	setupLog := ctrl.Log.WithName("setup")

	// Connect to Spire Server
	spireClient, err := c.EntryClient(ctx, SpiffeLogWrapper{setupLog})
	if err != nil {
		setupLog.Error(err, "Unable to connect to SPIRE registration API")
		return err
	}
	setupLog.Info("Connected to spire server")

	rootID := nodeID(c.TrustDomain, c.ControllerName, c.Cluster)

	// Setup all Controllers
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: c.MetricsAddr,
		LeaderElection:     c.LeaderElection,
		LeaderElectionID:   fmt.Sprintf("%s-leader-election", c.ControllerName),
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
		c.DisabledNamespaces,
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

// ServerID creates a server SPIFFE ID string given a trustDomain.
func ServerID(trustDomain string) *spiretypes.SPIFFEID {
	return &spiretypes.SPIFFEID{
		TrustDomain: trustDomain,
		Path:        idutil.JoinPathSegments("spire", "server"),
	}
}

func nodeID(trustDomain string, controllerName string, cluster string) *spiretypes.SPIFFEID {
	return &spiretypes.SPIFFEID{
		TrustDomain: trustDomain,
		Path:        idutil.JoinPathSegments(controllerName, cluster, "node"),
	}
}
