package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/spire/api/registration"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/controllers"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	defaultAddSvcDNSName      = true
	defaultPodController      = true
	defaultMetricsBindAddr    = ":8080"
	defaultWebhookName        = "k8s-workload-registrar"
	defaultWebhookPort        = 9443
	defaultWebhookServiceName = "k8s-workload-registrar"
	defaultWebhookPath        = "/validate-spiffeid-spiffe-io-v1beta1-spiffeid"
	namespaceFile             = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	podNameFile               = "/etc/hostname"
	webhookCertDir            = "/tmp/k8s-webhook-server/serving-certs"
)

type CRDMode struct {
	CommonMode
	AddSvcDNSName      bool   `hcl:"add_svc_dns_name"`
	LeaderElection     bool   `hcl:"leader_election"`
	MetricsBindAddr    string `hcl:"metrics_bind_addr"`
	PodController      bool   `hcl:"pod_controller"`
	WebhookEnabled     bool   `hcl:"webhook_enabled"`
	WebhookName        string `hcl:"webhook_name"`
	WebhookPort        int    `hcl:"webhook_port"`
	WebhookServiceName string `hcl:"webhook_service_name"`
	WebhookPath        string `hcl:"webhook_path"`
}

func (c *CRDMode) ParseConfig(hclConfig string) error {
	c.PodController = defaultPodController
	c.AddSvcDNSName = defaultAddSvcDNSName
	if err := hcl.Decode(c, hclConfig); err != nil {
		return errs.New("unable to decode configuration: %v", err)
	}

	if c.MetricsBindAddr == "" {
		c.MetricsBindAddr = defaultMetricsBindAddr
	}

	if c.WebhookName == "" {
		c.WebhookName = defaultWebhookName
	}

	if c.WebhookPort == 0 {
		c.WebhookPort = defaultWebhookPort
	}

	if c.WebhookServiceName == "" {
		c.WebhookServiceName = defaultWebhookServiceName
	}

	if c.WebhookPath == "" {
		c.WebhookPath = defaultWebhookPath
	}

	return nil
}

func (c *CRDMode) Run(ctx context.Context) error {
	log, err := c.SetupLogger()
	if err != nil {
		return errs.New("error setting up logging: %v", err)
	}
	defer log.Close()

	registrationClient, err := c.RegistrationClient(ctx, log)
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}

	mgr, err := controllers.NewManager(c.LeaderElection, c.MetricsBindAddr, webhookCertDir, c.WebhookPort)
	if err != nil {
		return err
	}

	myNamespace, err := getNamespace()
	if err != nil {
		return err
	}

	log.Info("Initializing SPIFFE ID CRD Mode")
	err = controllers.NewSpiffeIDReconciler(controllers.SpiffeIDReconcilerConfig{
		Client:      mgr.GetClient(),
		Cluster:     c.Cluster,
		Ctx:         ctx,
		Log:         log,
		R:           registrationClient,
		TrustDomain: c.TrustDomain,
	}).SetupWithManager(mgr)
	if err != nil {
		return err
	}

	var podr *controllers.PodReconciler
	if c.PodController {
		err = controllers.NewNodeReconciler(controllers.NodeReconcilerConfig{
			Client:      mgr.GetClient(),
			Cluster:     c.Cluster,
			Ctx:         ctx,
			Log:         log,
			Namespace:   myNamespace,
			Scheme:      mgr.GetScheme(),
			TrustDomain: c.TrustDomain,
		}).SetupWithManager(mgr)
		if err != nil {
			return err
		}
		podr = controllers.NewPodReconciler(controllers.PodReconcilerConfig{
			Client:             mgr.GetClient(),
			Cluster:            c.Cluster,
			Ctx:                ctx,
			DisabledNamespaces: c.DisabledNamespaces,
			Log:                log,
			PodLabel:           c.PodLabel,
			PodAnnotation:      c.PodAnnotation,
			Scheme:             mgr.GetScheme(),
			TrustDomain:        c.TrustDomain,
		})
		err = podr.SetupWithManager(mgr)
		if err != nil {
			return err
		}
	}

	var epr *controllers.EndpointReconciler
	if c.AddSvcDNSName {
		epr = controllers.NewEndpointReconciler(controllers.EndpointReconcilerConfig{
			Client:             mgr.GetClient(),
			Ctx:                ctx,
			DisabledNamespaces: c.DisabledNamespaces,
			Log:                log,
			PodLabel:           c.PodLabel,
			PodAnnotation:      c.PodAnnotation,
		})
		err = epr.SetupWithManager(mgr)
		if err != nil {
			return err
		}
	}

	if c.WebhookEnabled {
		err = mgr.Add(manager.RunnableFunc(func(<-chan struct{}) error {
			err = c.setupWebhook(ctx, mgr, registrationClient, log, myNamespace, podr, epr)
			if err != nil {
				return err
			}

			return nil
		}))
		if err != nil {
			return err
		}
	}

	return mgr.Start(ctrl.SetupSignalHandler())
}

func (c *CRDMode) setupWebhook(ctx context.Context, mgr ctrl.Manager, registrationClient registration.RegistrationClient,
	log *log.Logger, myNamespace string, podr *controllers.PodReconciler, epr *controllers.EndpointReconciler) error {
	log.Info("Waiting for SPIRE Agent")
	err := c.waitForSpireAgent()
	if err != nil {
		return err
	}

	// Ensure the SPIRE entry to be used for the webhook is available
	podName, err := getPodName()
	if err != nil {
		return err
	}
	_, err = podr.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      podName,
			Namespace: myNamespace,
		},
	})
	if err != nil {
		return err
	}
	_, err = epr.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      c.WebhookServiceName,
			Namespace: myNamespace,
		},
	})
	if err != nil {
		return err
	}

	log.Info("Setting up SPIFFE sidecar")
	err = os.MkdirAll(webhookCertDir, 0700)
	if err != nil {
		return err
	}
	spiffeSidecar, err := sidecar.NewSidecar(&sidecar.Config{
		AgentAddress:          c.AgentSocketPath,
		CertDir:               webhookCertDir,
		Ctx:                   ctx,
		ValidatingWebhookName: c.WebhookName,
		Log:                   log,
		SvidFileName:          "tls.crt",
		SvidKeyFileName:       "tls.key",
		SvidBundleFileName:    "rootca.pem",
	})
	if err != nil {
		return err
	}

	err = spiffeSidecar.RunDaemon()
	if err != nil {
		return err
	}
	select {
	case <-spiffeSidecar.CertReadyChan():
		log.Info("Received trust bundle from SPIRE")
	case <-time.After(3 * time.Minute):
		return fmt.Errorf("timed out waiting for trust bundle")
	}

	err = spiffeidv1beta1.AddSpiffeIDWebhook(spiffeidv1beta1.SpiffeIDWebhookConfig{
		Ctx:         ctx,
		Log:         log,
		Mgr:         mgr,
		Namespace:   myNamespace,
		R:           registrationClient,
		TrustDomain: c.TrustDomain,
		WebhookPath: c.WebhookPath,
	})
	if err != nil {
		return err
	}

	return nil
}

// waitForSpireAgent waits for the SPIRE Agent to be up and running. If it is dialed early, the dial
// will be successful but no data will come from the unix socket
func (c *CRDMode) waitForSpireAgent() error {
	conn, err := grpc.Dial("unix://"+c.AgentSocketPath, grpc.WithInsecure())
	if err != nil {
		return err
	}

	retries := 180
	for i := 0; i < retries; i++ {
		if conn.GetState() == connectivity.Ready {
			return nil
		}
		retries++
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("SPIRE Agent not ready, waited for 3 minutes")
}

func getNamespace() (string, error) {
	content, err := ioutil.ReadFile(namespaceFile)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func getPodName() (string, error) {
	content, err := ioutil.ReadFile(podNameFile)
	if err != nil {
		return "", err
	}

	return string(content), nil
}
