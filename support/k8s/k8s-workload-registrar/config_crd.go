package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/controllers"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	defaultAddSvcDNSName      = true
	defaultPodController      = true
	defaultMetricsBindAddr    = ":8080"
	defaultWebhookName        = "k8s-workload-registrar"
	defaultWebhookPort        = 9443
	defaultWebhookServiceName = "k8s-workload-registrar"
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
	R                  registration.RegistrationClient
	ctx                context.Context
	entryID            string
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

	return nil
}

func (c *CRDMode) Run(ctx context.Context) error {
	c.ctx = ctx
	log, err := c.SetupLogger()
	if err != nil {
		return errs.New("error setting up logging: %v", err)
	}
	defer log.Close()

	registrationClient, err := c.RegistrationClient(ctx, log)
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}
	c.R = registrationClient

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
		err = controllers.NewPodReconciler(controllers.PodReconcilerConfig{
			Client:             mgr.GetClient(),
			Cluster:            c.Cluster,
			Ctx:                ctx,
			DisabledNamespaces: c.DisabledNamespaces,
			Log:                log,
			PodLabel:           c.PodLabel,
			PodAnnotation:      c.PodAnnotation,
			Scheme:             mgr.GetScheme(),
			TrustDomain:        c.TrustDomain,
		}).SetupWithManager(mgr)
		if err != nil {
			return err
		}
	}

	if c.AddSvcDNSName {
		err = controllers.NewEndpointReconciler(controllers.EndpointReconcilerConfig{
			Client:             mgr.GetClient(),
			Ctx:                ctx,
			DisabledNamespaces: c.DisabledNamespaces,
			Log:                log,
			PodLabel:           c.PodLabel,
			PodAnnotation:      c.PodAnnotation,
		}).SetupWithManager(mgr)
		if err != nil {
			return err
		}
	}

	if c.WebhookEnabled {
		err = c.setupWebhook(mgr, log, myNamespace)
		if err != nil {
			return err
		}
	}

	return mgr.Start(ctrl.SetupSignalHandler())
}

func (c *CRDMode) Close() error {
	_ = controllers.DeleteRegistrationEntry(c.ctx, c.R, c.entryID)
	return c.registrationAPI.Close()
}

// setupWebhook gets the certificates and then registers the webhook
func (c *CRDMode) setupWebhook(mgr ctrl.Manager, log *log.Logger, myNamespace string) error {
	log.Info("Waiting for SPIRE Agent")
	err := c.waitForSpireAgent()
	if err != nil {
		return err
	}

	log.Info("Setting up webhook registration entries")
	err = c.setupWebhookEntries(myNamespace)
	if err != nil {
		return err
	}

	log.Info("Setting up SPIFFE sidecar")
	err = c.setupSpiffeSidecar(log)
	if err != nil {
		return err
	}

	err = spiffeidv1beta1.AddSpiffeIDWebhook(spiffeidv1beta1.SpiffeIDWebhookConfig{
		Ctx:         c.ctx,
		Log:         log,
		Mgr:         mgr,
		Namespace:   myNamespace,
		R:           c.R,
		TrustDomain: c.TrustDomain,
	})
	if err != nil {
		return err
	}

	return nil
}

// waitForSpireAgent waits for the SPIRE Agent to be up and running.
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

// setupWebhookEntries creates registration entries for webhook
func (c *CRDMode) setupWebhookEntries(myNamespace string) error {
	podName, err := getPodName()
	if err != nil {
		return err
	}

	podUID, err := getPodUID()
	if err != nil {
		return err
	}

	// Create parent entry
	_, err = c.R.CreateEntryIfNotExists(c.ctx, &common.RegistrationEntry{
		ParentId: idutil.ServerID(c.TrustDomain),
		SpiffeId: controllers.MakeID(c.TrustDomain, "k8s-workload-registrar/%s/webhook", c.Cluster),
		Selectors: []*common.Selector{
			{Type: "k8s_psat", Value: fmt.Sprintf("cluster:%s", c.Cluster)},
		},
	})
	if err != nil {
		return err
	}

	// Create entry used for webhook
	response, err := c.R.CreateEntryIfNotExists(c.ctx, &common.RegistrationEntry{
		ParentId: controllers.MakeID(c.TrustDomain, "k8s-workload-registrar/%s/webhook", c.Cluster),
		SpiffeId: controllers.MakeID(c.TrustDomain, "k8s-workload-registrar/%s/webhook/%s", c.Cluster, podName),
		Selectors: []*common.Selector{
			podUIDSelector(podUID),
		},
		DnsNames: []string{
			c.WebhookServiceName + "." + myNamespace + ".svc",
		},
	})
	if err != nil {
		return err
	}
	c.entryID = response.Entry.EntryId

	return nil
}

// setupSpiffeSidecar sets up the process to download and rotate the webhook certificates
func (c *CRDMode) setupSpiffeSidecar(log *log.Logger) error {
	err := os.MkdirAll(webhookCertDir, 0700)
	if err != nil {
		return err
	}
	spiffeSidecar, err := sidecar.NewSidecar(&sidecar.Config{
		AgentAddress:          c.AgentSocketPath,
		CertDir:               webhookCertDir,
		Ctx:                   c.ctx,
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
	case err = <-spiffeSidecar.ErrChan:
		return fmt.Errorf("error waiting for trust bundle: %v", err)
	case <-time.After(3 * time.Minute):
		return fmt.Errorf("timed out waiting for trust bundle")
	}

	return nil
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

func getPodUID() (string, error) {
	uid, ok := os.LookupEnv("MY_POD_UID")
	if !ok {
		return "", fmt.Errorf("unable to get Pod UID, ensure downward API is configured for this pod")
	}

	return uid, nil
}

func podUIDSelector(podUID string) *common.Selector {
	return &common.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("pod-uid:%s", podUID),
	}
}
