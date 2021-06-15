package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/hcl"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/controllers"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/webhook"
	"github.com/zeebo/errs"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	defaultAddSvcDNSName      = true
	defaultPodController      = true
	defaultMetricsBindAddr    = ":8080"
	defaultWebhookCertDir     = "/run/spire/serving-certs"
	defaultWebhookPort        = 9443
	defaultWebhookServiceName = "k8s-workload-registrar"
	namespaceFile             = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type CRDMode struct {
	CommonMode
	AddSvcDNSName      bool   `hcl:"add_svc_dns_name"`
	LeaderElection     bool   `hcl:"leader_election"`
	MetricsBindAddr    string `hcl:"metrics_bind_addr"`
	PodController      bool   `hcl:"pod_controller"`
	WebhookCertDir     string `hcl:"webhook_cert_dir"`
	WebhookEnabled     bool   `hcl:"webhook_enabled"`
	WebhookPort        int    `hcl:"webhook_port"`
	WebhookServiceName string `hcl:"webhook_service_name"`
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

	if c.WebhookCertDir == "" {
		c.WebhookCertDir = defaultWebhookCertDir
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
	log, err := c.SetupLogger()
	if err != nil {
		return errs.New("error setting up logging: %v", err)
	}
	defer log.Close()

	entryClient, err := c.EntryClient(ctx, log)
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}

	mgr, err := controllers.NewManager(c.LeaderElection, c.MetricsBindAddr, c.WebhookCertDir, c.WebhookPort)
	if err != nil {
		return err
	}

	myPodNamespace, err := getMyPodNamespace()
	if err != nil {
		return err
	}

	log.Info("Initializing SPIFFE ID CRD Mode")
	err = controllers.NewSpiffeIDReconciler(controllers.SpiffeIDReconcilerConfig{
		Client:      mgr.GetClient(),
		Cluster:     c.Cluster,
		Ctx:         ctx,
		Log:         log,
		E:           entryClient,
		TrustDomain: c.TrustDomain,
	}).SetupWithManager(mgr)
	if err != nil {
		return err
	}

	if c.WebhookEnabled {
		// Backwards compatibility check
		exists, err := c.certDirExistsAndReadOnly()
		if err != nil {
			return fmt.Errorf("checking webhook certificate directory permissions: %w", err)
		}
		if exists {
			log.Warn("Detected statically mounted webhook certificate directory, support for this will be removed in a future version. " +
				"Refer to README for instructions on using SPIRE Server to populate webhook certificates.")
		} else {
			myNodeName, err := getMyNodeName()
			if err != nil {
				return err
			}
			myPodName, err := getMyPodName()
			if err != nil {
				return err
			}
			myPodUID, err := getMyPodUID()
			if err != nil {
				return err
			}
			clientset, err := controllers.NewKubeClientset()
			if err != nil {
				return err
			}
			webhookEntry := webhook.NewEntry(webhook.EntryConfig{
				Clientset:          clientset,
				Cluster:            c.Cluster,
				Ctx:                ctx,
				E:                  entryClient,
				Log:                log,
				Name:               myPodName,
				Namespace:          myPodNamespace,
				NodeName:           myNodeName,
				TrustDomain:        c.TrustDomain,
				UID:                myPodUID,
				WebhookServiceName: c.WebhookServiceName,
			})
			if err = webhookEntry.CleanupStaleEntries(); err != nil {
				return err
			}
			if err = webhookEntry.CreateEntry(); err != nil {
				return err
			}
			defer func() {
				if err = webhookEntry.DeleteEntry(); err != nil {
					log.WithError(err).Error("Unable to delete webhook entry")
				}
			}()
			webhookSVIDWatcher := webhook.NewSVIDWatcher(webhook.SVIDWatcherConfig{
				AgentSocketPath: c.AgentSocketPath,
				Ctx:             ctx,
				Log:             log,
				SpiffeID:        webhookEntry.SpiffeID,
				WebhookCertDir:  c.WebhookCertDir,
			})
			if err = webhookSVIDWatcher.Start(); err != nil {
				return err
			}
		}
		err = spiffeidv1beta1.AddSpiffeIDWebhook(spiffeidv1beta1.SpiffeIDWebhookConfig{
			Ctx:         ctx,
			Log:         log,
			Mgr:         mgr,
			Namespace:   myPodNamespace,
			E:           entryClient,
			TrustDomain: c.TrustDomain,
		})
		if err != nil {
			return err
		}
	}

	if c.PodController {
		err = controllers.NewNodeReconciler(controllers.NodeReconcilerConfig{
			Client:      mgr.GetClient(),
			Cluster:     c.Cluster,
			Ctx:         ctx,
			Log:         log,
			Namespace:   myPodNamespace,
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

	return mgr.Start(ctrl.SetupSignalHandler())
}

func (c *CRDMode) certDirExistsAndReadOnly() (bool, error) {
	_, err := os.Stat(c.WebhookCertDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err = unix.Access(c.WebhookCertDir, unix.W_OK); err != nil {
		if errors.Is(err, unix.EROFS) {
			return true, nil
		}
		return false, err
	}

	return false, nil
}

func getMyNodeName() (string, error) {
	namespace, ok := os.LookupEnv("MY_NODE_NAME")
	if !ok {
		return "", fmt.Errorf("unable to get MY_NODE_NAME, ensure downward API is configured for this pod")
	}

	return namespace, nil
}

func getMyPodNamespace() (string, error) {
	namespace, ok := os.LookupEnv("MY_POD_NAMESPACE")
	if !ok {
		content, err := ioutil.ReadFile(namespaceFile)
		if err != nil {
			return "", fmt.Errorf("unable to get MY_POD_NAMESPACE, ensure downward API is configured for this pod")
		}
		return string(content), nil
	}

	return namespace, nil
}

func getMyPodName() (string, error) {
	name, ok := os.LookupEnv("MY_POD_NAME")
	if !ok {
		return "", fmt.Errorf("unable to get MY_POD_NAME, ensure downward API is configured for this pod")
	}

	return name, nil
}

func getMyPodUID() (types.UID, error) {
	uid, ok := os.LookupEnv("MY_POD_UID")
	if !ok {
		return "", fmt.Errorf("unable to get MY_POD_UID, ensure downward API is configured for this pod")
	}

	return types.UID(uid), nil
}
