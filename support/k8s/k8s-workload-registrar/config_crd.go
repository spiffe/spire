package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/hcl"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/controllers"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/webhook"
	"github.com/zeebo/errs"
	"golang.org/x/sys/unix"
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
	AddSvcDNSName         bool              `hcl:"add_svc_dns_name"`
	LeaderElection        bool              `hcl:"leader_election"`
	MetricsBindAddr       string            `hcl:"metrics_bind_addr"`
	PodController         bool              `hcl:"pod_controller"`
	WebhookCertDir        string            `hcl:"webhook_cert_dir"`
	WebhookEnabled        bool              `hcl:"webhook_enabled"`
	WebhookPort           int               `hcl:"webhook_port"`
	WebhookServiceName    string            `hcl:"webhook_service_name"`
	IdentityTemplate      string            `hcl:"identity_template"`
	IdentityTemplateLabel string            `hcl:"identity_template_label"`
	Context               map[string]string `hcl:"context"`
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

	if c.IdentityTemplate != "" && (c.PodAnnotation != "" || c.PodLabel != "") {
		return errs.New("workload registration configuration is incorrect, can only use one of identity_template, pod_annotation, or pod_label")
	}

	// Eliminate reference to the non-existing context (strip out the blank space first).
	if c.Context == nil && c.IdentityTemplate != "" && strings.Contains(strings.ReplaceAll(c.IdentityTemplate, " ", ""), "{{.Context.") {
		return errs.New("identity_template references non-existing context")
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
	svidClient := svidv1.NewSVIDClient(c.serverAPI.serverConn)

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
			webhookSVID, err := webhook.NewSVID(ctx, webhook.SVIDConfig{
				Cluster:            c.Cluster,
				S:                  svidClient,
				Log:                log,
				Namespace:          myPodNamespace,
				TrustDomain:        c.TrustDomain,
				WebhookCertDir:     c.WebhookCertDir,
				WebhookServiceName: c.WebhookServiceName,
			})
			if err != nil {
				return err
			}
			if err = webhookSVID.MintSVID(ctx, nil); err != nil {
				return err
			}
			go func() {
				if err := webhookSVID.SVIDRotator(ctx); err != nil {
					log.Fatalf("failed rotating webhook certificate: %v", err)
				}
			}()
		}
		err = spiffeidv1beta1.AddSpiffeIDWebhook(spiffeidv1beta1.SpiffeIDWebhook{
			E:           entryClient,
			Log:         log,
			Mgr:         mgr,
			Namespace:   myPodNamespace,
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
			Log:         log,
			Namespace:   myPodNamespace,
			Scheme:      mgr.GetScheme(),
			TrustDomain: c.TrustDomain,
		}).SetupWithManager(mgr)
		if err != nil {
			return err
		}
		p, err := controllers.NewPodReconciler(controllers.PodReconcilerConfig{
			Client:                mgr.GetClient(),
			Cluster:               c.Cluster,
			DisabledNamespaces:    c.DisabledNamespaces,
			Log:                   log,
			PodLabel:              c.PodLabel,
			PodAnnotation:         c.PodAnnotation,
			Scheme:                mgr.GetScheme(),
			TrustDomain:           c.TrustDomain,
			IdentityTemplate:      c.IdentityTemplate,
			Context:               c.Context,
			IdentityTemplateLabel: c.IdentityTemplateLabel,
		})
		if err != nil {
			return err
		}
		err = p.SetupWithManager(mgr)
		if err != nil {
			return err
		}
	}

	if c.AddSvcDNSName {
		err = controllers.NewEndpointReconciler(controllers.EndpointReconcilerConfig{
			Client:             mgr.GetClient(),
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
	err := unix.Access(c.WebhookCertDir, unix.W_OK)
	switch {
	case err == nil, errors.Is(err, unix.ENOENT):
		return false, nil
	case errors.Is(err, unix.EROFS):
		return true, nil
	default:
		return false, err
	}
}

func getMyPodNamespace() (string, error) {
	namespace, ok := os.LookupEnv("MY_POD_NAMESPACE")
	if !ok {
		content, err := ioutil.ReadFile(namespaceFile)
		if err != nil {
			return "", fmt.Errorf("unable to get MY_POD_NAMESPACE; ensure downward API is configured for this pod: %w", err)
		}
		return string(content), nil
	}

	return namespace, nil
}
