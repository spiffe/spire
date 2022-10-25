package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/controllers"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/webhook"
	"github.com/zeebo/errs"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	defaultAddSvcDNSName              = true
	defaultDNSTemplate                = "{{.Pod.Name}}"
	defaultPodController              = true
	defaultMetricsBindAddr            = ":8080"
	defaultWebhookCertDir             = "/run/spire/serving-certs"
	defaultWebhookPort                = 9443
	defaultWebhookServiceName         = "k8s-workload-registrar"
	defaultLeaderElectionResourceLock = resourcelock.LeasesResourceLock
	configMapsResourceLock            = "configmaps"
	namespaceFile                     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type CRDMode struct {
	CommonMode
	AddSvcDNSName              bool              `hcl:"add_svc_dns_name"`
	LeaderElection             bool              `hcl:"leader_election"`
	LeaderElectionResourceLock string            `hcl:"leader_election_resource_lock"`
	MetricsBindAddr            string            `hcl:"metrics_bind_addr"`
	PodController              bool              `hcl:"pod_controller"`
	WebhookCertDir             string            `hcl:"webhook_cert_dir"`
	WebhookEnabled             bool              `hcl:"webhook_enabled"`
	WebhookPort                int               `hcl:"webhook_port"`
	WebhookServiceName         string            `hcl:"webhook_service_name"`
	IdentityTemplate           string            `hcl:"identity_template"`
	IdentityTemplateLabel      string            `hcl:"identity_template_label"`
	DNSNameTemplates           *[]string         `hcl:"dns_name_templates"`
	Context                    map[string]string `hcl:"context"`
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

	if c.LeaderElectionResourceLock == "" {
		c.LeaderElectionResourceLock = defaultLeaderElectionResourceLock
	}

	if c.IdentityTemplate != "" && (c.PodAnnotation != "" || c.PodLabel != "") {
		return errs.New("workload registration configuration is incorrect, can only use one of identity_template, pod_annotation, or pod_label")
	}

	// Verify that if context is nil, it's not referenced in any templates
	if c.Context == nil {
		if c.IdentityTemplate != "" && strings.Contains(strings.ReplaceAll(c.IdentityTemplate, " ", ""), "{{.Context.") {
			return errs.New("identity_template references non-existing context")
		}
		if c.DNSNameTemplates != nil && len(*c.DNSNameTemplates) > 0 {
			for _, tmpl := range *c.DNSNameTemplates {
				if strings.Contains(strings.ReplaceAll(tmpl, " ", ""), "{{.Context.") {
					return errs.New("dns_name_template references non-existing context")
				}
			}
		}
	}

	if c.DNSNameTemplates == nil {
		c.DNSNameTemplates = &[]string{defaultDNSTemplate}
	}

	return nil
}

func (c *CRDMode) Run(ctx context.Context) error {
	log, err := c.SetupLogger()
	if err != nil {
		return errs.New("error setting up logging: %v", err)
	}
	defer log.Close()

	log.Warn("The k8s-workload-registrar is deprecated and no longer maintained. Please migrate to the SPIRE Controller Manager (https://github.com/spiffe/spire-controller-manager).")

	// DEPRECATED: remove this check in 1.5.0 since all those who migrate through 1.4.0 will already have moved away
	if c.LeaderElection && c.LeaderElectionResourceLock == configMapsResourceLock {
		return errs.New(`the "configmaps" leader election resource lock type is no longer supported`)
	}

	entryClient, err := c.EntryClient(ctx, log)
	if err != nil {
		return errs.New("failed to dial server: %v", err)
	}
	svidClient := svidv1.NewSVIDClient(c.serverAPI.serverConn)

	mgr, err := controllers.NewManager(c.LeaderElection, c.LeaderElectionResourceLock, c.MetricsBindAddr, c.WebhookCertDir, c.WebhookPort)
	if err != nil {
		return err
	}

	myPodNamespace, err := getMyPodNamespace()
	if err != nil {
		return err
	}

	log.Info("Initializing SPIFFE ID CRD Mode")
	err = controllers.NewSpiffeIDReconciler(controllers.SpiffeIDReconcilerConfig{
		Client:  mgr.GetClient(),
		Cluster: c.Cluster,
		Log:     log,
		E:       entryClient,
	}).SetupWithManager(mgr)
	if err != nil {
		return err
	}

	if c.WebhookEnabled {
		// Backwards compatibility check
		exists, err := dirExistsAndReadOnly(c.WebhookCertDir)
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
				TrustDomain:        c.trustDomain,
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
			DNSNameTemplates:      *c.DNSNameTemplates,
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

func getMyPodNamespace() (string, error) {
	namespace, ok := os.LookupEnv("MY_POD_NAMESPACE")
	if !ok {
		content, err := os.ReadFile(namespaceFile)
		if err != nil {
			return "", fmt.Errorf("unable to get MY_POD_NAMESPACE; ensure downward API is configured for this pod: %w", err)
		}
		return string(content), nil
	}

	return namespace, nil
}
