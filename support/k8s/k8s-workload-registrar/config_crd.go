package main

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/hcl"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/controllers"
	"github.com/zeebo/errs"

	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	defaultAddSvcDNSName   = true
	defaultPodController   = true
	defaultMetricsBindAddr = ":8080"
	defaultWebhookCertDir  = "/run/spire/serving-certs"
	defaultWebhookPort     = 9443
	namespaceFile          = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type CRDMode struct {
	CommonMode
	AddSvcDNSName         bool              `hcl:"add_svc_dns_name"`
	LeaderElection        bool              `hcl:"leader_election"`
	MetricsBindAddr       string            `hcl:"metrics_bind_addr"`
	PodController         bool              `hcl:"pod_controller"`
	WebhookEnabled        bool              `hcl:"webhook_enabled"`
	WebhookCertDir        string            `hcl:"webhook_cert_dir"`
	WebhookPort           int               `hcl:"webhook_port"`
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

	if c.IdentityTemplate != "" && (c.CommonMode.PodAnnotation != "" || c.CommonMode.PodLabel != "") {
		return errs.New("workload registration configuration is incorrect, can only use one of identity_template, pod_annotation, or pod_label")
	}

	// eliminate orphaned identity_template_label
	if c.IdentityTemplateLabel != "" && c.IdentityTemplate == "" {
		return errs.New("identity_template_label defined without identity_template")
	}

	// eliminate orphaned context
	if c.Context != nil && c.IdentityTemplate == "" {
		return errs.New("context defined without identity_template")
	}

	// eliminate reference to non-existing context
	// strip out the blanc space first
	if c.Context == nil && c.IdentityTemplate != "" && strings.Contains(strings.ReplaceAll(c.IdentityTemplate, " ",""), "{{.Context.") {
		return errs.New("identity_template references non-existing context")
	}

	// IdentityTemplate represents the format following the trust domain and as such, it must not begin with spiffe://, // or /
	if strings.HasPrefix(c.IdentityTemplate, "spiffe://") ||
		strings.HasPrefix(c.IdentityTemplate, "/") {
		return errs.New("identity_template cannot start with spiffe:// or /")
	}

	// one, and only one, workload registartion identity format must be selected.
	if c.CommonMode.Mode == modeCRD && c.IdentityTemplate == "" && c.CommonMode.PodAnnotation == "" && c.CommonMode.PodLabel == "" {
		return errs.New("in crd mode, but no workload registration mode set")
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
		E:           entryClient,
		TrustDomain: c.TrustDomain,
	}).SetupWithManager(mgr)
	if err != nil {
		return err
	}

	if c.WebhookEnabled {
		err = spiffeidv1beta1.AddSpiffeIDWebhook(spiffeidv1beta1.SpiffeIDWebhookConfig{
			Ctx:         ctx,
			Log:         log,
			Mgr:         mgr,
			Namespace:   myNamespace,
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
			Namespace:   myNamespace,
			Scheme:      mgr.GetScheme(),
			TrustDomain: c.TrustDomain,
		}).SetupWithManager(mgr)
		if err != nil {
			return err
		}
		p, err := controllers.NewPodReconciler(controllers.PodReconcilerConfig{
			Client:                mgr.GetClient(),
			Cluster:               c.Cluster,
			Ctx:                   ctx,
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
		err := controllers.NewEndpointReconciler(controllers.EndpointReconcilerConfig{
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

func getNamespace() (string, error) {
	content, err := os.ReadFile(namespaceFile)
	if err != nil {
		return "", err
	}

	return string(content), nil
}
