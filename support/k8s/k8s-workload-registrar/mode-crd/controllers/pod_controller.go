/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	federation "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/federation"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PodReconcilerConfig holds the config passed in when creating the reconciler
type PodReconcilerConfig struct {
	Client                client.Client
	Cluster               string
	DisabledNamespaces    []string
	Log                   logrus.FieldLogger
	PodLabel              string
	PodAnnotation         string
	Scheme                *runtime.Scheme
	TrustDomain           string
	IdentityTemplate      string
	IdentityTemplateLabel string
	DNSNameTemplates      []string
	Context               map[string]string
}

const (
	PodNameLabel           = "Name"
	PodUIDLabel            = "UID"
	PodNamespaceLabel      = "Namespace"
	PodServiceAccountLabel = "ServiceAccount"
	PodHostnameLabel       = "Hostname"
	PodNodeNameLabel       = "NodeName"
	DefaultSpiffeIDPath    = "ns/{{.Pod.Namespace}}/sa/{{.Pod.ServiceAccount}}"
)

// PodInfo is created for every processed Pod and it holds pod specific information
type PodInfo struct {
	ServiceAccount string
	Namespace      string
	Name           string
	UID            types.UID
	Hostname       string
	NodeName       string
}

// IdentityMaps is used for forming the text from the templates
type IdentityMaps struct {
	Context map[string]string
	Pod     PodInfo
}

// PodReconciler holds the runtime configuration and state of this controller
type PodReconciler struct {
	client.Client
	c                PodReconcilerConfig
	identityTempl    *template.Template
	dnsNameTemplates []*template.Template
}

// NewPodReconciler creates a new PodReconciler object
func NewPodReconciler(config PodReconcilerConfig) (*PodReconciler, error) {
	if config.IdentityTemplate == "" && config.PodAnnotation == "" && config.PodLabel == "" {
		config.IdentityTemplate = DefaultSpiffeIDPath
	}

	identityTempl, dnsNameTemplates, err := parseTemplates(config)
	if err != nil {
		return &PodReconciler{}, err
	}

	if err := validateTemplates(config, identityTempl, dnsNameTemplates); err != nil {
		return &PodReconciler{}, err
	}

	return &PodReconciler{
		Client:           config.Client,
		c:                config,
		identityTempl:    identityTempl,
		dnsNameTemplates: dnsNameTemplates,
	}, nil
}

func parseTemplates(config PodReconcilerConfig) (*template.Template, []*template.Template, error) {
	var identityTempl *template.Template
	var err error
	if config.IdentityTemplate != "" {
		identityTempl, err = template.New("IdentityTemplate").Parse(config.IdentityTemplate)
		if err != nil {
			config.Log.WithError(err).WithField("identity_template", config.IdentityTemplate).Error("error parsing identity template")
			return nil, nil, fmt.Errorf("parsing identity template: %w", err)
		}
	}

	dnsNameTemplates := make([]*template.Template, 0, len(config.DNSNameTemplates))
	for _, dnsNameTemplate := range config.DNSNameTemplates {
		strippedTemplate := strings.ReplaceAll(dnsNameTemplate, " ", "")

		tmpl, err := template.New("DNSNameTemplate").Parse(strippedTemplate)
		if err != nil {
			config.Log.WithError(err).WithField("dns_name_template", strippedTemplate).Error("error parsing dns name template")
			return nil, nil, fmt.Errorf("parsing dns name template: %w", err)
		}
		dnsNameTemplates = append(dnsNameTemplates, tmpl)
	}

	return identityTempl, dnsNameTemplates, nil
}

func validateTemplates(
	config PodReconcilerConfig,
	identityTempl *template.Template,
	dnsNameTemplates []*template.Template,
) error {
	// While the Context is persistent and can be tested here, PodInfo is dynamic and changes with each Pod update, so using a dummy entry.
	templateMaps := IdentityMaps{
		Context: config.Context,
		Pod: PodInfo{
			ServiceAccount: "xx",
			Namespace:      "xx",
			Name:           "xx",
			UID:            types.UID("123"),
			Hostname:       "xx",
			NodeName:       "xx",
		},
	}

	if identityTempl != nil {
		var sb strings.Builder
		if err := identityTempl.Execute(&sb, templateMaps); err != nil {
			config.Log.WithError(err).WithFields(logrus.Fields{
				"identity_template": config.IdentityTemplate,
				"context":           config.Context,
			}).Error("Error executing the identity template")
			return fmt.Errorf("executing identity template: %w", err)
		}
		testSpiffeIDPath := sb.String()
		testSpiffeID := fmt.Sprintf("spiffe://testdomain/%s", testSpiffeIDPath)
		if _, err := spiffeid.FromString(testSpiffeID); err != nil {
			// The format of the template is incorrect and it is resulting in invalid SPIFFE ID paths.
			config.Log.WithError(err).WithFields(logrus.Fields{
				"identity_template": config.IdentityTemplate,
				"context":           config.Context,
			}).Error("Error validating the identity template components")
			return fmt.Errorf("validating identity template: %w", err)
		}
	}

	for i, dnsNameTemplate := range dnsNameTemplates {
		var sb strings.Builder
		if err := dnsNameTemplate.Execute(&sb, templateMaps); err != nil {
			config.Log.WithError(err).WithFields(logrus.Fields{
				"dns_name_template":      config.DNSNameTemplates[i],
				"dns_name_template_maps": templateMaps,
			}).Error("Error executing the dns name template")
			return fmt.Errorf("executing the dns name template: %w", err)
		}

		if err := x509util.ValidateDNS(sb.String()); err != nil {
			config.Log.WithError(err).WithFields(logrus.Fields{
				"dns_name_template": config.DNSNameTemplates[i],
				"context":           config.Context,
			}).Error("Error validating the dns name template")
			return fmt.Errorf("validating the dns name template: %w", err)
		}
	}

	return nil
}

// SetupWithManager adds a controller manager to manage this reconciler
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// Reconcile creates a new SPIFFE ID when pods are created
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if containsString(r.c.DisabledNamespaces, req.NamespacedName.Namespace) {
		return ctrl.Result{}, nil
	}

	pod := corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if !k8serrors.IsNotFound(err) {
			r.c.Log.WithError(err).Error("Unable to get Pod")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Pod needs to be assigned a node before it can get a SPIFFE ID
	if pod.Spec.NodeName == "" {
		return ctrl.Result{}, nil
	}

	return r.updateorCreatePodEntry(ctx, &pod)
}

// updateorCreatePodEntry attempts to create a new SpiffeID resource.
func (r *PodReconciler) updateorCreatePodEntry(ctx context.Context, pod *corev1.Pod) (ctrl.Result, error) {
	spiffeIDURI, err := r.podSpiffeID(pod)
	if err != nil {
		return ctrl.Result{}, err
	}
	// If we have no spiffe ID for the pod, do nothing
	if spiffeIDURI == "" {
		return ctrl.Result{}, nil
	}
	federationDomains := federation.GetFederationDomains(pod)

	// create DNS names
	dnsNames, err := r.createDNSNames(pod)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Set up new SPIFFE ID
	spiffeID := &spiffeidv1beta1.SpiffeID{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Labels: map[string]string{
				"podUid": string(pod.ObjectMeta.UID),
			},
		},
		Spec: spiffeidv1beta1.SpiffeIDSpec{
			SpiffeId:      spiffeIDURI,
			ParentId:      r.podParentID(pod.Spec.NodeName),
			DnsNames:      dnsNames,
			FederatesWith: federationDomains,
			Selector: spiffeidv1beta1.Selector{
				PodUid:    pod.GetUID(),
				Namespace: pod.Namespace,
				NodeName:  pod.Spec.NodeName,
			},
		},
	}
	err = setOwnerRef(pod, spiffeID, r.c.Scheme)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Check for existing entry
	existing := spiffeidv1beta1.SpiffeID{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      spiffeID.ObjectMeta.Name,
		Namespace: spiffeID.ObjectMeta.Namespace,
	}, &existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// Create new entry
			return ctrl.Result{}, r.Create(ctx, spiffeID)
		}

		return ctrl.Result{}, err
	}

	if spiffeID.Spec.Selector.PodUid != existing.Spec.Selector.PodUid {
		// Already deleted pod is taking up the name, retry after it has deleted
		return ctrl.Result{Requeue: true}, nil
	}

	// Check if label or annotation has changed
	if spiffeID.Spec.SpiffeId != existing.Spec.SpiffeId {
		existing.Spec.SpiffeId = spiffeID.Spec.SpiffeId
		err := r.Update(ctx, &existing)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Nothing to do
	return ctrl.Result{}, nil
}

// podSpiffeID returns the desired spiffe ID for the pod, or nil if it should be ignored
func (r *PodReconciler) podSpiffeID(pod *corev1.Pod) (string, error) {
	if r.c.PodLabel != "" {
		// the controller has been configured with a pod label. if the pod
		// has that label, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if labelValue, ok := pod.Labels[r.c.PodLabel]; ok {
			return makeID(r.c.TrustDomain, "%s", labelValue), nil
		}
		return "", nil
	}

	if r.c.PodAnnotation != "" {
		// the controller has been configured with a pod annotation. if the pod
		// has that annotation, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if annotationValue, ok := pod.Annotations[r.c.PodAnnotation]; ok {
			return makeID(r.c.TrustDomain, "%s", annotationValue), nil
		}
		return "", nil
	}

	// the controller has not been configured with a pod label or a pod annotation, so identity_template must be set
	// as it is enforced in config_crd
	if r.c.IdentityTemplate == "" {
		// this is just a sanity check
		return "", nil
	}

	// If identity_template_label is not provided, all pods get the template formatted SPIFFE ID.
	if r.c.IdentityTemplateLabel != "" {
		// If identity_template_label is provided, only pods that have this label=`true` get the template formatted SPIFFE ID.
		if labelValue, ok := pod.Labels[r.c.IdentityTemplateLabel]; ok {
			if !strings.EqualFold("true", labelValue) {
				return "", nil
			}
		} else {
			return "", nil
		}
	}

	// Create an entry using provided identity template.
	spiffeIDPath, err := r.generateSpiffeIDPath(pod)
	if err != nil {
		return "", err
	}
	return makeID(r.c.TrustDomain, spiffeIDPath), nil
}

func (r *PodReconciler) podParentID(nodeName string) string {
	return makeID(r.c.TrustDomain, "k8s-workload-registrar/%s/node/%s", r.c.Cluster, nodeName)
}

func (r *PodReconciler) generateSpiffeIDPath(pod *corev1.Pod) (string, error) {
	// Create the IdentityMaps struct, with Pod and Context map
	templateMaps := IdentityMaps{
		Context: r.c.Context,
		Pod: PodInfo{
			ServiceAccount: pod.Spec.ServiceAccountName,
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			UID:            pod.UID,
			Hostname:       pod.Spec.Hostname,
			NodeName:       pod.Spec.NodeName,
		},
	}
	var spiffeIDPathBuilder strings.Builder
	if err := r.identityTempl.Execute(&spiffeIDPathBuilder, templateMaps); err != nil {
		r.c.Log.WithError(err).WithFields(logrus.Fields{
			"identity_template":      r.c.IdentityTemplate,
			"identity_template_maps": templateMaps,
		}).Error("Error executing the identity template")
		return spiffeIDPathBuilder.String(), err
	}
	return spiffeIDPathBuilder.String(), nil
}

func (r *PodReconciler) createDNSNames(pod *corev1.Pod) ([]string, error) {
	dnsNames := make([]string, 0, len(r.c.DNSNameTemplates))
	// Create the IdentityMaps struct, with Pod and Context map
	templateMaps := IdentityMaps{
		Context: r.c.Context,
		Pod: PodInfo{
			ServiceAccount: pod.Spec.ServiceAccountName,
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			UID:            pod.UID,
			Hostname:       pod.Spec.Hostname,
			NodeName:       pod.Spec.NodeName,
		},
	}

	for i, dnsNameTemplate := range r.dnsNameTemplates {
		var dnsNameBuilder strings.Builder
		if err := dnsNameTemplate.Execute(&dnsNameBuilder, templateMaps); err != nil {
			r.c.Log.WithError(err).WithFields(logrus.Fields{
				"dns_name_template":      r.c.DNSNameTemplates[i],
				"dns_name_template_maps": templateMaps,
			}).Error("Error executing the dns name template")
			return nil, err
		}
		dnsNames = append(dnsNames, dnsNameBuilder.String())
	}

	return dnsNames, nil
}
