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
	"bytes"
	"context"
	"errors"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
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

const (
	PodNameIDLabel           string = "pod_name"
	PodUIDLabel              string = "pod_uid"
	NamespaceIDLabel         string = "namespace"
	PodServiceAccountIDLabel string = "service_account"
	PodHostnameLabel         string = "hostname"
	PodNodeNameLabel         string = "node_name"
)

// PodReconcilerConfig holds the config passed in when creating the reconciler
type PodReconcilerConfig struct {
	Client                client.Client
	Cluster               string
	Ctx                   context.Context
	DisabledNamespaces    []string
	Log                   logrus.FieldLogger
	PodLabel              string
	PodAnnotation         string
	Scheme                *runtime.Scheme
	TrustDomain           string
	IdentityTemplate      string
	Context               map[string]string
	IdentityTemplateLabel string
}

// PodInfo is created for every processed Pod and it holds pod specific information
type PodInfo struct {
	PodServiceAccountIDLabel string
	NamespaceIDLabel         string
	PodNameIDLabel           string
	PodUIDLabel              string
	PodHostnameLabel         string
	PodNodeNameLabel         string
}

// IdentityMaps is used for forming the text from the templates
type IdentityMaps struct {
	Context map[string]string
	Pod     PodInfo
}

// PodReconciler holds the runtime configuration and state of this controller
type PodReconciler struct {
	client.Client
	c             PodReconcilerConfig
	identityTempl *template.Template
}

// NewPodReconciler creates a new PodReconciler object
func NewPodReconciler(config PodReconcilerConfig) (*PodReconciler, error) {

	tpl := config.IdentityTemplate
	tmpl, err := template.New("IdentityTemplate").Parse(tpl)
	if err != nil {
		config.Log.WithError(err).Errorf("error parsing the template %q", tpl)
		return &PodReconciler{}, err
	}
	return &PodReconciler{
		Client:        config.Client,
		c:             config,
		identityTempl: tmpl,
	}, nil
}

// SetupWithManager adds a controller manager to manage this reconciler
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// Reconcile creates a new SPIFFE ID when pods are created
func (r *PodReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	if containsString(r.c.DisabledNamespaces, req.NamespacedName.Namespace) {
		return ctrl.Result{}, nil
	}

	pod := corev1.Pod{}
	ctx := r.c.Ctx

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
			DnsNames:      []string{pod.Name}, // Set pod name as first DNS name
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
		err := r.Update(r.c.Ctx, &existing)
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

	// the controller has not been configured with a pod label or a pod annotation.
	if r.c.IdentityTemplate != "" {
		// create an entry using provided identity template.
		svid, err := r.getIdentityTemplate(pod)
		if err != nil {
			return "", err
		}

		if r.c.IdentityTemplateLabel != "" {
			if labelValue, ok := pod.Labels[r.c.IdentityTemplateLabel]; ok {
				if strings.EqualFold("true", labelValue) {
					return makeID(r.c.TrustDomain, svid), nil
				}
			}
			return "", nil
		}
		return makeID(r.c.TrustDomain, svid), nil
	}

	// the controller has not been configured with any required format. This should not happen, since the
	// config_crd prevents this case.
	// return makeID(r.c.TrustDomain, "ns/%s/sa/%s", pod.Namespace, pod.Spec.ServiceAccountName), nil
	return "", nil
}

func (r *PodReconciler) podParentID(nodeName string) string {
	return makeID(r.c.TrustDomain, "k8s-workload-registrar/%s/node/%s", r.c.Cluster, nodeName)
}

func (r *PodReconciler) getIdentityTemplate(pod *corev1.Pod) (string, error) {

	// Create the IdentityMaps struct, with maps, one for Pod and one for Context:
	podInfo := PodInfo{
		PodServiceAccountIDLabel: pod.Spec.ServiceAccountName,
		NamespaceIDLabel:         pod.Namespace,
		PodNameIDLabel:           pod.Name,
		PodUIDLabel:              string(pod.UID),
		PodHostnameLabel:         pod.Spec.Hostname,
		PodNodeNameLabel:         pod.Spec.NodeName,
	}

	templateMaps := IdentityMaps{
		Context: r.c.Context,
		Pod:     podInfo,
	}
	var svid bytes.Buffer
	err := r.identityTempl.Execute(&svid, templateMaps)
	if err != nil {
		r.c.Log.WithError(err).Errorf("Error executing the template %q with maps: %#v", r.c.IdentityTemplate, templateMaps)
		return svid.String(), err
	}
	// detect missing context values
	if strings.Contains(svid.String(), "<no value>") {
		err := errors.New("template references a value not included in context map")
		r.c.Log.WithError(err).Errorf("SVID: %s", svid.String())
		return svid.String(), err
	}
	// depending on runtime values, the SVID might end up with trailing '/' that is illegal
	if strings.HasSuffix(svid.String(), "/") {
		err := errors.New("invalid SVID, ends with /")
		r.c.Log.WithError(err).Errorf("SVID: %s", svid.String())
		return svid.String(), err
	}
	return svid.String(), nil
}
