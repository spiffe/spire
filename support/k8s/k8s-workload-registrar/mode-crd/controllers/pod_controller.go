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

	"github.com/sirupsen/logrus"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// PodReconcilerConfig holds the config passed in when creating the reconciler
type PodReconcilerConfig struct {
	Client             client.Client
	Cluster            string
	Ctx                context.Context
	DisabledNamespaces []string
	Log                logrus.FieldLogger
	PodLabel           string
	PodAnnotation      string
	Scheme             *runtime.Scheme
	TrustDomain        string
}

// PodReconciler holds the runtime configuration and state of this controller
type PodReconciler struct {
	client.Client
	c PodReconcilerConfig
}

// NewPodReconciler creates a new PodReconciler object
func NewPodReconciler(config PodReconcilerConfig) *PodReconciler {
	return &PodReconciler{
		Client: config.Client,
		c:      config,
	}
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
		if !errors.IsNotFound(err) {
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
	spiffeIDURI := r.podSpiffeID(pod)
	// If we have no spiffe ID for the pod, do nothing
	if spiffeIDURI == "" {
		return ctrl.Result{}, nil
	}

	parentIDURI, err := r.podParentID(ctx, pod.Spec.NodeName)
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
			SpiffeId: spiffeIDURI,
			ParentId: parentIDURI,
			DnsNames: []string{pod.Name}, // Set pod name as first DNS name
			Selector: spiffeidv1beta1.Selector{
				PodUid:    pod.GetUID(),
				Namespace: pod.Namespace,
				NodeName:  pod.Spec.NodeName,
			},
		},
	}
	err = r.setOwnerRef(pod, spiffeID)
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
		if errors.IsNotFound(err) {
			// Create new entry
			return ctrl.Result{}, r.Create(ctx, spiffeID)
		}

		return ctrl.Result{}, err
	}

	if spiffeID.Spec.Selector.PodUid != existing.Spec.Selector.PodUid {
		// Already deleted pod is taking up the name, retry after it has deleted
		return ctrl.Result{Requeue: true}, nil
	}

	// Check if label/annotation or parentId has changed
	if spiffeID.Spec.SpiffeId != existing.Spec.SpiffeId || spiffeID.Spec.ParentId != existing.Spec.ParentId {
		existing.Spec.SpiffeId = spiffeID.Spec.SpiffeId
		existing.Spec.ParentId = spiffeID.Spec.ParentId
		err := r.Update(r.c.Ctx, &existing)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Nothing to do
	return ctrl.Result{}, nil
}

// podSpiffeID returns the desired spiffe ID for the pod, or nil if it should be ignored
func (r *PodReconciler) podSpiffeID(pod *corev1.Pod) string {
	if r.c.PodLabel != "" {
		// the controller has been configured with a pod label. if the pod
		// has that label, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if labelValue, ok := pod.Labels[r.c.PodLabel]; ok {
			return makeID(r.c.TrustDomain, "%s", labelValue)
		}
		return ""
	}

	if r.c.PodAnnotation != "" {
		// the controller has been configured with a pod annotation. if the pod
		// has that annotation, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if annotationValue, ok := pod.Annotations[r.c.PodAnnotation]; ok {
			return makeID(r.c.TrustDomain, "%s", annotationValue)
		}
		return ""
	}

	// the controller has not been configured with a pod label or a pod annotation.
	// create an entry based on the service account.
	return makeID(r.c.TrustDomain, "ns/%s/sa/%s", pod.Namespace, pod.Spec.ServiceAccountName)
}

// podParentID creates the PSAT parent spiffe ID for the pod
func (r *PodReconciler) podParentID(ctx context.Context, nodeName string) (string, error) {
	nodeUID, err := r.nodeNameToUID(ctx, nodeName)
	if err != nil {
		return "", err
	}
	return makeID(r.c.TrustDomain, "spire/agent/k8s_psat/%s/%s", r.c.Cluster, nodeUID), nil
}

// nodeNameToUID converts the Node Name, which is available in the PodSpec, to its UID
// by fetching the Node object from the Kubernetes API
func (r *PodReconciler) nodeNameToUID(ctx context.Context, nodeName string) (types.UID, error) {
	node := corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
		return "", err
	}
	return node.UID, nil
}

// setOwnerRef sets the pod as owner of a new SPIFFE ID resource locally
func (r *PodReconciler) setOwnerRef(pod *corev1.Pod, spiffeID *spiffeidv1beta1.SpiffeID) error {
	err := controllerutil.SetControllerReference(pod, spiffeID, r.c.Scheme)
	if err != nil {
		return err
	}

	// Make owner reference non-blocking, so object can be deleted if registrar is down
	ownerRef := metav1.GetControllerOfNoCopy(spiffeID)
	if ownerRef == nil {
		return err
	}
	ownerRef.BlockOwnerDeletion = pointer.BoolPtr(false)

	return nil
}
