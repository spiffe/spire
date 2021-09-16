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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EndpointReconcilerConfig holds the config passed in when creating the reconciler
type EndpointReconcilerConfig struct {
	Client             client.Client
	DisabledNamespaces []string
	Log                logrus.FieldLogger
	PodLabel           string
	PodAnnotation      string
}

// EndpointReconciler holds the runtime configuration and state of this controller
type EndpointReconciler struct {
	client.Client
	c EndpointReconcilerConfig
}

// NewEndpointReconciler creates a new EndpointReconciler object
func NewEndpointReconciler(config EndpointReconcilerConfig) *EndpointReconciler {
	return &EndpointReconciler{
		Client: config.Client,
		c:      config,
	}
}

// SetupWithManager adds a controller manager to manage this reconciler
func (e *EndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Endpoints{}).
		Complete(e)
}

// Reconcile steps through the endpoints for each service and adds the name of the service as
// a DNS name to the SPIFFE ID CRD
func (e *EndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if containsString(e.c.DisabledNamespaces, req.NamespacedName.Namespace) {
		return ctrl.Result{}, nil
	}

	endpoints := corev1.Endpoints{}

	if err := e.Get(ctx, req.NamespacedName, &endpoints); err != nil {
		if errors.IsNotFound(err) {
			// Delete event
			if err := e.deleteExternalResources(ctx, req.NamespacedName); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, client.IgnoreNotFound(err)
		}

		e.c.Log.WithError(err).Error("Unable to fetch Endpoints")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	svcName := getServiceDNSName(req.NamespacedName)
	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			if address.TargetRef == nil {
				continue
			}

			// Get SPIFFE ID resource associated with this endpoint
			spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
			labelSelector := labels.Set(map[string]string{
				"podUid": string(address.TargetRef.UID),
			})
			err := e.List(ctx, &spiffeIDList, &client.ListOptions{
				LabelSelector: labelSelector.AsSelector(),
			})
			if err != nil {
				e.c.Log.WithError(err).Error("Error getting spiffeid list")
				return ctrl.Result{}, err
			}

			// If there are no SPIFFE ID resources associated with this endpoint, we may need to requeue
			// Its possible this reconcile loop ran before the SPIFFE ID resource was generated
			if len(spiffeIDList.Items) == 0 {
				return ctrl.Result{
					Requeue: e.requeue(ctx, address.TargetRef.Name, address.TargetRef.Namespace),
				}, nil
			}

			// Iterate through the list of SPIFFE ID resources and update to add the DNS name
			for _, spiffeID := range spiffeIDList.Items {
				if !containsString(spiffeID.Spec.DnsNames, svcName) {
					spiffeID := spiffeID
					spiffeID.Spec.DnsNames = append(spiffeID.Spec.DnsNames, svcName)
					err := e.Update(ctx, &spiffeID)
					if err != nil {
						return ctrl.Result{}, err
					}

					e.c.Log.WithFields(logrus.Fields{
						"spiffeID": spiffeID.ObjectMeta.Name,
						"dnsName":  svcName,
					}).Info("Adding DNS name")
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

// deleteExternalResources removes the service name from the list of DNS Names when the service is removed
func (e *EndpointReconciler) deleteExternalResources(ctx context.Context, namespacedName types.NamespacedName) error {
	svcName := getServiceDNSName(namespacedName)
	spiffeIDList := spiffeidv1beta1.SpiffeIDList{}

	err := e.List(ctx, &spiffeIDList, &client.ListOptions{
		Namespace: namespacedName.Namespace,
	})
	if err != nil {
		if !errors.IsNotFound(err) {
			e.c.Log.WithFields(logrus.Fields{
				"service": svcName,
			}).WithError(err).Error("Failed to get list of SpiffeID CRDs")
			return err
		}

		return nil
	}

	for _, spiffeID := range spiffeIDList.Items {
		e.c.Log.WithFields(logrus.Fields{
			"spiffeID": spiffeID.ObjectMeta.Name,
		}).Info("Removing DNS names")

		spiffeID := spiffeID
		spiffeID.Spec.DnsNames = removeStringIf(spiffeID.Spec.DnsNames, svcName)

		if err := e.Update(ctx, &spiffeID); err != nil {
			e.c.Log.WithFields(logrus.Fields{
				"spiffeID": spiffeID.ObjectMeta.Name,
			}).WithError(err).Error("Unable to delete DNS names in SpiffeID CRD")
			return err
		}
	}

	return nil
}

// requeue determines if the reconcile needs to be requeued. If the controller has been configured with a
// pod label/annotation and the pod has the label/annotation then yes. If the controller has not been
// configured with a pod label/annotation then yes. Otherwise no.
func (e *EndpointReconciler) requeue(ctx context.Context, name, namespace string) bool {
	pod := corev1.Pod{}
	podNamespacedName := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	if err := e.Get(ctx, podNamespacedName, &pod); err != nil {
		// Requeue if we are not able to get the pod object
		return true
	}

	if e.c.PodLabel != "" {
		if _, ok := pod.Labels[e.c.PodLabel]; ok {
			return true
		}
		return false
	}

	if e.c.PodAnnotation != "" {
		if _, ok := pod.Annotations[e.c.PodAnnotation]; ok {
			return true
		}
		return false
	}

	return true
}

func getServiceDNSName(namespacedName types.NamespacedName) string {
	return namespacedName.Name + "." + namespacedName.Namespace + ".svc"
}
