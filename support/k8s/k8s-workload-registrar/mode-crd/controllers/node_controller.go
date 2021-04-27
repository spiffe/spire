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
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NodeReconcilerConfig holds the config passed in when creating the reconciler
type NodeReconcilerConfig struct {
	Client    client.Client
	Ctx       context.Context
	E         entryv1.EntryClient
	Log       logrus.FieldLogger
	Namespace string
}

// NodeReconciler holds the runtime configuration and state of this controller
type NodeReconciler struct {
	client.Client
	c NodeReconcilerConfig
}

// NewNodeReconciler creates a new NodeReconciler object
func NewNodeReconciler(config NodeReconcilerConfig) *NodeReconciler {
	return &NodeReconciler{
		Client: config.Client,
		c:      config,
	}
}

// SetupWithManager adds a controller manager to manage this reconciler
func (n *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Complete(n)
}

// Reconcile removes the deprecated SPIFFE ID custom resource created for each node. PSAT parents
// are now used instead.
func (n *NodeReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	spiffeID := spiffeidv1beta1.SpiffeID{}
	err := n.Get(n.c.Ctx, types.NamespacedName{
		Name:      req.NamespacedName.Name,
		Namespace: n.c.Namespace,
	}, &spiffeID)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}

		return ctrl.Result{}, err
	}

	// Get all entries with this node as a parent. Until the pod reconciler reparents everything
	// and the list is empty, we will requeue.
	parentID, err := spiffeIDFromString(spiffeID.Spec.SpiffeId)
	if err != nil {
		return ctrl.Result{}, err
	}
	resp, err := n.c.E.ListEntries(n.c.Ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			ByParentId: parentID,
		},
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(resp.Entries) != 0 {
		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{}, n.Delete(n.c.Ctx, &spiffeID)
}
