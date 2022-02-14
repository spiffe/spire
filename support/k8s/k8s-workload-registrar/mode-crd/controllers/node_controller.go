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
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NodeReconcilerConfig holds the config passed in when creating the reconciler
type NodeReconcilerConfig struct {
	Client      client.Client
	Cluster     string
	Log         logrus.FieldLogger
	Namespace   string
	Scheme      *runtime.Scheme
	TrustDomain string
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

// Reconcile creates a SPIFFE ID for each node, used to parent SPIFFE IDs for pods
// running on that node
func (n *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	node := corev1.Node{}
	if err := n.Get(ctx, req.NamespacedName, &node); err != nil {
		if !errors.IsNotFound(err) {
			n.c.Log.WithError(err).Error("Unable to fetch Node")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return n.updateorCreateNodeEntry(ctx, &node)
}

// updateorCreateNodeEntry attempts to create a new SpiffeID resource.
func (n *NodeReconciler) updateorCreateNodeEntry(ctx context.Context, node *corev1.Node) (ctrl.Result, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(n.c.TrustDomain)
	if err != nil {
		return ctrl.Result{}, err
	}

	serverID, err := idutil.ServerID(trustDomain)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Set up new SPIFFE ID
	spiffeID := &spiffeidv1beta1.SpiffeID{
		ObjectMeta: metav1.ObjectMeta{
			Name:      node.Name,
			Namespace: n.c.Namespace,
			Labels: map[string]string{
				"nodeUid": string(node.ObjectMeta.UID),
			},
		},
		Spec: spiffeidv1beta1.SpiffeIDSpec{
			ParentId: serverID.String(),
			SpiffeId: n.nodeID(node.ObjectMeta.Name),
			Selector: spiffeidv1beta1.Selector{
				Cluster:      n.c.Cluster,
				AgentNodeUid: node.ObjectMeta.UID,
			},
		},
	}
	err = setOwnerRef(node, spiffeID, n.c.Scheme)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Check for existing entry
	existing := spiffeidv1beta1.SpiffeID{}
	err = n.Get(ctx, types.NamespacedName{
		Name:      spiffeID.ObjectMeta.Name,
		Namespace: spiffeID.ObjectMeta.Namespace,
	}, &existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new entry
			return ctrl.Result{}, n.Create(ctx, spiffeID)
		}

		return ctrl.Result{}, err
	}

	// Nothing to do
	return ctrl.Result{}, nil
}

func (n *NodeReconciler) nodeID(nodeName string) string {
	return makeID(n.c.TrustDomain, "k8s-workload-registrar/%s/node/%s", n.c.Cluster, nodeName)
}
