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
	"testing"

	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/stretchr/testify/suite"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NodeName      string = "test-node"
	NodeNamespace string = "default"
)

func TestNodeController(t *testing.T) {
	suite.Run(t, new(NodeControllerTestSuite))
}

type NodeControllerTestSuite struct {
	suite.Suite
	CommonControllerTestSuite
}

func (s *NodeControllerTestSuite) SetupSuite() {
	s.CommonControllerTestSuite = NewCommonControllerTestSuite(s.T())
}

// TestAddRemoveNode adds a node and checks if an entry is created on the SPIRE Server.
// It then removes the node and checks if the entry is delete on the SPIRE Server.
func (s *NodeControllerTestSuite) TestAddNode() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := NewNodeReconciler(NodeReconcilerConfig{
		Client:      s.k8sClient,
		Cluster:     s.cluster,
		Log:         s.log,
		Namespace:   NodeNamespace,
		Scheme:      s.scheme,
		TrustDomain: s.trustDomain,
	})

	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:      NodeName,
			Namespace: NodeNamespace,
		},
		Spec: corev1.NodeSpec{},
	}
	err := s.k8sClient.Create(ctx, &node)
	s.Require().NoError(err)
	s.reconcile(n)
	labelSelector := labels.Set(map[string]string{
		"nodeUid": string(node.ObjectMeta.UID),
	})

	// Verify that exactly 1 SPIFFE ID resource was created for this node
	spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
	err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
		LabelSelector: labelSelector.AsSelector(),
	})
	s.Require().NoError(err)
	s.Require().Len(spiffeIDList.Items, 1)
}

func (s *NodeControllerTestSuite) reconcile(n *NodeReconciler) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      NodeName,
			Namespace: NodeNamespace,
		},
	}

	_, err := n.Reconcile(ctx, req)
	s.Require().NoError(err)

	_, err = s.r.Reconcile(ctx, req)
	s.Require().NoError(err)
}
