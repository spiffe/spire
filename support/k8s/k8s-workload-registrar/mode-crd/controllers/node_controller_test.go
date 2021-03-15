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
	"testing"

	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/stretchr/testify/suite"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
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

// TestNodeSpiffeIDCleanup verifies the Node Reconciler can delete a SPIFFE ID custom resource
func (s *NodeControllerTestSuite) TestNodeSpiffeIDCleanup() {
	n := NewNodeReconciler(NodeReconcilerConfig{
		Client:    s.k8sClient,
		Ctx:       s.ctx,
		Log:       s.log,
		Namespace: NodeNamespace,
	})

	// Create the SPIFFE ID
	spiffeID := &spiffeidv1beta1.SpiffeID{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "spiffeid.spiffe.io/v1beta1",
			Kind:       "SpiffeID",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NodeName,
			Namespace: NodeNamespace,
		},
		Spec: spiffeidv1beta1.SpiffeIDSpec{
			SpiffeId: makeID(s.trustDomain, "%s", NodeName),
			ParentId: makeID(s.trustDomain, "%s/%s", "spire", "server"),
			Selector: spiffeidv1beta1.Selector{
				Cluster: Cluster,
			},
		},
	}
	err := s.k8sClient.Create(s.ctx, spiffeID)
	s.Require().NoError(err)

	// Reconcile the SPIFFE ID
	spiffeIDNamespacedName := types.NamespacedName{
		Name:      NodeName,
		Namespace: NodeNamespace,
	}
	_, err = s.r.Reconcile(ctrl.Request{NamespacedName: spiffeIDNamespacedName})
	s.Require().NoError(err)

	// Verify the SPIFFE ID was created
	createdSpiffeID := &spiffeidv1beta1.SpiffeID{}
	err = s.k8sClient.Get(s.ctx, spiffeIDNamespacedName, createdSpiffeID)
	s.Require().NoError(err)
	s.Require().NotNil(createdSpiffeID.Status.EntryId)

	// Run Node reconciler to delete the SPIFFE ID
	_, err = n.Reconcile(ctrl.Request{NamespacedName: spiffeIDNamespacedName})
	s.Require().NoError(err)

	// Verify the SPIFFE ID was deleted
	err = s.k8sClient.Get(s.ctx, spiffeIDNamespacedName, createdSpiffeID)
	s.Require().Error(err)
	s.Require().True(errors.IsNotFound(err))
}
