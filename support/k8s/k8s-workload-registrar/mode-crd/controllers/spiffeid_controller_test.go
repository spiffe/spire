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
	"testing"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spireTypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/stretchr/testify/suite"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	SpiffeIDName      = "test-spiffeid"
	SpiffeIDNamespace = "test-spiffeid-namespace"
)

func TestSpiffeIDController(t *testing.T) {
	suite.Run(t, new(SpiffeIDControllerTestSuite))
}

type SpiffeIDControllerTestSuite struct {
	suite.Suite
	CommonControllerTestSuite
}

func (s *SpiffeIDControllerTestSuite) SetupSuite() {
	s.CommonControllerTestSuite = NewCommonControllerTestSuite(s.T())
}

func (s *SpiffeIDControllerTestSuite) TestCreateSpiffeID() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First create the test namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: SpiffeIDNamespace,
		},
	}
	err := s.k8sClient.Create(ctx, namespace)
	s.Require().NoError(err)

	// Create the SPIFFE ID
	spiffeID := &spiffeidv1beta1.SpiffeID{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "spiffeid.spiffe.io/v1beta1",
			Kind:       "SpiffeID",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      SpiffeIDName,
			Namespace: SpiffeIDNamespace,
		},
		Spec: spiffeidv1beta1.SpiffeIDSpec{
			SpiffeId: makeID(s.trustDomain, "%s", SpiffeIDName),
			ParentId: makeID(s.trustDomain, "%s/%s", "spire", "server"),
			Selector: spiffeidv1beta1.Selector{
				Namespace: SpiffeIDNamespace,
			},
			Downstream: true,
		},
	}
	err = s.k8sClient.Create(ctx, spiffeID)
	s.Require().NoError(err)
	spiffeIDLookupKey := types.NamespacedName{Name: SpiffeIDName, Namespace: SpiffeIDNamespace}

	_, err = s.r.Reconcile(ctx, ctrl.Request{NamespacedName: spiffeIDLookupKey})
	s.Require().NoError(err)

	// Verify the Entry ID got set
	createdSpiffeID := &spiffeidv1beta1.SpiffeID{}
	err = s.k8sClient.Get(ctx, spiffeIDLookupKey, createdSpiffeID)
	s.Require().NoError(err)
	s.Require().NotNil(createdSpiffeID.Status.EntryId)

	// Check that the SPIFFE ID was created on the SPIRE server
	entry, err := s.entryClient.GetEntry(ctx, &entryv1.GetEntryRequest{
		Id: *createdSpiffeID.Status.EntryId,
	})
	s.Require().NoError(err)
	s.Require().NotNil(entry)
	s.Require().True(entry.Downstream)
	s.Require().Equal(makeID(s.trustDomain, "%s", SpiffeIDName), stringFromID(entry.SpiffeId))

	// Update SPIFFE ID
	createdSpiffeID.Spec.SpiffeId = makeID(s.trustDomain, "%s/%s", SpiffeIDName, "new")
	createdSpiffeID.Spec.ParentId = makeID(s.trustDomain, "%s/%s/%s", "spire", "server", "new")
	createdSpiffeID.Spec.Selector.PodName = "test"
	createdSpiffeID.Spec.Downstream = false
	err = s.k8sClient.Update(ctx, createdSpiffeID)
	s.Require().NoError(err)
	_, err = s.r.Reconcile(ctx, ctrl.Request{NamespacedName: spiffeIDLookupKey})
	s.Require().NoError(err)

	// Check SPIRE Server was updated
	entry, err = s.entryClient.GetEntry(ctx, &entryv1.GetEntryRequest{
		Id: *createdSpiffeID.Status.EntryId,
	})
	s.Require().NoError(err)
	s.Require().NotNil(entry)
	s.Require().Equal(createdSpiffeID.Spec.SpiffeId, stringFromID(entry.SpiffeId))
	s.Require().Equal(createdSpiffeID.Spec.ParentId, stringFromID(entry.ParentId))
	s.Require().False(createdSpiffeID.Spec.Downstream)
	s.Require().Equal(createdSpiffeID.Spec.Selector.PodName, "test")
}

func (s *SpiffeIDControllerTestSuite) TestSpiffeIDEqual() {
	var existing, current *spireTypes.SPIFFEID
	// Both nil
	s.Require().True(spiffeIDEqual(existing, current))

	// One nil
	var err error
	current, err = spiffeIDFromString(makeID(s.trustDomain, "%s", SpiffeIDName))
	s.Require().Nil(err)
	s.Require().False(spiffeIDEqual(existing, current))

	// Equal
	existing, err = spiffeIDFromString(makeID(s.trustDomain, "%s", SpiffeIDName))
	s.Require().Nil(err)
	s.Require().True(spiffeIDEqual(existing, current))

	// Not equal
	current, err = spiffeIDFromString(makeID(s.trustDomain, "%s", "spiffeid-not-equal"))
	s.Require().Nil(err)
	s.Require().False(spiffeIDEqual(existing, current))
}

func stringFromID(id *spireTypes.SPIFFEID) string {
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}
