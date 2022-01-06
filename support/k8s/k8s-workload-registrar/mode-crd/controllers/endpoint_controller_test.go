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

func TestEndpointController(t *testing.T) {
	suite.Run(t, new(EndpointControllerTestSuite))
}

type EndpointControllerTestSuite struct {
	suite.Suite
	CommonControllerTestSuite
}

func (s *EndpointControllerTestSuite) SetupSuite() {
	s.CommonControllerTestSuite = NewCommonControllerTestSuite(s.T())
}

// TestAddDNSName deploys and endpoint and checks if the SPIFFE ID is updated
// with the correct DNS name
func (s *EndpointControllerTestSuite) TestAddDNSName() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPodReconciler(PodReconcilerConfig{
		Client:      s.k8sClient,
		Cluster:     s.cluster,
		Log:         s.log,
		PodLabel:    "spiffe",
		Scheme:      s.scheme,
		TrustDomain: s.trustDomain,
	})
	s.Require().NoError(err)

	e := NewEndpointReconciler(EndpointReconcilerConfig{
		Client: s.k8sClient,
		Log:    s.log,
	})

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-endpoint",
			Namespace: "default",
			Labels:    map[string]string{"spiffe": "test-endpoint-label"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "test-endpoint",
				Image: "test-endpoint",
			}},
			NodeName: "test-node",
		},
	}
	err = s.k8sClient.Create(ctx, &pod)
	s.Require().NoError(err)

	_, err = p.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-endpoint",
			Namespace: "default",
		},
	})
	s.Require().NoError(err)

	// Create the endpoint directly because the envtest does not automatically
	// create it when creating a service.
	endpoints := corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-endpoint",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: "1.2.3.4",
				TargetRef: &corev1.ObjectReference{
					UID: pod.ObjectMeta.UID,
				},
			}},
		}},
	}
	err = s.k8sClient.Create(ctx, &endpoints)
	s.Require().NoError(err)

	_, err = e.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-endpoint",
			Namespace: "default",
		},
	})
	s.Require().NoError(err)

	// Verify that SPIFFE ID  resource has the appropriate DNS name
	spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
	labelSelector := labels.Set(map[string]string{
		"podUid": string(pod.ObjectMeta.UID),
	})
	err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
		LabelSelector: labelSelector.AsSelector(),
	})
	s.Require().NoError(err)
	s.Require().Len(spiffeIDList.Items, 1)
	s.Require().Len(spiffeIDList.Items[0].Spec.DnsNames, 1)
	s.Require().Equal("test-endpoint.default.svc", spiffeIDList.Items[0].Spec.DnsNames[0])
}
