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
	"fmt"
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
	PodName           string = "test-pod"
	PodNamespace      string = "default"
	PodServiceAccount string = "serviceAccount"
	DefaultTemplate   string = "ns/{{.Pod.Namespace}}/sa/{{.Pod.ServiceAccount}}"
	SimpleTemplate    string = "TEMPLATE"
	IdentityLabel     string = "IDENTITYTEMPLATE"
)

func TestPodController(t *testing.T) {
	suite.Run(t, new(PodControllerTestSuite))
}

type PodControllerTestSuite struct {
	suite.Suite
	CommonControllerTestSuite
}

func (s *PodControllerTestSuite) SetupSuite() {
	s.CommonControllerTestSuite = NewCommonControllerTestSuite(s.T())
}

// TestPodLabel adds a label to a pod and check if the SPIFFE ID is generated correctly.
// It then updates the label and ensures the SPIFFE ID is updated.
func (s *PodControllerTestSuite) TestPodLabel() {
	tests := []struct {
		PodLabel      string
		PodAnnotation string
		first         string
		second        string
	}{
		{
			PodLabel: "spiffe",
			first:    "test-label",
			second:   "new-test-label",
		},
		{
			PodAnnotation: "spiffe",
			first:         "test-annotation",
			second:        "new-test-annotation",
		},
	}

	for _, test := range tests {
		p, err := NewPodReconciler(PodReconcilerConfig{
			Client:        s.k8sClient,
			Cluster:       s.cluster,
			Ctx:           s.ctx,
			Log:           s.log,
			PodLabel:      test.PodLabel,
			PodAnnotation: test.PodAnnotation,
			Scheme:        s.scheme,
			TrustDomain:   s.trustDomain,
		})
		s.Require().NoError(err)

		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        PodName,
				Namespace:   PodNamespace,
				Labels:      map[string]string{"spiffe": test.first},
				Annotations: map[string]string{"spiffe": test.first},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "test-pod",
					Image: "test-pod",
				}},
				NodeName: "test-node",
			},
		}
		err = s.k8sClient.Create(s.ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(p)
		labelSelector := labels.Set(map[string]string{
			"podUid": string(pod.ObjectMeta.UID),
		})

		// Verify that exactly 1 SPIFFE ID  resource was created for this pod
		spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(s.ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
		s.Require().Len(spiffeIDList.Items, 1)

		// Verify the label/annotation matches what we expect
		expectedSpiffeID := makeID(s.trustDomain, "%s", test.first)
		actualSpiffeID := spiffeIDList.Items[0].Spec.SpiffeId
		s.Require().Equal(expectedSpiffeID, actualSpiffeID)

		// Update the labels/annotations
		pod.Labels["spiffe"] = test.second
		pod.Annotations["spiffe"] = test.second
		err = s.k8sClient.Update(s.ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(p)

		// Verify that there is still exactly 1 SPIFFE ID resource for this pod
		spiffeIDList = spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(s.ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
		s.Require().Len(spiffeIDList.Items, 1)

		// Verify the SPIFFE ID has changed
		expectedSpiffeID = makeID(s.trustDomain, "%s", test.second)
		actualSpiffeID = spiffeIDList.Items[0].Spec.SpiffeId
		s.Require().Equal(expectedSpiffeID, actualSpiffeID)

		// Delete Pod
		err = s.k8sClient.Delete(s.ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(p)
	}
}

// TestIdentityTemplate checks the various formats of the SPIFFE ID provided via IdentityTemplate.
func (s *PodControllerTestSuite) TestIdentityTemplate() {
	tests := []struct {
		identityTemplate      string
		identityTemplateLabel string
		labelValue            string
		context               map[string]string
		expectedSpiffeIDPath  string
		uid                   string
		err                   string
		spiffeIDCount         int
	}{
		// This section is testing various error conditions.
		{
			// Missing Context map.
			identityTemplate: "region/{{.Context.Region}}",
			err:              "path characters are limited to letters, numbers, dots, dashes, and underscores",
		},
		{
			// Invalid Context reference.
			context: map[string]string{
				"Region":      "EU-DE",
				"ClusterName": "MYCLUSTER",
			},
			identityTemplate: "error/{{.Context.XXXX}}",
			err:              "path characters are limited to letters, numbers, dots, dashes, and underscores",
		},
		{
			// Invalid Pod reference.
			identityTemplate: "region/{{.Pod.XXXX}}",
			err:              "can't evaluate field XXXX",
		},
		{
			// Invalid prefix.
			identityTemplate: fmt.Sprintf("spiffe://testdomain/%s", DefaultTemplate),
			err:              "path characters are limited to letters, numbers, dots, dashes, and underscores",
		},
		{
			// Invalid prefix.
			identityTemplate: fmt.Sprintf("/testdomain/%s", DefaultTemplate),
			err:              "path cannot contain empty segments",
		},
		{
			// Invalid prefix.
			identityTemplate: fmt.Sprintf("//%s", DefaultTemplate),
			err:              "path cannot contain empty segments",
		},
		{
			// Invalid suffix.
			identityTemplate: fmt.Sprintf("%s/", DefaultTemplate),
			err:              "path cannot have a trailing slash",
		},

		// This section is testing the identity_template_label.
		{
			// Label requested, but pod not labeled.
			identityTemplate:      SimpleTemplate,
			identityTemplateLabel: IdentityLabel,
			spiffeIDCount:         0,
		},
		{
			// Label requested, but pod labeled 'false'
			identityTemplate:      SimpleTemplate,
			identityTemplateLabel: IdentityLabel,
			labelValue:            "false",
			spiffeIDCount:         0,
		},
		{
			// Label not set.
			identityTemplate:     DefaultTemplate,
			expectedSpiffeIDPath: fmt.Sprintf("ns/%s/sa/%s", PodNamespace, PodServiceAccount),
			spiffeIDCount:        1,
		},
		{
			// Label empty.
			identityTemplate:      DefaultTemplate,
			identityTemplateLabel: "",
			expectedSpiffeIDPath:  fmt.Sprintf("ns/%s/sa/%s", PodNamespace, PodServiceAccount),
			spiffeIDCount:         1,
		},
		{
			// Label requested and pod labeled.
			identityTemplate:      DefaultTemplate,
			identityTemplateLabel: IdentityLabel,
			labelValue:            "true",
			expectedSpiffeIDPath:  fmt.Sprintf("ns/%s/sa/%s", PodNamespace, PodServiceAccount),
			spiffeIDCount:         1,
		},
		{
			// Label empty and pod labeled with `false`.
			identityTemplate:      DefaultTemplate,
			identityTemplateLabel: "",
			labelValue:            "false",
			expectedSpiffeIDPath:  fmt.Sprintf("ns/%s/sa/%s", PodNamespace, PodServiceAccount),
			spiffeIDCount:         1,
		},

		// This section is testing identity template formatting.
		{
			identityTemplate:     DefaultTemplate,
			expectedSpiffeIDPath: fmt.Sprintf("ns/%s/sa/%s", PodNamespace, PodServiceAccount),
			spiffeIDCount:        1,
		},
		{
			identityTemplate:     fmt.Sprintf("ns/{{.Pod.%s}}/sa/{{.Pod.%s}}", PodNamespaceLabel, PodServiceAccountLabel),
			expectedSpiffeIDPath: fmt.Sprintf("ns/%s/sa/%s", PodNamespace, PodServiceAccount),
			spiffeIDCount:        1,
		},
		{
			identityTemplate:     DefaultTemplate + "/podName/{{.Pod.Name}}",
			expectedSpiffeIDPath: fmt.Sprintf("ns/%s/sa/%s/podName/%s", PodNamespace, PodServiceAccount, PodName),
			spiffeIDCount:        1,
		},
		{
			// Testing Context usage.
			context: map[string]string{
				"Region":      "EU-DE",
				"ClusterName": "MYCLUSTER",
			},
			identityTemplate:     fmt.Sprintf("region/{{.Context.Region}}/cluster/{{.Context.ClusterName}}/podName/{{.Pod.%s}}", PodNameLabel),
			expectedSpiffeIDPath: fmt.Sprintf("region/EU-DE/cluster/MYCLUSTER/podName/%s", PodName),
			spiffeIDCount:        1,
		},
		{
			// Testing various Pod elements.
			identityTemplate:     fmt.Sprintf("{{.Pod.%s}}/{{.Pod.%s}}/{{.Pod.%s}}/{{.Pod.%s}}/{{.Pod.%s}}", PodNameLabel, PodNamespaceLabel, PodServiceAccountLabel, PodHostnameLabel, PodNodeNameLabel),
			expectedSpiffeIDPath: fmt.Sprintf("%s/%s/%s/hostname/test-node", PodName, PodNamespace, PodServiceAccount),
			spiffeIDCount:        1,
		},
	}

	for _, test := range tests {
		p, err := NewPodReconciler(PodReconcilerConfig{
			Client:                s.k8sClient,
			Cluster:               s.cluster,
			Ctx:                   s.ctx,
			Log:                   s.log,
			Scheme:                s.scheme,
			TrustDomain:           s.trustDomain,
			IdentityTemplate:      test.identityTemplate,
			Context:               test.context,
			IdentityTemplateLabel: test.identityTemplateLabel,
		})
		if test.err != "" {
			s.Require().Error(err)
			s.Require().Contains(err.Error(), test.err)
			continue
		}
		s.Require().NoError(err)

		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      PodName,
				Namespace: PodNamespace,
				Labels:    map[string]string{test.identityTemplateLabel: test.labelValue},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "test-pod",
					Image: "test-pod",
				}},
				NodeName:           "test-node",
				Hostname:           "hostname",
				ServiceAccountName: PodServiceAccount,
			},
		}
		err = s.k8sClient.Create(s.ctx, &pod)
		s.Require().NoError(err)
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      PodName,
				Namespace: PodNamespace,
			},
		}
		_, err = p.Reconcile(req)
		s.Require().NoError(err)

		_, err = s.r.Reconcile(req)
		s.Require().NoError(err)

		labelSelector := labels.Set(map[string]string{
			"podUid": string(pod.ObjectMeta.UID),
		})

		// Verify that exactly 1 SPIFFE ID resource was created for this pod.
		spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(s.ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
		s.Require().Len(spiffeIDList.Items, test.spiffeIDCount)
		if test.spiffeIDCount == 0 {
			err = s.k8sClient.Delete(s.ctx, &pod)
			s.Require().NoError(err)
			continue
		}
		// Verify the SVID matches what we expect.
		expectedSpiffeID := makeID(s.trustDomain, "%s", test.expectedSpiffeIDPath)
		actualSpiffeID := spiffeIDList.Items[0].Spec.SpiffeId
		s.Require().Equal(expectedSpiffeID, actualSpiffeID)

		// Delete Pod.
		err = s.k8sClient.Delete(s.ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(p)
		spiffeIDList = spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(s.ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
	}
}

func (s *PodControllerTestSuite) reconcile(p *PodReconciler) {
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      PodName,
			Namespace: PodNamespace,
		},
	}

	_, err := p.Reconcile(req)
	s.Require().NoError(err)

	_, err = s.r.Reconcile(req)
	s.Require().NoError(err)
}
