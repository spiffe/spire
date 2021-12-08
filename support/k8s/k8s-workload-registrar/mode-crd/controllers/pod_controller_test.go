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
	PodName           = "test-pod"
	PodNamespace      = "default"
	PodServiceAccount = "serviceAccount"
	DefaultTemplate   = "ns/{{.Pod.Namespace}}/sa/{{.Pod.ServiceAccount}}"
	SimpleTemplate    = "TEMPLATE"
	IdentityLabel     = "IDENTITYTEMPLATE"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
		err = s.k8sClient.Create(ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(ctx, p)
		labelSelector := labels.Set(map[string]string{
			"podUid": string(pod.ObjectMeta.UID),
		})

		// Verify that exactly 1 SPIFFE ID  resource was created for this pod
		spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
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
		err = s.k8sClient.Update(ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(ctx, p)

		// Verify that there is still exactly 1 SPIFFE ID resource for this pod
		spiffeIDList = spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
		s.Require().Len(spiffeIDList.Items, 1)

		// Verify the SPIFFE ID has changed
		expectedSpiffeID = makeID(s.trustDomain, "%s", test.second)
		actualSpiffeID = spiffeIDList.Items[0].Spec.SpiffeId
		s.Require().Equal(expectedSpiffeID, actualSpiffeID)

		// Delete Pod
		err = s.k8sClient.Delete(ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(ctx, p)
	}
}

// TestIdentityTemplate checks the various formats of the SPIFFE ID provided via IdentityTemplate.
func (s *PodControllerTestSuite) TestIdentityTemplate() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
			err:              "validating identity template",
		},
		{
			// Invalid Context reference.
			context: map[string]string{
				"Region":      "EU-DE",
				"ClusterName": "MYCLUSTER",
			},
			identityTemplate: "error/{{.Context.XXXX}}",
			err:              "validating identity template",
		},
		{
			// Invalid Pod reference.
			identityTemplate: "region/{{.Pod.XXXX}}",
			err:              "executing identity template",
		},
		{
			// Invalid prefix.
			identityTemplate: fmt.Sprintf("spiffe://testdomain/%s", DefaultTemplate),
			err:              "validating identity template",
		},
		{
			// Invalid prefix.
			identityTemplate: fmt.Sprintf("/testdomain/%s", DefaultTemplate),
			err:              "validating identity template",
		},
		{
			// Invalid prefix.
			identityTemplate: fmt.Sprintf("//%s", DefaultTemplate),
			err:              "validating identity template",
		},
		{
			// Invalid suffix.
			identityTemplate: fmt.Sprintf("%s/", DefaultTemplate),
			err:              "validating identity template: path cannot have a trailing slash",
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
		err = s.k8sClient.Create(ctx, &pod)
		s.Require().NoError(err)
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      PodName,
				Namespace: PodNamespace,
			},
		}
		_, err = p.Reconcile(ctx, req)
		s.Require().NoError(err)

		_, err = s.r.Reconcile(ctx, req)
		s.Require().NoError(err)

		labelSelector := labels.Set(map[string]string{
			"podUid": string(pod.ObjectMeta.UID),
		})

		// Verify that exactly 1 SPIFFE ID resource was created for this pod.
		spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
		s.Require().Len(spiffeIDList.Items, test.spiffeIDCount)
		if test.spiffeIDCount == 0 {
			err = s.k8sClient.Delete(ctx, &pod)
			s.Require().NoError(err)
			continue
		}
		// Verify the SVID matches what we expect.
		expectedSpiffeID := makeID(s.trustDomain, "%s", test.expectedSpiffeIDPath)
		actualSpiffeID := spiffeIDList.Items[0].Spec.SpiffeId
		s.Require().Equal(expectedSpiffeID, actualSpiffeID)

		// Delete Pod.
		err = s.k8sClient.Delete(ctx, &pod)
		s.Require().NoError(err)
		s.reconcile(ctx, p)
		spiffeIDList = spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
	}
}

// TestDNSNameTemplate checks that DNS name templates can be rendered properly into dnsNames.
func (s *PodControllerTestSuite) TestDNSNameTemplate() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tests := []struct {
		dnsNameTemplates []string
		expList          []string
		context          map[string]string
		err              string
	}{
		{
			// no template
			dnsNameTemplates: nil,
			expList:          nil,
		},
		{
			// invalid template
			dnsNameTemplates: []string{"{{.Does.Not.Exist}}"},
			err:              "can't evaluate field",
		},
		{
			// invalid dns name
			dnsNameTemplates: []string{"$%^&*"},
			err:              "validating the dns name template",
		},
		{
			// literal value
			dnsNameTemplates: []string{"my.dns.name"},
			expList:          []string{"my.dns.name"},
		},
		{
			// single DNS using Pod fields
			dnsNameTemplates: []string{"{{.Pod.ServiceAccount}}.{{.Pod.Namespace}}.svc"},
			expList:          []string{"serviceAccount.default.svc"},
		},
		{
			// single DNS using context fields
			context: map[string]string{
				"Namespace": "my-network",
			},
			dnsNameTemplates: []string{"{{.Pod.ServiceAccount}}.{{.Context.Namespace}}.svc"},
			expList:          []string{"serviceAccount.my-network.svc"},
		},
		{
			// multiple DNS entries without space
			dnsNameTemplates: []string{"{{.Pod.ServiceAccount}}.{{.Pod.Namespace}}.svc", "{{.Pod.Name}}.svc"},
			expList:          []string{"serviceAccount.default.svc", "test-pod.svc"},
		},
		{
			// multiple DNS entries with space
			dnsNameTemplates: []string{"{{.Pod.ServiceAccount}}.{{.Pod.Namespace}}.svc", "{{.Pod.Name}}.svc"},
			expList:          []string{"serviceAccount.default.svc", "test-pod.svc"},
		},
	}

	for _, test := range tests {
		p, err := NewPodReconciler(PodReconcilerConfig{
			Client:           s.k8sClient,
			Cluster:          s.cluster,
			Log:              s.log,
			Scheme:           s.scheme,
			TrustDomain:      s.trustDomain,
			Context:          test.context,
			DNSNameTemplates: test.dnsNameTemplates,
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
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: PodName,
				}},
				NodeName:           "test-node",
				Hostname:           "hostname",
				ServiceAccountName: PodServiceAccount,
			},
		}
		err = s.k8sClient.Create(ctx, &pod)
		s.Require().NoError(err)

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      PodName,
				Namespace: PodNamespace,
			},
		}
		_, err = p.Reconcile(ctx, req)
		s.Require().NoError(err)

		_, err = s.r.Reconcile(ctx, req)
		s.Require().NoError(err)

		labelSelector := labels.Set(map[string]string{
			"podUid": string(pod.ObjectMeta.UID),
		})

		// Verify that exactly 1 SPIFFE ID  resource was created for this pod
		spiffeIDList := spiffeidv1beta1.SpiffeIDList{}
		err = s.k8sClient.List(ctx, &spiffeIDList, &client.ListOptions{
			LabelSelector: labelSelector.AsSelector(),
		})
		s.Require().NoError(err)
		s.Require().Len(spiffeIDList.Items, 1)

		// Verify the dnsNames match what we expect
		dnsNames := spiffeIDList.Items[0].Spec.DnsNames
		s.Require().Equal(test.expList, dnsNames)

		// Delete Pod and SpiffeID
		err = s.k8sClient.Delete(ctx, &pod)
		s.Require().NoError(err)
		err = s.k8sClient.Delete(ctx, &spiffeIDList.Items[0])
		s.Require().NoError(err)
		s.reconcile(ctx, p)
	}
}

func (s *PodControllerTestSuite) reconcile(ctx context.Context, p *PodReconciler) {
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      PodName,
			Namespace: PodNamespace,
		},
	}

	_, err := p.Reconcile(ctx, req)
	s.Require().NoError(err)

	_, err = s.r.Reconcile(ctx, req)
	s.Require().NoError(err)
}
