package certmanager

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/go-hclog"
	cmapi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager/internal/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func Test_cleanupStaleCertificateRequests(t *testing.T) {
	const (
		trustDomain = "example.org"
		namespace   = "spire"
	)

	tests := map[string]struct {
		existingCRs []runtime.Object
		expectedCRs []string
	}{
		"if no CertificateRequests exist, should result in no requests": {
			existingCRs: nil,
			expectedCRs: []string{},
		},
		"if CertificateRequests exist with the correct label, but not in a terminal state, should not delete any": {
			existingCRs: []runtime.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-1",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionFalse, Reason: cmapi.CertificateRequestReasonPending},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-2",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
				},
			},
			expectedCRs: []string{"cr-1", "cr-2"},
		},
		"if CertificateRequests exist with the incorrect label and in a terminal state, should not delete any": {
			existingCRs: []runtime.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-1",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": "not-trust-domain",
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-2",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": "not-trust-domain",
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed},
						},
					},
				},
			},
			expectedCRs: []string{"cr-1", "cr-2"},
		},
		"if some CertificateRequests exist with the correct label and in a terminal state, should delete them": {
			existingCRs: []runtime.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-1",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-2",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": "not-trust-domain",
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-3",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionDenied, Status: cmapi.ConditionTrue},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-4",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionFalse, Reason: cmapi.CertificateRequestReasonPending},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-5",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-6",
						Namespace: namespace,
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionType("Random"), Status: cmapi.ConditionTrue},
						},
					},
				},
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cr-7",
						Namespace: "wrong-namespace",
						Labels: map[string]string{
							"cert-manager.spiffe.io/trust-domain": trustDomain,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{Type: cmapi.CertificateRequestConditionDenied, Status: cmapi.ConditionTrue},
						},
					},
				},
			},
			expectedCRs: []string{"cr-2", "cr-4", "cr-6", "cr-7"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := fakeclient.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(test.existingCRs...).Build()
			logOptions := hclog.DefaultOptions
			logOptions.Level = hclog.Debug
			p := &Plugin{
				log:         hclog.New(logOptions),
				cmclient:    client,
				trustDomain: trustDomain,
				config: &Configuration{
					Namespace: namespace,
				},
			}

			if err := p.cleanupStaleCertificateRequests(context.TODO()); err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			crList := &cmapi.CertificateRequestList{}
			if err := client.List(context.TODO(), crList); err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			var existingCRs []string
			for _, cr := range crList.Items {
				existingCRs = append(existingCRs, cr.Name)
			}
			if !equalUnsorted(existingCRs, test.expectedCRs) {
				t.Errorf("unexpected existing requests, exp=%s got=%s", test.expectedCRs, existingCRs)
			}
		})
	}
}

func equalUnsorted(s1 []string, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	s1_2, s2_2 := make([]string, len(s1)), make([]string, len(s2))
	copy(s1_2, s1)
	copy(s2_2, s2)
	sort.Strings(s1_2)
	sort.Strings(s2_2)
	for i, s := range s1_2 {
		if s != s2_2[i] {
			return false
		}
	}
	return true
}
