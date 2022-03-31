package certmanager

import (
	"bytes"
	"context"
	"encoding/pem"
	"time"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	cmapi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager/internal/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	schemeGroupVersion := schema.GroupVersion{Group: "cert-manager.io", Version: "v1"}
	scheme.AddKnownTypes(schemeGroupVersion,
		&cmapi.CertificateRequest{},
		&cmapi.CertificateRequestList{},
	)
	metav1.AddToGroupVersion(scheme, schemeGroupVersion)
}

func (p *Plugin) buildCertificateRequest(request *upstreamauthorityv1.MintX509CARequest) (*cmapi.CertificateRequest, error) {
	// Build PEM encoded CSR
	csrBuf := new(bytes.Buffer)
	err := pem.Encode(csrBuf, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: request.Csr,
	})
	if err != nil {
		return nil, err
	}

	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "spiffe-ca-",
			Namespace:    p.config.Namespace,
			Labels: map[string]string{
				"cert-manager.spiffe.io/trust-domain": p.trustDomain,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: time.Duration(request.PreferredTtl) * time.Second,
			},
			IssuerRef: cmapi.ObjectReference{
				Name:  p.config.IssuerName,
				Kind:  p.config.IssuerKind,
				Group: p.config.IssuerGroup,
			},
			Request: csrBuf.Bytes(),
			IsCA:    true,
			Usages: []cmapi.KeyUsage{
				cmapi.UsageCertSign,
				cmapi.UsageCRLSign,
			},
		},
	}, nil
}

// cleanupStaleCertificateRequests will attempt to delete CertificateRequests
// that have been created for this trust domain, and are in a terminal state.
// Terminal states are:
// - The request has been Denied
// - The request is in a Ready state
// - The request is in a Failed state
func (p *Plugin) cleanupStaleCertificateRequests(ctx context.Context) error {
	crList := &cmapi.CertificateRequestList{}
	err := p.cmclient.List(ctx, crList,
		client.MatchingLabels{"cert-manager.spiffe.io/trust-domain": p.trustDomain},
		client.InNamespace(p.config.Namespace),
	)
	if err != nil {
		return err
	}

	for i, cr := range crList.Items {
		for _, cond := range []cmapi.CertificateRequestCondition{
			cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionDenied,
				Status: cmapi.ConditionTrue,
			},
			cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmapi.ConditionTrue,
			},
			cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmapi.ConditionFalse,
				Reason: cmapi.CertificateRequestReasonFailed,
			},
		} {
			if ok, c := certificateRequestHasCondition(&crList.Items[i], cond); ok {
				log := p.log.With("namespace", cr.GetNamespace(), "name", cr.GetName(), "type", c.Type, "reason", c.Reason, "message", c.Message)
				log.Debug("Deleting stale CertificateRequest")
				if err := p.cmclient.Delete(ctx, &crList.Items[i]); err != nil {
					return err
				}

				break
			}
		}
	}

	return nil
}

// certificateRequestHasCondition will return true and the condition if the
// given CertificateRequest has a condition matching the provided
// CertificateRequestCondition.
// Only the Type and Status field will be used in the comparison, unless the
// given condition has set a Reason.
func certificateRequestHasCondition(cr *cmapi.CertificateRequest, c cmapi.CertificateRequestCondition) (bool, cmapi.CertificateRequestCondition) {
	if cr == nil {
		return false, cmapi.CertificateRequestCondition{}
	}
	existingConditions := cr.Status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			if c.Reason == "" || c.Reason == cond.Reason {
				return true, cond
			}
		}
	}
	return false, cmapi.CertificateRequestCondition{}
}
