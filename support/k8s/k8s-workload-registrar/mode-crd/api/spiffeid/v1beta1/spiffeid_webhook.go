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

package v1beta1

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/zeebo/errs"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

type SpiffeIDWebhookConfig struct {
	Ctx         context.Context
	Log         logrus.FieldLogger
	Mgr         ctrl.Manager
	Namespace   string
	E           entry.EntryClient
	TrustDomain string
}

var c SpiffeIDWebhookConfig

func AddSpiffeIDWebhook(config SpiffeIDWebhookConfig) error {
	c = config
	return ctrl.NewWebhookManagedBy(config.Mgr).
		For(&SpiffeID{}).
		Complete()
}

var _ webhook.Validator = &SpiffeID{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (s *SpiffeID) ValidateCreate() error {
	if err := s.validateSpiffeID(); err != nil {
		return err
	}

	// TODO: filter additionally by SPIFFE ID? what about parent ID?

	// Check for duplicates
	resp, err := c.E.ListEntries(c.Ctx, &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			BySelectors: &types.SelectorMatch{
				Match:     types.SelectorMatch_MATCH_EXACT,
				Selectors: s.TypesSelector(),
			},
		},
	})
	if err != nil {
		return err
	}

	for _, entry := range resp.Entries {
		entrySPIFFEID, err := idutil.IDFromProto(entry.SpiffeId)
		if err != nil {
			return fmt.Errorf("entry SPIFFE ID is malformed: %v", err)
		}
		if s.Spec.SpiffeId == entrySPIFFEID.String() {
			if s.Status.EntryId == nil || *s.Status.EntryId != entry.Id {
				c.Log.WithFields(logrus.Fields{
					"spiffeID": s.Spec.SpiffeId,
					"name":     s.ObjectMeta.Name,
					"entryId":  s.Status.EntryId,
				}).Info("Duplicate detected")
				return errs.New("Duplicate detected")
			}
		}
	}

	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (s *SpiffeID) ValidateUpdate(old runtime.Object) error {
	return s.validateSpiffeID()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (s *SpiffeID) ValidateDelete() error {
	return nil
}

// validateSpiffeID does basic checks to make sure the SPIFFE ID resource is formatted correctly
func (s *SpiffeID) validateSpiffeID() error {
	spiffeIDPrefix := "spiffe://" + c.TrustDomain

	// Validate Spiffe and Parent IDs have the correct format
	if !strings.HasPrefix(s.Spec.ParentId, spiffeIDPrefix) {
		return errs.New("spec.parentId must begin with " + spiffeIDPrefix)
	}

	if !strings.HasPrefix(s.Spec.SpiffeId, spiffeIDPrefix) {
		return errs.New("spec.spiffeId must begin with " + spiffeIDPrefix)
	}

	if s.Spec.Selector.Cluster != "" || s.Spec.Selector.AgentNodeUid != "" {
		// k8s_psat selectors can only be used from the k8s-workload-registrar namespace
		if s.ObjectMeta.Namespace != c.Namespace {
			return errs.New("spec.Selector.Cluster and spec.Selector.AgentNodeUid can " +
				"only be used by the k8s-workload-registrar")
		}
	} else {
		// Ensure namespace selector matches namespace of Spiffe ID resource for k8s selectors
		if s.ObjectMeta.Namespace != s.Spec.Selector.Namespace {
			return errs.New("spec.Selector.Namespace must match namespace of resource")
		}
	}

	for _, dnsName := range s.Spec.DnsNames {
		if err := x509util.ValidateDNS(dnsName); err != nil {
			return fmt.Errorf("invalid DNS name %q: %v", dnsName, err)
		}
	}

	return nil
}
