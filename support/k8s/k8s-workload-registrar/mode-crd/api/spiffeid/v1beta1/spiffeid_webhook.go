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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
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
	R           registration.RegistrationClient
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

	// Check for duplicates
	registrationEntries, err := c.R.ListBySelectors(c.Ctx, &common.Selectors{
		Entries: s.CommonSelector(),
	})
	if err != nil {
		return err
	}
	if len(registrationEntries.Entries) > 0 {
		for _, entry := range registrationEntries.Entries {
			if s.Spec.SpiffeId == entry.SpiffeId {
				if s.Status.EntryId == nil || *s.Status.EntryId != entry.EntryId {
					c.Log.WithFields(logrus.Fields{
						"spiffeID": s.Spec.SpiffeId,
						"name":     s.ObjectMeta.Name,
						"entryId":  s.Status.EntryId,
					}).Info("Duplicate detected")
					return errs.New("Duplicate detected")
				}
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
func (s *SpiffeID) validateSpiffeID() error{
	spiffeIDPrefix := "spiffe://" + c.TrustDomain

	// Validate Spiffe and Parent IDs have the correct format
	if !strings.HasPrefix(s.Spec.ParentId, spiffeIDPrefix) {
		return errs.New("spec.parentId must begin with " + spiffeIDPrefix)
	}

	if !strings.HasPrefix(s.Spec.SpiffeId, spiffeIDPrefix) {
		return errs.New("spec.spiffeId must begin with " + spiffeIDPrefix)
	}

	if (s.Spec.Selector.Cluster != "" || s.Spec.Selector.AgentNodeUid != "") {
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

	return nil
}
