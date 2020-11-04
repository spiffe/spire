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

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SpiffeIDReconcilerConfig holds the config passed in when creating the reconciler
type SpiffeIDReconcilerConfig struct {
	Client      client.Client
	Cluster     string
	Ctx         context.Context
	Log         logrus.FieldLogger
	R           registration.RegistrationClient
	TrustDomain string
}

// SpiffeIDReconciler holds the runtime configuration and state of this controller
type SpiffeIDReconciler struct {
	client.Client
	c SpiffeIDReconcilerConfig
}

// NewSpiffeIDReconciler creates a new SpiffeIDReconciler object
func NewSpiffeIDReconciler(config SpiffeIDReconcilerConfig) *SpiffeIDReconciler {
	return &SpiffeIDReconciler{
		Client: config.Client,
		c:      config,
	}
}

// SetupWithManager adds a controller manager to manage this reconciler
func (r *SpiffeIDReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&spiffeidv1beta1.SpiffeID{}).
		Complete(r)
}

// Reconcile ensures the SPIRE Server entry matches the corresponding CRD
func (r *SpiffeIDReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	spiffeID := spiffeidv1beta1.SpiffeID{}
	ctx := r.c.Ctx

	if err := r.Get(ctx, req.NamespacedName, &spiffeID); err != nil {
		if !k8serrors.IsNotFound(err) {
			r.c.Log.WithFields(logrus.Fields{
				"name":      spiffeID.Name,
				"namespace": spiffeID.Namespace,
			}).WithError(err).Error("Unable to fetch SpiffeID resource")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	myFinalizerName := "finalizers.spiffeid.spiffe.io"
	if spiffeID.ObjectMeta.DeletionTimestamp.IsZero() {
		// Add our finalizer if it doesn't already exist
		if !containsString(spiffeID.GetFinalizers(), myFinalizerName) {
			spiffeID.SetFinalizers(append(spiffeID.GetFinalizers(), myFinalizerName))
			if err := r.Update(ctx, &spiffeID); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// Delete event
		if containsString(spiffeID.GetFinalizers(), myFinalizerName) {
			if err := r.deleteSpiffeID(ctx, &spiffeID); err != nil {
				r.c.Log.WithFields(logrus.Fields{
					"name":      spiffeID.Name,
					"namespace": spiffeID.Namespace,
					"entryID":   *spiffeID.Status.EntryId,
				}).WithError(err).Error("Unable to delete registration entry")
				return ctrl.Result{}, err
			}

			// Remove our finalizer from the list and update it.
			spiffeID.SetFinalizers(removeStringIf(spiffeID.GetFinalizers(), myFinalizerName))
			if err := r.Update(ctx, &spiffeID); err != nil {
				return ctrl.Result{}, err
			}
			r.c.Log.WithFields(logrus.Fields{
				"name":      spiffeID.Name,
				"namespace": spiffeID.Namespace,
			}).Info("Finalized SPIFFE ID Resource")
		}
		return ctrl.Result{}, nil
	}

	entryID, preexisting, err := r.updateOrCreateSpiffeID(ctx, &spiffeID)
	if err != nil {
		// If the entry doesn't exist on the Spire Server but it should have, fall through
		// to clear the EntryID on the SPIFFE ID resource and recreate the entry
		if status.Code(err) != codes.NotFound {
			r.c.Log.WithFields(logrus.Fields{
				"name":      spiffeID.Name,
				"namespace": spiffeID.Namespace,
			}).WithError(err).Error("Unable to update or create registration entry")
			return ctrl.Result{}, err
		}
	}

	if !preexisting || spiffeID.Status.EntryId == nil {
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := r.Get(ctx, req.NamespacedName, &spiffeID); err != nil {
				return err
			}
			spiffeID.Status.EntryId = entryID
			if err := r.Status().Update(ctx, &spiffeID); err != nil {
				return err
			}
			return nil
		})
		if retryErr != nil {
			r.c.Log.WithFields(logrus.Fields{
				"name":      spiffeID.Name,
				"namespace": spiffeID.Namespace,
			}).WithError(err).Error("Unable to update SPIFFE ID status")
			return ctrl.Result{}, retryErr
		}
	}

	return ctrl.Result{}, nil
}

// updateOrCreateSpiffeID attempts to create a new entry. if the entry already exists, it updates it.
func (r *SpiffeIDReconciler) updateOrCreateSpiffeID(ctx context.Context, spiffeID *spiffeidv1beta1.SpiffeID) (*string, bool, error) {
	entry := &common.RegistrationEntry{
		ParentId:  spiffeID.Spec.ParentId,
		SpiffeId:  spiffeID.Spec.SpiffeId,
		Selectors: spiffeID.CommonSelector(),
		DnsNames:  spiffeID.Spec.DnsNames,
	}

	var existing *common.RegistrationEntry
	var entryID string
	var err error
	var preexisting bool
	if spiffeID.Status.EntryId != nil {
		// Fetch existing entry
		existing, err = r.c.R.FetchEntry(r.c.Ctx, &registration.RegistrationEntryID{
			Id: *spiffeID.Status.EntryId,
		})
		if err != nil {
			return nil, false, err
		}

		entryID = *spiffeID.Status.EntryId
		preexisting = true
	} else {
		// Create new entry
		response, err := r.c.R.CreateEntryIfNotExists(ctx, entry)
		if err != nil {
			return nil, false, err
		}
		existing = response.Entry
		entryID = response.Entry.EntryId
		preexisting = response.Preexisting
	}

	if preexisting {
		if !equalSpiffeID(existing, entry) {
			entry.EntryId = entryID
			_, err := r.c.R.UpdateEntry(ctx, &registration.UpdateEntryRequest{
				Entry: entry,
			})
			if err != nil {
				return nil, false, err
			}

			r.c.Log.WithFields(logrus.Fields{
				"entryID":  entryID,
				"spiffeID": spiffeID.Spec.SpiffeId,
			}).Info("Updated entry")
		}
	} else {
		r.c.Log.WithFields(logrus.Fields{
			"entryID":  entryID,
			"spiffeID": spiffeID.Spec.SpiffeId,
		}).Info("Created entry")
	}

	return &entryID, preexisting, nil
}

// deleteSpiffeID deletes the specified entry on the SPIRE Server
func (r *SpiffeIDReconciler) deleteSpiffeID(ctx context.Context, spiffeID *spiffeidv1beta1.SpiffeID) error {
	if spiffeID.Status.EntryId != nil {
		err := DeleteRegistrationEntry(ctx, r.c.R, *spiffeID.Status.EntryId)
		if err != nil {
			return err
		}

		r.c.Log.WithFields(logrus.Fields{
			"entryID":  *spiffeID.Status.EntryId,
			"spiffeID": spiffeID.Spec.SpiffeId,
		}).Info("Deleted entry")
	}

	return nil
}

// equalSpiffeID checks if the current SPIRE Server registration entry and SPIFFE ID resource are equal
func equalSpiffeID(existing, current *common.RegistrationEntry) bool {
	existingSet := selector.NewSetFromRaw(existing.Selectors)
	currentSet := selector.NewSetFromRaw(current.Selectors)

	return equalStringSlice(existing.DnsNames, current.DnsNames) &&
		existingSet.Equal(currentSet) &&
		existing.SpiffeId == current.SpiffeId &&
		existing.ParentId == current.ParentId
}
