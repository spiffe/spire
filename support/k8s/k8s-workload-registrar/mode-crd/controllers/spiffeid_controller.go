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
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SpiffeIDReconcilerConfig holds the config passed in when creating the reconciler
type SpiffeIDReconcilerConfig struct {
	Client  client.Client
	Cluster string
	Log     logrus.FieldLogger
	E       entryv1.EntryClient
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
func (r *SpiffeIDReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	spiffeID := spiffeidv1beta1.SpiffeID{}
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
			return r.Status().Update(ctx, &spiffeID)
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
	entry, err := entryFromCRD(spiffeID)
	if err != nil {
		return nil, false, err
	}

	var existing *types.Entry
	var entryID string
	var preexisting bool
	if spiffeID.Status.EntryId != nil {
		// Fetch existing entry
		existing, err = r.c.E.GetEntry(ctx, &entryv1.GetEntryRequest{
			Id: *spiffeID.Status.EntryId,
		})
		if err != nil {
			return nil, false, err
		}

		entryID = *spiffeID.Status.EntryId
		preexisting = true
	} else {
		// Create new entry
		existing, preexisting, err = r.createEntry(ctx, entry)
		if err != nil {
			return nil, false, err
		}
		entryID = existing.Id
	}

	if preexisting {
		if !entryEqual(existing, entry) {
			entry.Id = entryID
			if err := r.updateEntry(ctx, entry); err != nil {
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
		err := deleteRegistrationEntry(ctx, r.c.E, *spiffeID.Status.EntryId)
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

func (r *SpiffeIDReconciler) createEntry(ctx context.Context, entry *types.Entry) (*types.Entry, bool, error) {
	resp, err := r.c.E.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
		Entries: []*types.Entry{entry},
	})
	if err != nil {
		return nil, false, err
	}

	// These checks are purely defensive.
	switch {
	case len(resp.Results) > 1:
		return nil, false, errors.New("batch create response has too many results")
	case len(resp.Results) < 1:
		return nil, false, errors.New("batch create response result empty")
	}

	err = errorFromStatus(resp.Results[0].Status)
	switch status.Code(err) {
	case codes.OK:
		return resp.Results[0].Entry, false, nil
	case codes.AlreadyExists:
		return resp.Results[0].Entry, true, nil
	default:
		return nil, false, err
	}
}

func (r *SpiffeIDReconciler) updateEntry(ctx context.Context, entry *types.Entry) error {
	resp, err := r.c.E.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{
		Entries: []*types.Entry{entry},
	})
	if err != nil {
		return err
	}

	// These checks are purely defensive.
	switch {
	case len(resp.Results) > 1:
		return errors.New("batch create response has too many results")
	case len(resp.Results) < 1:
		return errors.New("batch create response result empty")
	}

	return errorFromStatus(resp.Results[0].Status)
}

func errorFromStatus(s *types.Status) error {
	if s == nil {
		return errors.New("result status is unexpectedly nil")
	}
	return status.Error(codes.Code(s.Code), s.Message)
}

func entryFromCRD(crd *spiffeidv1beta1.SpiffeID) (*types.Entry, error) {
	parentID, err := spiffeIDFromString(crd.Spec.ParentId)
	if err != nil {
		return nil, errs.New("malformed CRD parent ID: %v", err)
	}
	spiffeID, err := spiffeIDFromString(crd.Spec.SpiffeId)
	if err != nil {
		return nil, errs.New("malformed CRD SPIFFE ID: %v", err)
	}
	return &types.Entry{
		ParentId:      parentID,
		SpiffeId:      spiffeID,
		Selectors:     crd.TypesSelector(),
		DnsNames:      crd.Spec.DnsNames,
		FederatesWith: crd.Spec.FederatesWith,
		Downstream:    crd.Spec.Downstream,
	}, nil
}

func spiffeIDFromString(rawID string) (*types.SPIFFEID, error) {
	id, err := spiffeid.FromString(rawID)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}, nil
}

// entryEqual checks if the current SPIRE Server registration entry and SPIFFE ID resource are equal
func entryEqual(existing, current *types.Entry) bool {
	return equalStringSlice(existing.DnsNames, current.DnsNames) &&
		selectorSetsEqual(existing.Selectors, current.Selectors) &&
		spiffeIDEqual(existing.SpiffeId, current.SpiffeId) &&
		spiffeIDEqual(existing.ParentId, current.ParentId) &&
		existing.Downstream == current.Downstream
}

func spiffeIDEqual(existing, current *types.SPIFFEID) bool {
	if existing == nil || current == nil {
		return existing == current
	}
	return existing.String() == current.String()
}

func selectorSetsEqual(as, bs []*types.Selector) bool {
	if len(as) != len(bs) {
		return false
	}
	type sel struct {
		t string
		v string
	}
	set := map[sel]struct{}{}
	for _, a := range as {
		set[sel{t: a.Type, v: a.Value}] = struct{}{}
	}
	for _, b := range bs {
		if _, ok := set[sel{t: b.Type, v: b.Value}]; !ok {
			return false
		}
	}
	return true
}
