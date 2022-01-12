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
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/federation"
	"github.com/zeebo/errs"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlBuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type ObjectReconciler interface {
	// Returns an instance of the object type to be reconciled
	getObject() ObjectWithMetadata
	// Return a SPIFFE ID to register for the object, or nil if no registration should be created
	makeSpiffeID(ObjectWithMetadata) (*spiretypes.SPIFFEID, error)
	// Return the SPIFFE ID to be used as a parent for the object, or "" if no registration should be created
	makeParentID(ObjectWithMetadata) (*spiretypes.SPIFFEID, error)
	// Return all registration entries owned by the controller
	getAllEntries(context.Context) ([]*spiretypes.Entry, error)
	// Return the selectors that should be used for a name
	// For example, given a name of "foo" a reconciler might return a `k8s_psat:node-name:foo` selector.
	getSelectors(types.NamespacedName) []*spiretypes.Selector
	// Parse the selectors to extract a namespaced name.
	// For example, a list containing a `k8s_psat:node-name:foo` selector might result in a NamespacedName of "foo"
	selectorsToNamespacedName([]*spiretypes.Selector) *types.NamespacedName
	// Fill additional fields on a spire registration entry for a k8s object
	fillEntryForObject(context.Context, *spiretypes.Entry, ObjectWithMetadata) (*spiretypes.Entry, error)
	// Return true if we should continue to reconcile this request, false to skip
	shouldProcess(req ctrl.Request) bool
	// Perform any additional manager setup required
	SetupWithManager(ctrl.Manager, *ctrlBuilder.Builder) error
}

// BaseReconciler reconciles... something
// This implements the polling solution documented here: https://docs.google.com/document/d/19BDGrCRh9rjj09to1D2hlDJZXRuwOlY4hL5c4n7_bVc
// By using name+namespace as a key we are able to maintain a 1:1 mapping from k8s resources to SPIRE registration entries.
// The base reconciler implements the common functionality required to maintain that mapping, including a watcher on the
// given resource, and a watcher which receives notifications from polling the SPIRE Entry API.
type BaseReconciler struct {
	client.Client
	ObjectReconciler
	Scheme      *runtime.Scheme
	RootID      *spiretypes.SPIFFEID
	SpireClient entryv1.EntryClient
	Log         logr.Logger
}

type RuntimeObject = runtime.Object
type V1Object = v1.Object

type ObjectWithMetadata interface {
	RuntimeObject
	V1Object
}

func (r *BaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if !r.shouldProcess(req) {
		return ctrl.Result{}, nil
	}
	reqLogger := r.Log.WithValues("request", req.NamespacedName)

	obj := r.getObject()
	err := r.Get(ctx, req.NamespacedName, obj)
	if err != nil && !errors.IsNotFound(err) {
		reqLogger.Error(err, "Unable to fetch resource")
		return ctrl.Result{}, err
	}

	isDeleted := errors.IsNotFound(err) || !obj.GetDeletionTimestamp().IsZero()

	matchedEntries, err := r.getMatchingEntries(ctx, reqLogger, req.NamespacedName)
	if err != nil {
		return ctrl.Result{}, err
	}
	if isDeleted {
		reqLogger.V(1).Info("Deleting entries for deleted object", "count", len(matchedEntries))
		err := r.deleteAllEntries(ctx, reqLogger, matchedEntries)
		return ctrl.Result{}, err
	}

	myEntry, err := r.makeEntryForObject(ctx, obj)
	if err != nil {
		reqLogger.Error(err, "Failed to populate spire entry for object")
		return ctrl.Result{}, err
	}

	if myEntry == nil {
		// Object does not need an entry.
		if len(matchedEntries) == 0 {
			return ctrl.Result{}, nil
		}
		// Object had entries before, but doesn't need them now. Delete them.
		reqLogger.V(1).Info("Deleting entries for object that no longer needs an ID", "count", len(matchedEntries))
		err := r.deleteAllEntries(ctx, reqLogger, matchedEntries)
		return ctrl.Result{}, err
	}

	var myEntryID string

	if len(matchedEntries) == 0 {
		createdEntry, preExisting, err := r.createEntry(ctx, myEntry)
		if err != nil {
			reqLogger.Error(err, "Failed to create or update spire entry")
			return ctrl.Result{}, err
		}
		if preExisting {
			// This can only happen if multiple controllers are running, since any entry returned here should also have
			// been in matchedEntries!
			reqLogger.V(1).Info("Found existing identical spire entry", "entry", createdEntry)
		} else {
			reqLogger.Info("Created new spire entry", "entry", createdEntry)
		}
		myEntryID = createdEntry.Id
	} else {
		// matchedEntries contains all entries created by this controller (based on parent ID) whose selectors match the object
		// being reconciled. Typically there will be only one. One of these existing entries might already be just right, but
		// if not, we choose one and update it (e.g. change spiffe ID or dns names, avoiding causing a period where the workload
		// has no SVID.) We then delete all the others.
		requiresUpdate := true
		for _, foundEntry := range matchedEntries {
			if r.entryEquals(myEntry, foundEntry) {
				reqLogger.V(1).Info("Found existing identical enough spire entry", "entry", foundEntry.Id)
				myEntryID = foundEntry.Id
				requiresUpdate = false
				break
			}
		}
		if requiresUpdate {
			reqLogger.V(1).Info("Updating existing spire entry to match desired state", "entry", matchedEntries[0].Id)
			// It's important that if multiple instances are running they all pick the same entry here, otherwise
			// we could have two instances of the registrar delete each others changes. This can only happen if both are
			// also working off an up to date cache (otherwise the lagging one will pick up the other change later and correct
			// the mistake.) If that happens then as long as they'd both pick to keep the same entry from the list, we can
			// guarantee they wont end up deleting all the entries and not noticing: so we'll pick the entry with the
			// "lowest" Entry ID.
			myEntryID = matchedEntries[0].Id
			for _, foundEntry := range matchedEntries {
				if foundEntry.Id < myEntryID {
					myEntryID = foundEntry.Id
				}
			}

			// myEntry is the entry we'd have created if we weren't updating an existing one, by giving it the chosen EntryId
			// we can use it to update the existing entry to perfectly match what we want.
			myEntry.Id = myEntryID
			err := r.updateEntry(ctx, myEntry)
			if err != nil {
				reqLogger.Error(err, "Failed to update existing spire entry", "existingEntry", matchedEntries[0].Id)
				return ctrl.Result{}, err
			}
		}
	}

	err = r.deleteAllEntriesExcept(ctx, reqLogger, matchedEntries, myEntryID)

	return ctrl.Result{}, err
}

func (r *BaseReconciler) updateEntry(ctx context.Context, updatedEntry *spiretypes.Entry) error {
	batchUpdateResponse, err := r.SpireClient.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{
		Entries: []*spiretypes.Entry{updatedEntry},
	})
	if err == nil {
		err = status.Error(codes.Code(batchUpdateResponse.Results[0].Status.Code), batchUpdateResponse.Results[0].Status.Message)
	}
	return err
}

func (r *BaseReconciler) createEntry(ctx context.Context, entryToCreate *spiretypes.Entry) (*spiretypes.Entry, bool, error) {
	createEntryResponse, err := r.SpireClient.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{Entries: []*spiretypes.Entry{entryToCreate}})
	if err != nil {
		return nil, false, err
	}
	result := createEntryResponse.Results[0]
	statusCode := codes.Code(result.Status.Code)
	resultEntry := result.Entry
	if resultEntry == nil {
		return nil, false, status.Error(statusCode, result.Status.Message)
	}
	preexisting := false
	if statusCode == codes.AlreadyExists {
		preexisting = true
	}
	return resultEntry, preexisting, nil
}

func (r *BaseReconciler) makeEntryForObject(ctx context.Context, obj ObjectWithMetadata) (*spiretypes.Entry, error) {
	spiffeID, err := r.makeSpiffeID(obj)
	if err != nil {
		return nil, err
	}
	parentID, err := r.makeParentID(obj)
	if err != nil {
		return nil, err
	}

	federationDomains := federation.GetFederationDomains(obj)

	if spiffeID == nil || parentID == nil {
		return nil, nil
	}

	newEntry := spiretypes.Entry{
		Selectors: r.getSelectors(types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		}),
		ParentId:      parentID,
		SpiffeId:      spiffeID,
		FederatesWith: federationDomains,
	}
	return r.fillEntryForObject(ctx, &newEntry, obj)
}

func (r *BaseReconciler) entryEquals(myEntry *spiretypes.Entry, in *spiretypes.Entry) bool {
	// We consider an entry to be "equal" if the fields we can update match.
	// This doesn't include selectors, since those can never be updated. The caller is expected to only pass us
	// entries whose selectors would match the same k8s resource.
	if !spiffeIDsEqual(in.SpiffeId, myEntry.SpiffeId) {
		return false
	}
	if !spiffeIDsEqual(in.ParentId, myEntry.ParentId) {
		return false
	}
	if len(in.DnsNames) != len(myEntry.DnsNames) {
		return false
	}
	inDNSNames := make(map[string]bool, len(in.DnsNames))
	for _, dnsName := range in.DnsNames {
		inDNSNames[dnsName] = true
	}
	for _, dnsName := range myEntry.DnsNames {
		if !inDNSNames[dnsName] {
			return false
		}
	}
	return true
}

func (r *BaseReconciler) deleteAllEntries(ctx context.Context, reqLogger logr.Logger, entries []*spiretypes.Entry) error {
	entryIDs := make([]string, 0, len(entries))

	for _, entryToDelete := range entries {
		entryIDs = append(entryIDs, entryToDelete.Id)
	}
	return r.deleteEntriesByID(ctx, reqLogger, entryIDs)
}

func (r *BaseReconciler) deleteAllEntriesExcept(ctx context.Context, reqLogger logr.Logger, entries []*spiretypes.Entry, exceptEntryID string) error {
	entryIDs := make([]string, 0, len(entries))

	for _, entryToDelete := range entries {
		if entryToDelete.Id != exceptEntryID {
			entryIDs = append(entryIDs, entryToDelete.Id)
		}
	}
	return r.deleteEntriesByID(ctx, reqLogger, entryIDs)
}

func (r *BaseReconciler) deleteEntriesByID(ctx context.Context, reqLogger logr.Logger, entryIDs []string) error {
	errorGroup := errs.Group{}

	batchDeleteEntryRequest := &entryv1.BatchDeleteEntryRequest{Ids: entryIDs}

	results, err := r.SpireClient.BatchDeleteEntry(ctx, batchDeleteEntryRequest)
	if err != nil {
		return err
	}
	for _, result := range results.Results {
		err := status.Error(codes.Code(result.Status.Code), result.Status.Message)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				reqLogger.Info("Entry had already been deleted", "entryID", result.Id)
			} else {
				errorGroup.Add(err)
				reqLogger.Error(err, "Failed to delete entry", "entryID", result.Id)
			}
		} else {
			reqLogger.Info("Deleted entry", "entryID", result.Id)
		}
	}
	return errorGroup.Err()
}

func (r *BaseReconciler) getMatchingEntries(ctx context.Context, reqLogger logr.Logger, namespacedName types.NamespacedName) ([]*spiretypes.Entry, error) {
	entries, err := listEntries(ctx, r.SpireClient, &entryv1.ListEntriesRequest_Filter{
		BySelectors: &spiretypes.SelectorMatch{
			Selectors: r.getSelectors(namespacedName),
			Match:     spiretypes.SelectorMatch_MATCH_EXACT,
		},
	})
	if err != nil {
		reqLogger.Error(err, "Failed to load entries")
		return nil, err
	}
	var result []*spiretypes.Entry
	for _, foundEntry := range entries {
		if spiffeIDHasPrefix(foundEntry.ParentId, r.RootID) || spiffeIDHasPrefix(foundEntry.SpiffeId, r.RootID) {
			result = append(result, foundEntry)
		}
	}
	return result, nil
}

func (r *BaseReconciler) doPollSpire(ctx context.Context, log logr.Logger) []event.GenericEvent {
	log.Info("Syncing spire entries")
	start := time.Now()

	entries, err := r.getAllEntries(ctx)
	if err != nil {
		log.Error(err, "Unable to fetch entries")
		return nil
	}

	var events []event.GenericEvent
	seen := make(map[string]bool)

	for _, foundEntry := range entries {
		if namespacedName := r.selectorsToNamespacedName(foundEntry.Selectors); namespacedName != nil {
			reconcile := false
			if seen[namespacedName.String()] {
				// More than one entry found
				reconcile = true
			} else {
				obj := r.getObject()
				err := r.Get(ctx, *namespacedName, obj)
				if err != nil {
					if errors.IsNotFound(err) {
						// resource has been deleted
						reconcile = true
					} else {
						log.Error(err, "Unable to fetch resource", "name", namespacedName)
					}
				} else {
					myEntry, err := r.makeEntryForObject(ctx, obj)
					if err != nil {
						log.Error(err, "Unable to populate spire entry for object", "name", namespacedName)
					}
					if myEntry == nil || !r.entryEquals(myEntry, foundEntry) {
						// No longer needs an entry or it doesn't match the expected entry
						// This can trigger for various reasons, but it's OK to accidentally queue more than entirely necessary
						reconcile = true
					}
				}
			}
			seen[namespacedName.String()] = true
			if reconcile {
				log.V(1).Info("Triggering reconciliation for resource", "name", namespacedName)
				events = append(events, event.GenericEvent{Object: &corev1.Event{
					ObjectMeta: v1.ObjectMeta{
						Name:      namespacedName.Name,
						Namespace: namespacedName.Namespace,
					},
				}})
			}
		}
	}
	log.Info("Synced spire entries", "took", time.Since(start), "found", len(entries), "queued", len(events))
	return events
}

func (r *BaseReconciler) pollSpire(ctx context.Context, out chan event.GenericEvent) error {
	log := r.Log
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
			for _, pollEvent := range r.doPollSpire(ctx, log) {
				select {
				case out <- pollEvent:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

type SpirePoller struct {
	r   *BaseReconciler
	out chan event.GenericEvent
}

// Start implements Runnable
func (p *SpirePoller) Start(ctx context.Context) error {
	return p.r.pollSpire(ctx, p.out)
}

func (r *BaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	events := make(chan event.GenericEvent)

	if err := mgr.Add(&SpirePoller{
		r:   r,
		out: events,
	}); err != nil {
		return err
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		For(r.getObject()).
		Watches(&source.Channel{Source: events}, &handler.EnqueueRequestForObject{})

	if err := r.ObjectReconciler.SetupWithManager(mgr, builder); err != nil {
		return err
	}

	return builder.Complete(r)
}
