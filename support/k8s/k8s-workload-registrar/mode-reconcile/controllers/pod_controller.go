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
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlBuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type PodReconcilerMode int32

const (
	PodReconcilerModeServiceAccount PodReconcilerMode = iota
	PodReconcilerModeLabel
	PodReconcilerModeAnnotation
)

// PodReconciler reconciles a Pod object
type PodReconciler struct {
	client.Client
	TrustDomain        string
	Mode               PodReconcilerMode
	Value              string
	RootID             *spiretypes.SPIFFEID
	SpireClient        entryv1.EntryClient
	ClusterDNSZone     string
	AddPodDNSNames     bool
	DisabledNamespaces map[string]bool
}

type WorkloadSelectorSubType string

const (
	PodNamespaceSelector WorkloadSelectorSubType = "ns"
	PodNameSelector      WorkloadSelectorSubType = "pod-name"
)

const endpointSubsetAddressReferenceField string = ".subsets.addresses.targetRef.uid"

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

func (r *PodReconciler) shouldProcess(req ctrl.Request) bool {
	_, disabled := r.DisabledNamespaces[req.Namespace]
	return !disabled
}

func (r *PodReconciler) k8sWorkloadSelector(selector WorkloadSelectorSubType, value string) *spiretypes.Selector {
	return &spiretypes.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("%s:%s", selector, value),
	}
}

func (r *PodReconciler) selectorsToNamespacedName(selectors []*spiretypes.Selector) *types.NamespacedName {
	podNamespace := ""
	podName := ""
	for _, selector := range selectors {
		if selector.Type == "k8s" {
			splitted := strings.SplitN(selector.Value, ":", 2)
			if len(splitted) > 1 {
				switch WorkloadSelectorSubType(splitted[0]) {
				case PodNamespaceSelector:
					podNamespace = splitted[1]
				case PodNameSelector:
					podName = splitted[1]
				}
			}
		}
	}
	if podNamespace != "" && podName != "" {
		return &types.NamespacedName{
			Namespace: podNamespace,
			Name:      podName,
		}
	}
	return nil
}

func (r *PodReconciler) makeSpiffeID(obj ObjectWithMetadata) (*spiretypes.SPIFFEID, error) {
	return r.makeSpiffeIDForPod(obj.(*corev1.Pod))
}

func (r *PodReconciler) mungeIP(ip string) string {
	if strings.Contains(ip, ".") {
		// IPv4
		return strings.ReplaceAll(ip, ".", "-")
	}
	if strings.Contains(ip, ":") {
		// IPv6
		return strings.ReplaceAll(ip, ":", "-")
	}
	return ip
}

func (r *PodReconciler) addSearchPathNamesForPrefix(prefix string, namespace string, names map[string]bool) {
	// Kubernetes makes use of an unusual search path arrangement. We need to add names to allow all of the variants
	// the search path permits.
	// search $namespace.svc.$clusterDNSZone svc.$clusterDNSZone $clusterDNSZone ...
	names[fmt.Sprintf("%s.%s.svc.%s", prefix, namespace, r.ClusterDNSZone)] = true
	names[fmt.Sprintf("%s.%s.svc", prefix, namespace)] = true
	names[fmt.Sprintf("%s.%s", prefix, namespace)] = true
	names[prefix] = true
}

func (r *PodReconciler) isValidK8sDNSNameComponent(name string) bool {
	return name != "" && !strings.Contains(name, ".")
}

func (r *PodReconciler) getNamesForEndpoints(ctx context.Context, pod *corev1.Pod) ([]string, error) {
	names := make(map[string]bool)

	endpointsList := corev1.EndpointsList{}
	if err := r.List(ctx, &endpointsList, client.InNamespace(pod.Namespace), client.MatchingFields{endpointSubsetAddressReferenceField: pod.Name}); err != nil {
		return nil, err
	}

	for _, endpoints := range endpointsList.Items {
		endpoints := endpoints
		if !r.isValidK8sDNSNameComponent(endpoints.Name) || !r.isValidK8sDNSNameComponent(endpoints.Namespace) {
			continue
		}

		// Based on https://github.com/kubernetes/dns/blob/master/docs/specification.md
		// We cheat slightly and don't check the type of service (headless or not), we just add all possible names.

		// 2.3.1 and 2.4.1: <service>.<ns>.svc.<zone>
		r.addSearchPathNamesForPrefix(endpoints.Name, endpoints.Namespace, names)

		r.forEachPodEndpointAddress(&endpoints, func(address corev1.EndpointAddress) {
			if pod.Name == address.TargetRef.Name && pod.Namespace == address.TargetRef.Namespace {
				// 2.4.1: <hostname>.<service>.<ns>.svc.<zone>
				if r.isValidK8sDNSNameComponent(address.Hostname) {
					r.addSearchPathNamesForPrefix(fmt.Sprintf("%s.%s", address.Hostname, endpoints.Name), endpoints.Namespace, names)
				} else {
					// The spec leaves this case up to the implementation, so here we copy CoreDns...
					// CoreDNS has an endpoint_pod_names flag to switch between the following two options. We don't have that flag, so
					// we'll just add both pod name and IP based name (the CoreDns default) for now.
					r.addSearchPathNamesForPrefix(fmt.Sprintf("%s.%s", r.mungeIP(address.IP), endpoints.Name), endpoints.Namespace, names)
					if r.isValidK8sDNSNameComponent(address.TargetRef.Name) {
						r.addSearchPathNamesForPrefix(fmt.Sprintf("%s.%s", address.TargetRef.Name, endpoints.Name), endpoints.Namespace, names)
					}
				}
			}
		})
	}

	namesSlice := make([]string, 0, len(names))
	for name := range names {
		namesSlice = append(namesSlice, name)
	}

	// We sort the list to provide consistent results
	sort.Strings(namesSlice)

	return namesSlice, nil
}

func (r *PodReconciler) fillEntryForPod(ctx context.Context, entry *spiretypes.Entry, pod *corev1.Pod) (*spiretypes.Entry, error) {
	if !r.AddPodDNSNames {
		return entry, nil
	}

	if pod.Status.PodIP == "" {
		// Pod doesn't have an IP yet, so we can't generate names properly yet. We'll be called to reconcile it again
		// once it has an IP, at which point we'll fill the entry.
		return entry, nil
	}

	endpointNames, err := r.getNamesForEndpoints(ctx, pod)
	if err != nil {
		return nil, err
	}

	// We want to add DNS names for our pod. The order of these is important, as the first one will be used as the DN
	// for X509 SVIDs. This means we would like to use a completely unambiguous, unique, name for our pod first.
	// The docs at https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods claim that we should have:
	// `pod-ip-address.my-namespace.pod.cluster-domain.example` for all pods.
	// CoreDns does indeed have a pods option allowing resolution names in the form 1-2-3-4.ns.pod.cluster.local.
	// It's enabled only if the CoreDns pods option is set to a value other than `disabled.` We will include this as the
	// first dns name (regardless of configuration) as it makes for a stable choice of DN.
	//
	// The docs also claim we should have a `pod-ip-address.deployment-name.my-namespace.svc.cluster-domain.example`
	// name for daemonsets/deployments exposed by a service. This doesn't seem to be implemented by anything, and would
	// clash with naming used for endpoints! We follow CoreDns here, and don't attempt to add that format of name.

	entry.DnsNames = append([]string{
		fmt.Sprintf("%s.%s.pod.%s", r.mungeIP(pod.Status.PodIP), pod.Namespace, r.ClusterDNSZone),
		fmt.Sprintf("%s.%s.pod", r.mungeIP(pod.Status.PodIP), pod.Namespace), // k8s search path contains $clusterDNSZone
	}, endpointNames...)

	return entry, nil
}

func (r *PodReconciler) fillEntryForObject(ctx context.Context, entry *spiretypes.Entry, obj ObjectWithMetadata) (*spiretypes.Entry, error) {
	return r.fillEntryForPod(ctx, entry, obj.(*corev1.Pod))
}

func (r *PodReconciler) makeSpiffeIDForPod(pod *corev1.Pod) (*spiretypes.SPIFFEID, error) {
	switch r.Mode {
	case PodReconcilerModeServiceAccount:
		return r.makeID("ns", pod.Namespace, "sa", pod.Spec.ServiceAccountName)
	case PodReconcilerModeLabel:
		if val, ok := pod.GetLabels()[r.Value]; ok {
			return r.makeID(val)
		}
	case PodReconcilerModeAnnotation:
		if val, ok := pod.GetAnnotations()[r.Value]; ok {
			return r.makeID(val)
		}
	default:
		return nil, fmt.Errorf("unhandled pod reconciler mode: %q", r.Mode)
	}

	// Pod does not have the requisite label or annotation so don't return
	// a SPIFFE ID.
	return nil, nil
}

func (r *PodReconciler) makeID(segments ...string) (*spiretypes.SPIFFEID, error) {
	path, err := spiffeid.JoinPathSegments(segments...)
	if err != nil {
		return nil, err
	}
	return &spiretypes.SPIFFEID{
		TrustDomain: r.TrustDomain,
		Path:        path,
	}, nil
}

func (r *PodReconciler) makeParentIDForPod(pod *corev1.Pod) (*spiretypes.SPIFFEID, error) {
	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		return nil, nil
	}
	path, err := spiffeid.JoinPathSegments(nodeName)
	if err != nil {
		return nil, err
	}
	return &spiretypes.SPIFFEID{
		TrustDomain: r.RootID.TrustDomain,
		Path:        r.RootID.Path + path,
	}, nil
}

func (r *PodReconciler) makeParentID(obj ObjectWithMetadata) (*spiretypes.SPIFFEID, error) {
	return r.makeParentIDForPod(obj.(*corev1.Pod))
}

func (r *PodReconciler) getSelectors(namespacedName types.NamespacedName) []*spiretypes.Selector {
	return []*spiretypes.Selector{
		r.k8sWorkloadSelector(PodNamespaceSelector, namespacedName.Namespace),
		r.k8sWorkloadSelector(PodNameSelector, namespacedName.Name),
	}
}

func (r *PodReconciler) getAllEntries(ctx context.Context) ([]*spiretypes.Entry, error) {
	// Parents for an entry are not guaranteed to exist. This means we cannot do a search by parent ID
	// starting from rootId to find nodes, then find pods parented to those nodes. Instead we have to
	// get the full set of entries, and scan them for parentIds that match the format we use for a
	// node's ID. This is probably faster anyway: most entries in spire are going to be for pods, so we
	// may as well just load the whole lot.
	// TODO: Move to some kind of poll and cache and notify system, so multiple controllers don't have to poll.
	allEntries, err := listEntries(ctx, r.SpireClient, nil)
	if err != nil {
		return nil, err
	}
	var allPodEntries []*spiretypes.Entry
	nodeIDPrefix := spiretypes.SPIFFEID{
		TrustDomain: r.RootID.TrustDomain,
		Path:        r.RootID.Path,
	}

	for _, maybePodEntry := range allEntries {
		if spiffeIDHasPrefix(maybePodEntry.ParentId, &nodeIDPrefix) {
			allPodEntries = append(allPodEntries, maybePodEntry)
		}
	}
	return allPodEntries, nil
}

func (r *PodReconciler) getObject() ObjectWithMetadata {
	return &corev1.Pod{}
}

func (r *PodReconciler) forEachPodSubsetEndpointAddress(subset corev1.EndpointSubset, action func(corev1.EndpointAddress)) {
	for _, address := range subset.Addresses {
		if address.TargetRef != nil && address.TargetRef.Kind == "Pod" {
			action(address)
		}
	}
	for _, address := range subset.NotReadyAddresses {
		if address.TargetRef != nil && address.TargetRef.Kind == "Pod" {
			action(address)
		}
	}
}

func (r *PodReconciler) forEachPodEndpointAddress(endpoints *corev1.Endpoints, thing func(corev1.EndpointAddress)) {
	for _, subset := range endpoints.Subsets {
		r.forEachPodSubsetEndpointAddress(subset, thing)
	}
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager, builder *ctrlBuilder.Builder) error {
	if r.AddPodDNSNames {
		builder.Watches(&source.Kind{Type: &corev1.Endpoints{}}, handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
			endpoints := a.(*corev1.Endpoints)

			var requests []reconcile.Request
			r.forEachPodEndpointAddress(endpoints, func(address corev1.EndpointAddress) {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: address.TargetRef.Namespace,
						Name:      address.TargetRef.Name,
					},
				})
			})

			return requests
		}))

		return mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Endpoints{}, endpointSubsetAddressReferenceField, func(rawObj client.Object) []string {
			endpoints := rawObj.(*corev1.Endpoints)

			var podNames []string

			r.forEachPodEndpointAddress(endpoints, func(address corev1.EndpointAddress) {
				podNames = append(podNames, address.TargetRef.Name)
			})

			return podNames
		})
	}
	return nil
}

func NewPodReconciler(client client.Client, log logr.Logger, scheme *runtime.Scheme, trustDomain string, rootID *spiretypes.SPIFFEID, spireClient entryv1.EntryClient, mode PodReconcilerMode, value string, clusterDNSZone string, addPodDNSNames bool, disabledNamespaces []string) *BaseReconciler {
	disabledNamespacesMap := make(map[string]bool, len(disabledNamespaces))
	for _, ns := range disabledNamespaces {
		disabledNamespacesMap[ns] = true
	}

	return &BaseReconciler{
		Client:      client,
		Scheme:      scheme,
		RootID:      rootID,
		SpireClient: spireClient,
		Log:         log,
		ObjectReconciler: &PodReconciler{
			Client:             client,
			RootID:             rootID,
			SpireClient:        spireClient,
			TrustDomain:        trustDomain,
			Mode:               mode,
			Value:              value,
			ClusterDNSZone:     clusterDNSZone,
			AddPodDNSNames:     addPodDNSNames,
			DisabledNamespaces: disabledNamespacesMap,
		},
	}
}
