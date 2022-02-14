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
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/protobuf/proto"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlBuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	RootID      *spiretypes.SPIFFEID
	SpireClient entryv1.EntryClient
	Cluster     string
	ServerID    *spiretypes.SPIFFEID
}

type NodeSelectorSubType string

const (
	NodeNameSelector NodeSelectorSubType = "agent_node_name"
	ClusterSelector  NodeSelectorSubType = "cluster"
)

// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

func (r *NodeReconciler) shouldProcess(_ ctrl.Request) bool {
	return true
}

func (r *NodeReconciler) makeSpiffeID(obj ObjectWithMetadata) (*spiretypes.SPIFFEID, error) {
	path, err := spiffeid.JoinPathSegments(obj.GetName())
	if err != nil {
		return nil, err
	}
	return &spiretypes.SPIFFEID{
		TrustDomain: r.RootID.TrustDomain,
		Path:        r.RootID.Path + path,
	}, nil
}

func (r *NodeReconciler) makeParentID(_ ObjectWithMetadata) (*spiretypes.SPIFFEID, error) {
	return cloneSPIFFEID(r.ServerID), nil
}

func (r *NodeReconciler) getSelectors(namespacedName types.NamespacedName) []*spiretypes.Selector {
	return []*spiretypes.Selector{
		r.k8sNodeSelector(NodeNameSelector, namespacedName.Name),
		r.k8sNodeSelector(ClusterSelector, r.Cluster),
	}
}

func (r *NodeReconciler) getAllEntries(ctx context.Context) ([]*spiretypes.Entry, error) {
	// TODO: Move to some kind of poll and cache and notify system, so multiple controllers don't have to poll.
	serverChildEntries, err := listEntries(ctx, r.SpireClient, &entryv1.ListEntriesRequest_Filter{
		ByParentId: r.ServerID,
	})
	if err != nil {
		return nil, err
	}
	var allNodeEntries []*spiretypes.Entry

	for _, maybeNodeEntry := range serverChildEntries {
		if spiffeIDHasPrefix(maybeNodeEntry.SpiffeId, r.RootID) {
			allNodeEntries = append(allNodeEntries, maybeNodeEntry)
		}
	}
	return allNodeEntries, nil
}

func (r *NodeReconciler) getObject() ObjectWithMetadata {
	return &corev1.Node{}
}

func (r *NodeReconciler) k8sNodeSelector(selector NodeSelectorSubType, value string) *spiretypes.Selector {
	return &spiretypes.Selector{
		Type:  "k8s_psat",
		Value: fmt.Sprintf("%s:%s", selector, value),
	}
}

func (r *NodeReconciler) selectorsToNamespacedName(selectors []*spiretypes.Selector) *types.NamespacedName {
	nodeName := ""
	for _, selector := range selectors {
		if selector.Type == "k8s_psat" {
			splitted := strings.SplitN(selector.Value, ":", 2)
			if len(splitted) > 1 && NodeSelectorSubType(splitted[0]) == NodeNameSelector {
				nodeName = splitted[1]
				break
			}
		}
	}
	if nodeName != "" {
		return &types.NamespacedName{
			Namespace: "",
			Name:      nodeName,
		}
	}
	return nil
}

func (r *NodeReconciler) fillEntryForObject(_ context.Context, entry *spiretypes.Entry, _ ObjectWithMetadata) (*spiretypes.Entry, error) {
	// We don't add anything additional to entries for Nodes, so just pass back the base entry.
	return entry, nil
}

func (r *NodeReconciler) SetupWithManager(_ ctrl.Manager, _ *ctrlBuilder.Builder) error {
	// This controller doesn't need to do any additional setup
	return nil
}

func NewNodeReconciler(client client.Client, log logr.Logger, scheme *runtime.Scheme, serverID *spiretypes.SPIFFEID, cluster string, rootID *spiretypes.SPIFFEID, spireClient entryv1.EntryClient) *BaseReconciler {
	return &BaseReconciler{
		Client:      client,
		Scheme:      scheme,
		RootID:      rootID,
		SpireClient: spireClient,
		Log:         log,
		ObjectReconciler: &NodeReconciler{
			RootID:      rootID,
			SpireClient: spireClient,
			Cluster:     cluster,
			ServerID:    serverID,
		},
	}
}

func cloneSPIFFEID(spiffeID *spiretypes.SPIFFEID) *spiretypes.SPIFFEID {
	return proto.Clone(spiffeID).(*spiretypes.SPIFFEID)
}
