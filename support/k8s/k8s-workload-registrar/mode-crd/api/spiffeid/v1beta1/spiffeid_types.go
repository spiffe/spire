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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Selector struct {
	// Cluster is the k8s_psat cluster
	Cluster string `json:"cluster,omitempty"`
	// AgentNodeUid is the UID Of the node
	AgentNodeUid types.UID `json:"agent_node_uid,omitempty"`
	// Pod label name/value to match for this spiffe ID
	PodLabel map[string]string `json:"podLabel,omitempty"`
	// Pod name to match for this spiffe ID
	PodName string `json:"podName,omitempty"`
	// Pod UID to match for this spiffe ID
	PodUid types.UID `json:"podUid,omitempty"`
	// Namespace to match for this spiffe ID
	Namespace string `json:"namespace,omitempty"`
	// ServiceAccount to match for this spiffe ID
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// ContainerImage to match for this spiffe ID
	ContainerImage string `json:"containerImage,omitempty"`
	// ContainerName to match for this spiffe ID
	ContainerName string `json:"containerName,omitempty"`
	// NodeName to match for this spiffe ID
	NodeName string `json:"nodeName,omitempty"`
	// Arbitrary k8s selectors
	Arbitrary []string `json:"arbitrary,omitempty"`
}

// SpiffeIDSpec defines the desired state of SpiffeID
type SpiffeIDSpec struct {
	ParentId      string   `json:"parentId"`
	SpiffeId      string   `json:"spiffeId"`
	Selector      Selector `json:"selector"`
	Downstream    bool     `json:"downstream,omitempty"`
	DnsNames      []string `json:"dnsNames,omitempty"`
	FederatesWith []string `json:"federatesWith,omitempty"`
}

// SpiffeIDStatus defines the observed state of SpiffeID
type SpiffeIDStatus struct {
	EntryId *string `json:"entryId,omitempty"`
}

// SpiffeID is the Schema for the SpiffeIds API
type SpiffeID struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SpiffeIDSpec   `json:"spec,omitempty"`
	Status SpiffeIDStatus `json:"status,omitempty"`
}

// SpiffeIDList contains a list of SpiffeID
type SpiffeIDList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SpiffeID `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SpiffeID{}, &SpiffeIDList{})
}
