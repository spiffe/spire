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
	"fmt"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// TypesSelector converts the selectors from the CRD to the types.Selector
// format needed to create the entry on the SPIRE server
func (s *SpiffeID) TypesSelector() []*types.Selector {
	commonSelector := make([]*types.Selector, 0, len(s.Spec.Selector.PodLabel))
	if len(s.Spec.Selector.Cluster) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s_psat",
			Value: fmt.Sprintf("cluster:%s", s.Spec.Selector.Cluster),
		})
	}
	if len(s.Spec.Selector.AgentNodeUid) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s_psat",
			Value: fmt.Sprintf("agent_node_uid:%s", s.Spec.Selector.AgentNodeUid),
		})
	}
	for k, v := range s.Spec.Selector.PodLabel {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("pod-label:%s:%s", k, v),
		})
	}
	if len(s.Spec.Selector.PodName) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("pod-name:%s", s.Spec.Selector.PodName),
		})
	}
	if len(s.Spec.Selector.PodUid) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("pod-uid:%s", s.Spec.Selector.PodUid),
		})
	}
	if len(s.Spec.Selector.Namespace) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("ns:%s", s.Spec.Selector.Namespace),
		})
	}
	if len(s.Spec.Selector.ServiceAccount) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("sa:%s", s.Spec.Selector.ServiceAccount),
		})
	}
	if len(s.Spec.Selector.ContainerName) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("container-name:%s", s.Spec.Selector.ContainerName),
		})
	}
	if len(s.Spec.Selector.ContainerImage) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("container-image:%s", s.Spec.Selector.ContainerImage),
		})
	}
	if len(s.Spec.Selector.NodeName) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: fmt.Sprintf("node-name:%s", s.Spec.Selector.NodeName),
		})
	}
	if len(s.Spec.Selector.SigstoreValidationPassed) > 0 {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: "sigstore-validation:passed",
		})
	}
	for _, v := range s.Spec.Selector.Arbitrary {
		commonSelector = append(commonSelector, &types.Selector{
			Type:  "k8s",
			Value: v,
		})
	}

	return commonSelector
}
