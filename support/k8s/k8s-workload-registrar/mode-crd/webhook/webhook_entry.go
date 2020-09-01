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

package webhook

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type EntryConfig struct {
	Clientset          kubernetes.Interface
	Cluster            string
	Ctx                context.Context
	E                  entryv1.EntryClient
	Log                logrus.FieldLogger
	Name               string
	Namespace          string
	NodeName           string
	TrustDomain        string
	UID                types.UID
	WebhookServiceName string
}

type Entry struct {
	SpiffeID *spiretypes.SPIFFEID
	c        EntryConfig
	entryID  string
}

func NewEntry(config EntryConfig) *Entry {
	return &Entry{
		c: config,
	}
}

// CreateEntry creates the registration entry for the webhook
func (e *Entry) CreateEntry() error {
	webhookParentID, err := e.webhookParentID()
	if err != nil {
		return err
	}
	resp, err := e.c.E.BatchCreateEntry(e.c.Ctx, &entryv1.BatchCreateEntryRequest{
		Entries: []*spiretypes.Entry{
			{
				ParentId: webhookParentID,
				SpiffeId: e.webhookSpiffeID(),
				Selectors: []*spiretypes.Selector{
					{Type: "k8s", Value: fmt.Sprintf("pod-name:%s", e.c.Name)},
					{Type: "k8s", Value: fmt.Sprintf("pod-uid:%s", e.c.UID)},
					{Type: "k8s", Value: fmt.Sprintf("ns:%s", e.c.Namespace)},
				},
				DnsNames: []string{
					e.c.WebhookServiceName + "." + e.c.Namespace + ".svc",
				},
			},
		},
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

	err = errorFromStatus(resp.Results[0].Status)
	switch status.Code(err) {
	case codes.AlreadyExists:
		fallthrough
	case codes.OK:
		e.entryID = resp.Results[0].Entry.Id
		e.SpiffeID = resp.Results[0].Entry.SpiffeId
		return nil
	default:
		return err
	}
}

// CleanupStaleEntries clean up any entries from previous deployments
// For example if the k8s-workload-registrar was force deleted and did not get
// a chance to delete its webhook entry
func (e *Entry) CleanupStaleEntries() error {
	list, err := e.getWebhookEntries()
	if err != nil {
		return err
	}

	for _, entry := range list.Entries {
		namespacedName, uid := selectorsToNamespacedNameAndUID(entry.Selectors)
		if namespacedName == nil || (namespacedName.Name == e.c.Name &&
			namespacedName.Namespace == e.c.Namespace &&
			uid == e.c.UID) {
			// Skip lookup for entry beloging to this pod
			continue
		}
		pod, err := e.getPod(namespacedName)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				// Resource has been deleted
				if err = e.deleteEntry(entry.Id); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if pod.UID != uid {
			if err = e.deleteEntry(entry.Id); err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteEntry deletes the registration entry for the webhook
func (e *Entry) DeleteEntry() error {
	if e.entryID != "" {
		if err := e.deleteEntry(e.entryID); err != nil {
			return err
		}
	}
	e.entryID = ""
	e.SpiffeID = nil
	return nil
}

// deleteEntry deletes an entry by ID
func (e *Entry) deleteEntry(entryID string) error {
	resp, err := e.c.E.BatchDeleteEntry(e.c.Ctx, &entryv1.BatchDeleteEntryRequest{Ids: []string{entryID}})
	if err != nil {
		return err
	}

	// These checks are purely defensive
	switch {
	case len(resp.Results) > 1:
		return errors.New("batch delete response has too many results")
	case len(resp.Results) < 1:
		return errors.New("batch delete response missing result")
	}

	err = errorFromStatus(resp.Results[0].Status)
	switch status.Code(err) {
	case codes.OK, codes.NotFound:
		return nil
	default:
		return err
	}
}

// webhookParentID creates the SPIFFEID for the PSAT parent used by the webhook
func (e *Entry) webhookParentID() (*spiretypes.SPIFFEID, error) {
	nodeUID, err := e.nodeNameToUID()
	if err != nil {
		return nil, err
	}
	return &spiretypes.SPIFFEID{
		TrustDomain: e.c.TrustDomain,
		Path:        fmt.Sprintf("spire/agent/k8s_psat/%s/%s", e.c.Cluster, nodeUID),
	}, nil
}

// webhookSpiffeID creates the SPIFFEID for the webhook
func (e *Entry) webhookSpiffeID() *spiretypes.SPIFFEID {
	return &spiretypes.SPIFFEID{
		TrustDomain: e.c.TrustDomain,
		Path:        fmt.Sprintf("/k8s-workload-registrar/%s/webhook", e.c.Cluster),
	}
}

// nodeNameToUID converts an node name to a corresponding UID by calling the Kubernetes API
func (e *Entry) nodeNameToUID() (types.UID, error) {
	node, err := e.c.Clientset.CoreV1().Nodes().Get(e.c.Ctx, e.c.NodeName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return node.UID, nil
}

// getWebhookEntries gets a list of the all the entries for the webhook
func (e *Entry) getWebhookEntries() (*entryv1.ListEntriesResponse, error) {
	return e.c.E.ListEntries(e.c.Ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			BySpiffeId: e.webhookSpiffeID(),
		},
	})
}

func (e *Entry) getPod(namespacedName *types.NamespacedName) (*corev1.Pod, error) {
	return e.c.Clientset.CoreV1().Pods(namespacedName.Namespace).Get(e.c.Ctx, namespacedName.Name, metav1.GetOptions{})
}

func selectorsToNamespacedNameAndUID(selectors []*spiretypes.Selector) (*types.NamespacedName, types.UID) {
	var podUID types.UID
	podNamespace := ""
	podName := ""
	for _, selector := range selectors {
		if selector.Type == "k8s" {
			splitted := strings.SplitN(selector.Value, ":", 2)
			if len(splitted) > 1 {
				switch splitted[0] {
				case "ns":
					podNamespace = splitted[1]
				case "pod-name":
					podName = splitted[1]
				case "pod-uid":
					podUID = types.UID(splitted[1])
				}
			}
		}
	}
	if podNamespace != "" && podName != "" && podUID != "" {
		return &types.NamespacedName{
			Namespace: podNamespace,
			Name:      podName,
		}, podUID
	}
	return nil, ""
}
