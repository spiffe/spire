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
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/test/fakes/fakeentryclient"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	Cluster            = "test-cluster"
	TrustDomain        = "example.org"
	Name               = "test-pod"
	Namespace          = "test"
	NodeName           = "test-node"
	UID                = "1234"
	WebhookServiceName = "k8s-workload-registrar"
)

func TestInvalidSpiffeID(t *testing.T) {
	ctx, cancel, clientset, entryClient := setupTest(t)
	defer cancel()

	webhookEntry := NewEntry(EntryConfig{
		Clientset:          clientset,
		Ctx:                ctx,
		E:                  entryClient,
		Log:                plugin.NullLogger(),
		Namespace:          Namespace,
		NodeName:           NodeName,
		TrustDomain:        TrustDomain,
		UID:                UID,
		WebhookServiceName: WebhookServiceName,
	})
	require.NotNil(t, webhookEntry)
	err := webhookEntry.CreateEntry()
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = failed to convert entry: parent ID is malformed: path cannot contain empty, '.', or '..' segments")
}

func TestCreateAndDeleteEntry(t *testing.T) {
	ctx, cancel, clientset, entryClient := setupTest(t)
	defer cancel()

	webhookEntry := NewEntry(EntryConfig{
		Clientset:          clientset,
		Cluster:            Cluster,
		Ctx:                ctx,
		E:                  entryClient,
		Log:                plugin.NullLogger(),
		Name:               Name,
		Namespace:          Namespace,
		NodeName:           NodeName,
		TrustDomain:        TrustDomain,
		UID:                UID,
		WebhookServiceName: WebhookServiceName,
	})
	require.NotNil(t, webhookEntry)
	err := webhookEntry.CreateEntry()
	require.NoError(t, err)
	require.Equal(t, webhookEntry.webhookSpiffeID(), webhookEntry.SpiffeID)
	require.NotEqual(t, "", webhookEntry.entryID)

	list, err := webhookEntry.getWebhookEntries()
	require.NoError(t, err)
	require.Equal(t, 1, len(list.Entries))
	require.Equal(t, webhookEntry.entryID, list.Entries[0].Id)
	require.Equal(t, webhookEntry.SpiffeID, list.Entries[0].SpiffeId)

	err = webhookEntry.DeleteEntry()
	require.NoError(t, err)
	require.Equal(t, "", webhookEntry.entryID)
	list, err = webhookEntry.getWebhookEntries()
	require.NoError(t, err)
	require.Equal(t, 0, len(list.Entries))
}

func TestCleanupUpStaleEntries(t *testing.T) {
	ctx, cancel, clientset, entryClient := setupTest(t)
	defer cancel()

	// Create pod and webhook entry
	createPod(ctx, t, clientset, Name, Namespace, UID)
	webhookEntry := NewEntry(EntryConfig{
		Clientset:          clientset,
		Cluster:            Cluster,
		Ctx:                ctx,
		E:                  entryClient,
		Log:                plugin.NullLogger(),
		Name:               Name,
		Namespace:          Namespace,
		NodeName:           NodeName,
		TrustDomain:        TrustDomain,
		UID:                UID,
		WebhookServiceName: WebhookServiceName,
	})
	require.NotNil(t, webhookEntry)
	err := webhookEntry.CreateEntry()
	require.NoError(t, err)

	// Delete pod
	deletePod(ctx, t, clientset, Name, Namespace)

	// Create new pod with same namespace/name but different UID, and webhook entry
	createPod(ctx, t, clientset, Name, Namespace, "5678")
	webhookEntry = NewEntry(EntryConfig{
		Clientset:          clientset,
		Cluster:            Cluster,
		Ctx:                ctx,
		E:                  entryClient,
		Log:                plugin.NullLogger(),
		Name:               Name,
		Namespace:          Namespace,
		NodeName:           NodeName,
		TrustDomain:        TrustDomain,
		UID:                "5678",
		WebhookServiceName: WebhookServiceName,
	})
	require.NotNil(t, webhookEntry)
	err = webhookEntry.CreateEntry()
	require.NoError(t, err)

	// We should have 2 entries at this point
	list, err := webhookEntry.getWebhookEntries()
	require.NoError(t, err)
	require.Equal(t, 2, len(list.Entries))

	// Cleanup the stale entry and ensure we have one 1 left
	err = webhookEntry.CleanupStaleEntries()
	require.NoError(t, err)
	list, err = webhookEntry.getWebhookEntries()
	require.NoError(t, err)
	require.Equal(t, 1, len(list.Entries))
	require.Equal(t, webhookEntry.entryID, list.Entries[0].Id)
}

func setupTest(t *testing.T) (context.Context, context.CancelFunc, *fake.Clientset, *fakeentryclient.Client) {
	ctx, cancel := context.WithCancel(context.Background())

	clientset := fake.NewSimpleClientset()
	require.NotNil(t, clientset)

	entryClient := fakeentryclient.New(t, spiffeid.RequireTrustDomainFromString(TrustDomain), nil, nil)
	require.NotNil(t, entryClient)

	createNode(ctx, t, clientset)

	return ctx, cancel, clientset, entryClient
}

func createNode(ctx context.Context, t *testing.T, clientset *fake.Clientset) {
	_, err := clientset.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: NodeName,
			UID:  UID,
		},
		Spec: corev1.NodeSpec{},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

func createPod(ctx context.Context, t *testing.T, clientset *fake.Clientset, name, namespace string, uid types.UID) {
	_, err := clientset.CoreV1().Pods(namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: Namespace,
			UID:       uid,
		},
		Spec: corev1.PodSpec{},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

func deletePod(ctx context.Context, t *testing.T, clientset *fake.Clientset, name, namespace string) {
	err := clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	require.NoError(t, err)
}
