package main

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	admv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	fakePodWithLabel = `
{
	"kind": "Pod",
	"apiVersion": "v1",
	"metadata": {
		"name": "PODNAME",
		"namespace": "NAMESPACE",
		"labels": {
			"spire-workload": "WORKLOAD"
		}
	},
	"spec": {
		"serviceAccountName": "SERVICEACCOUNT"
	}
}
`
	fakePodWithAnnotation = `
{
	"kind": "Pod",
	"apiVersion": "v1",
	"metadata": {
		"name": "PODNAME",
		"namespace": "NAMESPACE",
		"annotations": {
			"spiffe.io/spiffe-id": "ENV/WORKLOAD"
		}
	},
	"spec": {
		"serviceAccountName": "SERVICEACCOUNT"
	}
}
`
	fakePodOnlySA = `
{
	"kind": "Pod",
	"apiVersion": "v1",
	"metadata": {
		"name": "PODNAME-NOLABEL",
		"namespace": "NAMESPACE"
	},
	"spec": {
		"serviceAccountName": "SERVICEACCOUNT"
	}
}
`
)

func TestControllerInitialization(t *testing.T) {
	controller, r := newTestController("", "")

	// Initialize should create the registration entry for the cluster nodes
	require.NoError(t, controller.Initialize(context.Background()))
	requireEntriesEqual(t, []*common.RegistrationEntry{
		{
			EntryId:  "00000001",
			ParentId: "spiffe://domain.test/spire/server",
			SpiffeId: "spiffe://domain.test/k8s-workload-registrar/CLUSTER/node",
			Selectors: []*common.Selector{
				{Type: "k8s_psat", Value: "cluster:CLUSTER"},
			},
		},
	}, r.GetEntries())
}

func TestControllerIgnoresKubeNamespaces(t *testing.T) {
	controller, r := newTestController("", "")

	for _, namespace := range []string{"kube-system", "kube-public"} {
		requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
			UID: "uid",
			Kind: metav1.GroupVersionKind{
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: namespace,
			Name:      "PODNAME",
			Operation: "CREATE",
			Object: runtime.RawExtension{
				Raw: []byte(fakePodWithLabel),
			},
		})
		require.Empty(t, r.GetEntries(), 0)
	}
}

func TestControllerIgnoresNonPods(t *testing.T) {
	controller, r := newTestController("", "")

	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "ServiceAccount",
		},
		Namespace: "NAMESPACE",
		Name:      "SERVICEACCOUNTNAME",
		Operation: "CREATE",
	})
	require.Empty(t, r.GetEntries(), 0)
}

func TestControllerFailsIfPodUnparsable(t *testing.T) {
	controller, _ := newTestController("", "")

	requireReviewAdmissionFailure(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "POD",
		Operation: "CREATE",
	}, "unable to unmarshal v1/Pod object")
}

func TestControllerIgnoresPodOperationsOtherThanCreateAndDelete(t *testing.T) {
	controller, _ := newTestController("", "")

	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "POD",
		Operation: "UPDATE",
	})
}

func TestControllerServiceAccountBasedRegistration(t *testing.T) {
	controller, r := newTestController("", "")

	// Send in a POD CREATE and assert that it will be admitted
	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodWithLabel),
		},
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*common.RegistrationEntry{
		{
			EntryId:  "00000001",
			ParentId: "spiffe://domain.test/k8s-workload-registrar/CLUSTER/node",
			SpiffeId: "spiffe://domain.test/ns/NAMESPACE/sa/SERVICEACCOUNT",
			Selectors: []*common.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerCleansUpOnPodDeletion(t *testing.T) {
	controller, r := newTestController("", "")

	// create an entry for the POD in one service account
	_, err := r.CreateEntry(context.Background(), &common.RegistrationEntry{
		Selectors: []*common.Selector{
			namespaceSelector("NAMESPACE"),
			podNameSelector("PODNAME"),
		},
	})
	require.NoError(t, err)

	// create an entry for the POD in another service account (should be rare
	// in practice but we need to handle it).
	_, err = r.CreateEntry(context.Background(), &common.RegistrationEntry{
		Selectors: []*common.Selector{
			namespaceSelector("OTHERNAMESPACE"),
			podNameSelector("PODNAME"),
		},
	})
	require.NoError(t, err)

	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "DELETE",
	})

	// Assert that the right registration entry for the pod was removed
	requireEntriesEqual(t, []*common.RegistrationEntry{
		{
			EntryId: "00000002",
			Selectors: []*common.Selector{
				{Type: "k8s", Value: "ns:OTHERNAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerLabelBasedRegistration(t *testing.T) {
	controller, r := newTestController("spire-workload", "")

	// Send in a POD CREATE and assert that it will be admitted
	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodWithLabel),
		},
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*common.RegistrationEntry{
		{
			EntryId:  "00000001",
			ParentId: "spiffe://domain.test/k8s-workload-registrar/CLUSTER/node",
			SpiffeId: "spiffe://domain.test/WORKLOAD",
			Selectors: []*common.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerLabelBasedRegistrationIgnoresPodsWithoutLabel(t *testing.T) {
	controller, r := newTestController("spire-workload", "")

	// Send in a POD CREATE and assert that it will be admitted
	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodOnlySA),
		},
	})

	// Assert that the registration entry for the pod was created
	require.Len(t, r.GetEntries(), 0)
}

func TestPodSpiffeId(t *testing.T) {
	for _, test := range []struct {
		expectedSpiffeID  string
		configLabel       string
		podLabel          string
		configAnnotation  string
		podAnnotation     string
		podNamespace      string
		podServiceAccount string
	}{
		{
			expectedSpiffeID:  "spiffe://domain.test/ns/NS/sa/SA",
			podNamespace:      "NS",
			podServiceAccount: "SA",
		},
		{
			expectedSpiffeID: "spiffe://domain.test/LABEL",
			configLabel:      "spiffe.io/label",
			podLabel:         "LABEL",
		},
		{
			expectedSpiffeID: "spiffe://domain.test/ANNOTATION",
			configAnnotation: "spiffe.io/annotation",
			podAnnotation:    "ANNOTATION",
		},
		{
			expectedSpiffeID: "spiffe://domain.test/LABEL",
			configLabel:      "spiffe.io/label",
			podLabel:         "LABEL",
		},
		{
			configAnnotation: "someannotation",
			expectedSpiffeID: "",
		},
		{
			configLabel:      "somelabel",
			expectedSpiffeID: "",
		},
	} {
		c, _ := newTestController(test.configLabel, test.configAnnotation)

		// Set up pod:
		pod := &corev1.Pod{
			Spec: corev1.PodSpec{
				ServiceAccountName: test.podServiceAccount,
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   test.podNamespace,
				Labels:      map[string]string{},
				Annotations: map[string]string{},
			},
		}
		if test.configLabel != "" && test.podLabel != "" {
			pod.Labels[test.configLabel] = test.podLabel
		}
		if test.configAnnotation != "" && test.podAnnotation != "" {
			pod.Annotations[test.configAnnotation] = test.podAnnotation
		}

		// Test:
		spiffeID := c.podSpiffeID(pod)

		// Verify result:
		require.Equal(t, test.expectedSpiffeID, spiffeID)
	}
}

func TestControllerAnnotationBasedRegistration(t *testing.T) {
	controller, r := newTestController("", "spiffe.io/spiffe-id")

	// Send in a POD CREATE and assert that it will be admitted
	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodWithAnnotation),
		},
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*common.RegistrationEntry{
		{
			EntryId:  "00000001",
			ParentId: "spiffe://domain.test/k8s-workload-registrar/CLUSTER/node",
			SpiffeId: "spiffe://domain.test/ENV/WORKLOAD",
			Selectors: []*common.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerAnnotationBasedRegistrationIgnoresPodsWithoutLabel(t *testing.T) {
	controller, r := newTestController("", "spiffe.io/spiffe-id")

	// Send in a POD CREATE and assert that it will be admitted
	requireReviewAdmissionSuccess(t, controller, &admv1beta1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodOnlySA),
		},
	})

	// Assert that the registration entry for the pod was created
	require.Len(t, r.GetEntries(), 0)
}

func newTestController(podLabel, podAnnotation string) (*Controller, *fakeRegistrationClient) {
	log, _ := test.NewNullLogger()
	r := newFakeRegistrationClient()
	return NewController(ControllerConfig{
		Log:           log,
		R:             r,
		TrustDomain:   "domain.test",
		Cluster:       "CLUSTER",
		PodLabel:      podLabel,
		PodAnnotation: podAnnotation,
	}), r
}

func requireReviewAdmissionSuccess(t *testing.T, controller *Controller, req *admv1beta1.AdmissionRequest) {
	resp, err := controller.ReviewAdmission(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, &admv1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}, resp)
}

func requireReviewAdmissionFailure(t *testing.T, controller *Controller, req *admv1beta1.AdmissionRequest, contains string) {
	resp, err := controller.ReviewAdmission(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), contains)
	require.Nil(t, resp)
}

type fakeRegistrationClient struct {
	registration.RegistrationClient

	mu      sync.Mutex
	nextID  int64
	entries map[string]*common.RegistrationEntry
}

func newFakeRegistrationClient() *fakeRegistrationClient {
	return &fakeRegistrationClient{
		entries: make(map[string]*common.RegistrationEntry),
	}
}

func (c *fakeRegistrationClient) GetEntries() []*common.RegistrationEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := make([]*common.RegistrationEntry, 0, len(c.entries))
	for _, entry := range c.entries {
		entries = append(entries, cloneRegistrationEntry(entry))
	}
	util.SortRegistrationEntries(entries)
	return entries
}

func (c *fakeRegistrationClient) CreateEntry(ctx context.Context, entry *common.RegistrationEntry, opts ...grpc.CallOption) (*registration.RegistrationEntryID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry = cloneRegistrationEntry(entry)

	c.nextID++
	entry.EntryId = fmt.Sprintf("%08x", c.nextID)

	c.entries[entry.EntryId] = entry
	return &registration.RegistrationEntryID{Id: entry.EntryId}, nil
}

func (c *fakeRegistrationClient) DeleteEntry(ctx context.Context, id *registration.RegistrationEntryID, opts ...grpc.CallOption) (*common.RegistrationEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[id.Id]
	if !ok {
		return nil, fmt.Errorf("entry %q not found", id.Id)
	}
	delete(c.entries, id.Id)

	return entry, nil
}

func (c *fakeRegistrationClient) ListBySelectors(ctx context.Context, selectors *common.Selectors, opts ...grpc.CallOption) (*common.RegistrationEntries, error) {
	// peform an exact match check against selectors
	var entries []*common.RegistrationEntry
	for _, entry := range c.entries {
		if areSelectorsEqual(selectors.Entries, entry.Selectors) {
			entries = append(entries, cloneRegistrationEntry(entry))
		}
	}

	return &common.RegistrationEntries{
		Entries: entries,
	}, nil
}

func requireEntriesEqual(t *testing.T, expected, actual []*common.RegistrationEntry) {
	actual = cloneRegistrationEntries(actual)
	util.SortRegistrationEntries(actual)
	expected = cloneRegistrationEntries(expected)
	util.SortRegistrationEntries(expected)
	require.Equal(t, expected, actual)
}

func areSelectorsEqual(expected, actual []*common.Selector) bool {
	actual = cloneSelectors(actual)
	util.SortSelectors(actual)
	expected = cloneSelectors(expected)
	util.SortSelectors(expected)
	return proto.Equal(&common.Selectors{Entries: actual}, &common.Selectors{Entries: expected})
}

func cloneRegistrationEntries(in []*common.RegistrationEntry) []*common.RegistrationEntry {
	return proto.Clone(&common.RegistrationEntries{Entries: in}).(*common.RegistrationEntries).Entries
}

func cloneRegistrationEntry(in *common.RegistrationEntry) *common.RegistrationEntry {
	return proto.Clone(in).(*common.RegistrationEntry)
}

func cloneSelectors(in []*common.Selector) []*common.Selector {
	return proto.Clone(&common.Selectors{Entries: in}).(*common.Selectors).Entries
}
