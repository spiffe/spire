package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	admv1 "k8s.io/api/admission/v1"
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

	fakePodWithFederation = `
{
	"kind": "Pod",
	"apiVersion": "v1",
	"metadata": {
		"name": "PODNAME",
		"namespace": "NAMESPACE",
		"annotations": {
			"spiffe.io/federatesWith": "example.net"
		}
	},
	"spec": {
		"serviceAccountName": "SERVICEACCOUNT"
	}
}
`

	fakePodWithMultiFederation = `
{
	"kind": "Pod",
	"apiVersion": "v1",
	"metadata": {
		"name": "PODNAME",
		"namespace": "NAMESPACE",
		"annotations": {
			"spiffe.io/federatesWith": "example.net,example.io"
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
	requireEntriesEqual(t, []*types.Entry{
		{
			Id:       "00000001",
			ParentId: mustIDFromString("spiffe://domain.test/spire/server"),
			SpiffeId: mustIDFromString("spiffe://domain.test/k8s-workload-registrar/CLUSTER/node"),
			Selectors: []*types.Selector{
				{Type: "k8s_psat", Value: "cluster:CLUSTER"},
			},
		},
	}, r.GetEntries())
}

func TestControllerIgnoresKubeNamespaces(t *testing.T) {
	controller, r := newTestController("", "")

	for _, namespace := range []string{"kube-system", "kube-public"} {
		request := &admv1.AdmissionRequest{
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
		}
		requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
			Request: request,
		})
		require.Empty(t, r.GetEntries(), 0)
	}
}

func TestControllerIgnoresNonPods(t *testing.T) {
	controller, r := newTestController("", "")

	request := &admv1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "ServiceAccount",
		},
		Namespace: "NAMESPACE",
		Name:      "SERVICEACCOUNTNAME",
		Operation: "CREATE",
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})
	require.Empty(t, r.GetEntries(), 0)
}

func TestControllerFailsIfPodUnparsable(t *testing.T) {
	controller, _ := newTestController("", "")

	request := &admv1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "POD",
		Operation: "CREATE",
	}
	requireReviewAdmissionFailure(t, controller, admv1.AdmissionReview{Request: request}, "unable to unmarshal v1/Pod object")
}

func TestControllerIgnoresPodOperationsOtherThanCreateAndDelete(t *testing.T) {
	controller, _ := newTestController("", "")

	request := &admv1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "POD",
		Operation: "UPDATE",
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})
}

func TestControllerServiceAccountBasedRegistration(t *testing.T) {
	controller, r := newTestController("", "")

	// Send in a POD CREATE and assert that it will be admitted
	request := &admv1.AdmissionRequest{
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
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*types.Entry{
		{
			Id:       "00000001",
			ParentId: mustIDFromString("spiffe://domain.test/k8s-workload-registrar/CLUSTER/node"),
			SpiffeId: mustIDFromString("spiffe://domain.test/ns/NAMESPACE/sa/SERVICEACCOUNT"),
			Selectors: []*types.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerCleansUpOnPodDeletion(t *testing.T) {
	controller, r := newTestController("", "")

	// create an entry for the POD in one service account
	r.CreateEntry(&types.Entry{
		Selectors: []*types.Selector{
			namespaceSelector("NAMESPACE"),
			podNameSelector("PODNAME"),
		},
	})

	// create an entry for the POD in another service account (should be rare
	// in practice but we need to handle it).
	r.CreateEntry(&types.Entry{
		Selectors: []*types.Selector{
			namespaceSelector("OTHERNAMESPACE"),
			podNameSelector("PODNAME"),
		},
	})

	request := &admv1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "DELETE",
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the right registration entry for the pod was removed
	requireEntriesEqual(t, []*types.Entry{
		{
			Id: "00000002",
			Selectors: []*types.Selector{
				{Type: "k8s", Value: "ns:OTHERNAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerLabelBasedRegistration(t *testing.T) {
	controller, r := newTestController("spire-workload", "")

	// Send in a POD CREATE and assert that it will be admitted
	request := &admv1.AdmissionRequest{
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
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*types.Entry{
		{
			Id:       "00000001",
			ParentId: mustIDFromString("spiffe://domain.test/k8s-workload-registrar/CLUSTER/node"),
			SpiffeId: mustIDFromString("spiffe://domain.test/WORKLOAD"),
			Selectors: []*types.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerLabelBasedRegistrationIgnoresPodsWithoutLabel(t *testing.T) {
	controller, r := newTestController("spire-workload", "")

	// Send in a POD CREATE and assert that it will be admitted
	request := &admv1.AdmissionRequest{
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
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the registration entry for the pod was created
	require.Len(t, r.GetEntries(), 0)
}

func TestPodSpiffeId(t *testing.T) {
	for _, testCase := range []struct {
		name              string
		expectedSpiffeID  string
		configLabel       string
		podLabel          string
		configAnnotation  string
		podAnnotation     string
		podNamespace      string
		podServiceAccount string
	}{
		{
			name:              "using namespace and serviceaccount",
			expectedSpiffeID:  "spiffe://domain.test/ns/NS/sa/SA",
			podNamespace:      "NS",
			podServiceAccount: "SA",
		},
		{
			name:             "using label",
			expectedSpiffeID: "spiffe://domain.test/LABEL",
			configLabel:      "spiffe.io/label",
			podLabel:         "LABEL",
		},
		{
			name:             "using annotation",
			expectedSpiffeID: "spiffe://domain.test/ANNOTATION",
			configAnnotation: "spiffe.io/annotation",
			podAnnotation:    "ANNOTATION",
		},
		{
			name:             "ignore unannotated",
			configAnnotation: "someannotation",
			expectedSpiffeID: "",
		},
		{
			name:             "ignore unlabelled",
			configLabel:      "somelabel",
			expectedSpiffeID: "",
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			c, _ := newTestController(testCase.configLabel, testCase.configAnnotation)

			// Set up pod:
			pod := &corev1.Pod{
				Spec: corev1.PodSpec{
					ServiceAccountName: testCase.podServiceAccount,
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   testCase.podNamespace,
					Labels:      map[string]string{},
					Annotations: map[string]string{},
				},
			}
			if testCase.configLabel != "" && testCase.podLabel != "" {
				pod.Labels[testCase.configLabel] = testCase.podLabel
			}
			if testCase.configAnnotation != "" && testCase.podAnnotation != "" {
				pod.Annotations[testCase.configAnnotation] = testCase.podAnnotation
			}

			// Test:
			spiffeID := c.podSpiffeID(pod)

			// Verify result:
			require.Equal(t, testCase.expectedSpiffeID, stringFromID(spiffeID))
		})
	}
}

func TestControllerAnnotationBasedRegistration(t *testing.T) {
	controller, r := newTestController("", "spiffe.io/spiffe-id")

	// Send in a POD CREATE and assert that it will be admitted
	request := &admv1.AdmissionRequest{
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
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*types.Entry{
		{
			Id:       "00000001",
			ParentId: mustIDFromString("spiffe://domain.test/k8s-workload-registrar/CLUSTER/node"),
			SpiffeId: mustIDFromString("spiffe://domain.test/ENV/WORKLOAD"),
			Selectors: []*types.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerFederationBasedRegistration(t *testing.T) {
	controller, r := newTestController("", "")

	// Send in a POD CREATE and assert that it will be admitted
	request := &admv1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodWithFederation),
		},
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*types.Entry{
		{
			Id:            "00000001",
			ParentId:      mustIDFromString("spiffe://domain.test/k8s-workload-registrar/CLUSTER/node"),
			SpiffeId:      mustIDFromString("spiffe://domain.test/ns/NAMESPACE/sa/SERVICEACCOUNT"),
			FederatesWith: []string{"example.net"},
			Selectors: []*types.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerMultiFederationBasedRegistration(t *testing.T) {
	controller, r := newTestController("", "")

	// Send in a POD CREATE and assert that it will be admitted
	request := &admv1.AdmissionRequest{
		UID: "uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "NAMESPACE",
		Name:      "PODNAME",
		Operation: "CREATE",
		Object: runtime.RawExtension{
			Raw: []byte(fakePodWithMultiFederation),
		},
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{
		Request: request,
	})

	// Assert that the registration entry for the pod was created
	requireEntriesEqual(t, []*types.Entry{
		{
			Id:            "00000001",
			ParentId:      mustIDFromString("spiffe://domain.test/k8s-workload-registrar/CLUSTER/node"),
			SpiffeId:      mustIDFromString("spiffe://domain.test/ns/NAMESPACE/sa/SERVICEACCOUNT"),
			FederatesWith: []string{"example.net", "example.io"},
			Selectors: []*types.Selector{
				{Type: "k8s", Value: "ns:NAMESPACE"},
				{Type: "k8s", Value: "pod-name:PODNAME"},
			},
		},
	}, r.GetEntries())
}

func TestControllerAnnotationBasedRegistrationIgnoresPodsWithoutLabel(t *testing.T) {
	controller, r := newTestController("", "spiffe.io/spiffe-id")

	// Send in a POD CREATE and assert that it will be admitted
	ar := &admv1.AdmissionRequest{
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
	}
	requireReviewAdmissionSuccess(t, controller, admv1.AdmissionReview{Request: ar})

	// Assert that the registration entry for the pod was created
	require.Len(t, r.GetEntries(), 0)
}

func newTestController(podLabel, podAnnotation string) (*Controller, *fakeEntryClient) {
	log, _ := test.NewNullLogger()
	e := newFakeEntryClient()
	return NewController(ControllerConfig{
		Log:                log,
		E:                  e,
		TrustDomain:        "domain.test",
		Cluster:            "CLUSTER",
		PodLabel:           podLabel,
		PodAnnotation:      podAnnotation,
		DisabledNamespaces: map[string]bool{"kube-system": true, "kube-public": true},
	}), e
}

func requireReviewAdmissionSuccess(t *testing.T, controller *Controller, ar admv1.AdmissionReview) {
	resp, err := controller.ReviewAdmission(context.Background(), ar)
	require.NoError(t, err)
	require.Equal(t, &admv1.AdmissionResponse{
		UID:     ar.Request.UID,
		Allowed: true,
	}, resp)
}

func requireReviewAdmissionFailure(t *testing.T, controller *Controller, ar admv1.AdmissionReview, contains string) {
	resp, err := controller.ReviewAdmission(context.Background(), ar)
	require.Error(t, err)
	require.Contains(t, err.Error(), contains)
	require.Nil(t, resp)
}

type fakeEntryClient struct {
	entryv1.EntryClient

	mu      sync.Mutex
	nextID  int64
	entries map[string]*types.Entry
}

func newFakeEntryClient() *fakeEntryClient {
	return &fakeEntryClient{
		entries: make(map[string]*types.Entry),
	}
}

func (c *fakeEntryClient) GetEntries() []*types.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := make([]*types.Entry, 0, len(c.entries))
	for _, entry := range c.entries {
		entries = append(entries, cloneEntry(entry))
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Id < entries[j].Id
	})
	return entries
}

func (c *fakeEntryClient) CreateEntry(entry *types.Entry) *types.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clone for storage
	entry = cloneEntry(entry)

	c.nextID++
	entry.Id = fmt.Sprintf("%08x", c.nextID)

	c.entries[entry.Id] = entry
	// Clone on the way out
	return cloneEntry(entry)
}

func (c *fakeEntryClient) BatchCreateEntry(ctx context.Context, req *entryv1.BatchCreateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error) {
	resp := new(entryv1.BatchCreateEntryResponse)
	for _, entryIn := range req.Entries {
		resp.Results = append(resp.Results, &entryv1.BatchCreateEntryResponse_Result{
			Status: &types.Status{},
			Entry:  c.CreateEntry(entryIn),
		})
	}
	return resp, nil
}

func (c *fakeEntryClient) BatchDeleteEntry(ctx context.Context, req *entryv1.BatchDeleteEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp := new(entryv1.BatchDeleteEntryResponse)
	for _, id := range req.Ids {
		_, ok := c.entries[id]
		code := codes.OK
		var msg string
		if !ok {
			code = codes.NotFound
			msg = "not found"
		}

		resp.Results = append(resp.Results, &entryv1.BatchDeleteEntryResponse_Result{
			Status: &types.Status{Code: int32(code), Message: msg},
			Id:     id,
		})
		delete(c.entries, id)
	}

	return resp, nil
}

func (c *fakeEntryClient) ListEntries(ctx context.Context, req *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	switch {
	case req.Filter == nil:
		return nil, status.Error(codes.InvalidArgument, "expecting filter")
	case req.Filter.BySelectors == nil:
		return nil, status.Error(codes.InvalidArgument, "expecting filter by selector")
	case req.Filter.BySelectors.Match != types.SelectorMatch_MATCH_EXACT:
		return nil, status.Error(codes.InvalidArgument, "expecting exact selector match")
	}

	// peform an exact match check against selectors
	var entries []*types.Entry
	for _, entry := range c.entries {
		if selectorSetsEqual(req.Filter.BySelectors.Selectors, entry.Selectors) {
			entries = append(entries, cloneEntry(entry))
		}
	}

	return &entryv1.ListEntriesResponse{
		Entries: entries,
	}, nil
}

func requireEntriesEqual(t *testing.T, expected, actual []*types.Entry) {
	spiretest.RequireProtoListEqual(t, expected, actual)
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

func cloneEntry(in *types.Entry) *types.Entry {
	return proto.Clone(in).(*types.Entry)
}

func mustIDFromString(s string) *types.SPIFFEID {
	id := spiffeid.RequireFromString(s)
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}
}

func stringFromID(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}
