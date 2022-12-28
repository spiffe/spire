package controllers

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeentryclient"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/test/spiretest"
)

const podControllerTestTrustDomain = "example.test"

func TestPodController(t *testing.T) {
	spiretest.Run(t, new(PodControllerTestSuite))
}

type PodControllerTestSuite struct {
	spiretest.Suite

	ctrl        *gomock.Controller
	ds          *fakedatastore.DataStore
	entryClient *fakeentryclient.Client

	log logr.Logger
}

func (s *PodControllerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())

	s.ds = fakedatastore.New(s.T())
	s.entryClient = fakeentryclient.New(s.T(), spiffeid.RequireTrustDomainFromString(podControllerTestTrustDomain), s.ds, nil)

	s.ctrl = mockCtrl

	s.log = zap.New()
}

func (s *PodControllerTestSuite) TearDownTest() {
	s.ctrl.Finish()
	s.entryClient.Close()
}

func (s *PodControllerTestSuite) makePodID(name string) *spiretypes.SPIFFEID {
	return &spiretypes.SPIFFEID{
		TrustDomain: nodeControllerTestTrustDomain,
		Path:        name,
	}
}

func (s *PodControllerTestSuite) TestAddChangeRemovePod() {
	ctx := context.TODO()

	tests := []struct {
		m      PodReconcilerMode
		first  string
		second string
	}{
		{PodReconcilerModeLabel, "/label1", "/label2"},
		{PodReconcilerModeAnnotation, "/annotation1", "/annotation2"},
		{PodReconcilerModeServiceAccount, "/ns/bar/sa/sa1", "/ns/bar/sa/sa2"},
	}

	for _, tt := range tests {
		tt := tt
		s.Run(tt.first, func() {
			k8sClient := createK8sClient()
			r := NewPodReconciler(
				k8sClient,
				s.log,
				scheme.Scheme,
				podControllerTestTrustDomain,
				&spiretypes.SPIFFEID{
					TrustDomain: nodeControllerTestTrustDomain,
					Path:        "/foo/node",
				}, s.entryClient,
				tt.m,
				"spiffe",
				"",
				false,
				[]string{},
			)

			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
					Labels: map[string]string{
						"spiffe": "label1",
					},
					Annotations: map[string]string{
						"spiffe":                  "annotation1",
						"spiffe.io/federatesWith": "example.io",
					},
				},
				Spec: corev1.PodSpec{
					NodeName:           "baz",
					ServiceAccountName: "sa1",
				},
			}

			_, err := s.ds.AppendBundle(ctx, &common.Bundle{TrustDomainId: "spiffe://example.io"})
			s.Assert().NoError(err)

			err = k8sClient.Create(ctx, &pod)
			s.Assert().NoError(err)

			_, err = r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "foo",
					Namespace: "bar",
				},
			})
			s.Assert().NoError(err)

			es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
				BySpiffeId: s.makePodID(tt.first),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es, 1)

			pod.Labels["spiffe"] = "label2"
			pod.Annotations["spiffe"] = "annotation2"
			pod.Spec.ServiceAccountName = "sa2"

			err = k8sClient.Update(ctx, &pod)
			s.Assert().NoError(err)

			_, err = r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "foo",
					Namespace: "bar",
				},
			})
			s.Assert().NoError(err)

			es, err = listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
				BySpiffeId: s.makePodID(tt.first),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es, 0)

			es, err = listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
				BySpiffeId: s.makePodID(tt.second),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es, 1)

			err = k8sClient.Delete(ctx, &pod)
			s.Assert().NoError(err)

			_, err = r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "foo",
					Namespace: "bar",
				},
			})
			s.Assert().NoError(err)

			es, err = listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
				BySpiffeId: s.makePodID(tt.second),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es, 0)
		})
	}
}

func (s *PodControllerTestSuite) TestAddDnsNames() {
	ctx := context.TODO()

	endpointsToCreate := corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "foo-svc", Namespace: "bar"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{
				{
					IP: "123.123.123.123",
					TargetRef: &corev1.ObjectReference{
						Kind:      "Pod",
						Namespace: "bar",
						Name:      "foo",
					},
				},
			},
			Ports: []corev1.EndpointPort{
				{
					Name:     "endpointName",
					Protocol: "TCP",
					Port:     12345,
				},
			},
		}},
	}
	k8sClient := createK8sClientWithEndpoint(&endpointsToCreate, "foo")

	r := NewPodReconciler(
		k8sClient,
		s.log,
		scheme.Scheme,
		podControllerTestTrustDomain,
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/foo/node",
		},
		s.entryClient,
		PodReconcilerModeServiceAccount,
		"",
		"cluster.local",
		true,
		[]string{},
	)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: corev1.PodSpec{
			NodeName:           "baz",
			ServiceAccountName: "sa1",
		},
		Status: corev1.PodStatus{
			PodIP: "123.123.123.124",
		},
	}
	err := k8sClient.Create(ctx, &pod)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makePodID("/ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	if s.Assert().Len(es, 1) {
		s.Assert().Equal([]string{
			"123-123-123-124.bar.pod.cluster.local",
			"123-123-123-124.bar.pod",
		}, es[0].DnsNames)
	}

	err = k8sClient.Create(ctx, &endpointsToCreate)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err = listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makePodID("/ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es, 1)
	s.Assert().ElementsMatch([]string{
		"123-123-123-124.bar.pod.cluster.local",
		"foo-svc.bar.svc.cluster.local",
		"foo.foo-svc.bar.svc.cluster.local",
		"123-123-123-123.foo-svc.bar.svc.cluster.local",
		"123-123-123-124.bar.pod",
		"foo-svc.bar.svc",
		"foo.foo-svc.bar.svc",
		"123-123-123-123.foo-svc.bar.svc",
		"foo-svc.bar",
		"foo.foo-svc.bar",
		"123-123-123-123.foo-svc.bar",
		"foo-svc",
		"foo.foo-svc",
		"123-123-123-123.foo-svc",
	}, es[0].DnsNames)
	// It's important that the pod name is the first in the list so that it gets used as the DN
	s.Assert().Equal("123-123-123-124.bar.pod.cluster.local", es[0].DnsNames[0])
}

func (s *PodControllerTestSuite) TestDottedPodNamesDns() {
	ctx := context.TODO()

	endpointsToCreate := corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "foo-svc", Namespace: "bar"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{
				{
					IP: "123.123.123.123",
					TargetRef: &corev1.ObjectReference{
						Kind:      "Pod",
						Namespace: "bar",
						Name:      "foo.3.0.0.woo",
					},
				},
			},
			Ports: []corev1.EndpointPort{
				{
					Name:     "endpointName",
					Protocol: "TCP",
					Port:     12345,
				},
			},
		}},
	}
	k8sClient := createK8sClientWithEndpoint(&endpointsToCreate, "foo.3.0.0.woo")

	r := NewPodReconciler(
		k8sClient,
		s.log,
		scheme.Scheme,
		podControllerTestTrustDomain,
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/foo/node",
		},
		s.entryClient,
		PodReconcilerModeServiceAccount,
		"",
		"cluster.local",
		true,
		[]string{},
	)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo.3.0.0.woo",
			Namespace: "bar",
		},
		Spec: corev1.PodSpec{
			NodeName:           "baz",
			ServiceAccountName: "sa1",
		},
		Status: corev1.PodStatus{
			PodIP: "123.123.123.124",
		},
	}
	err := k8sClient.Create(ctx, &pod)
	s.Assert().NoError(err)

	err = k8sClient.Create(ctx, &endpointsToCreate)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo.3.0.0.woo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makePodID("/ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	if s.Assert().Len(es, 1) {
		s.Assert().ElementsMatch([]string{
			"123-123-123-124.bar.pod.cluster.local",
			"foo-svc.bar.svc.cluster.local",
			"123-123-123-123.foo-svc.bar.svc.cluster.local",
			"123-123-123-124.bar.pod",
			"foo-svc.bar.svc",
			"123-123-123-123.foo-svc.bar.svc",
			"foo-svc.bar",
			"123-123-123-123.foo-svc.bar",
			"foo-svc",
			"123-123-123-123.foo-svc",
		}, es[0].DnsNames)
		// It's important that the pod name is the first in the list so that it gets used as the DN
		s.Assert().Equal("123-123-123-124.bar.pod.cluster.local", es[0].DnsNames[0])
	}
}

func (s *PodControllerTestSuite) TestDottedServiceNamesDns() {
	ctx := context.TODO()

	endpointsToCreate := corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "foo-svc.3.0.0", Namespace: "bar"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{
				{
					IP: "123.123.123.123",
					TargetRef: &corev1.ObjectReference{
						Kind:      "Pod",
						Namespace: "bar",
						Name:      "foo",
					},
				},
			},
			Ports: []corev1.EndpointPort{
				{
					Name:     "endpointName",
					Protocol: "TCP",
					Port:     12345,
				},
			},
		}},
	}
	k8sClient := createK8sClientWithEndpoint(&endpointsToCreate, "foo")
	r := NewPodReconciler(
		k8sClient,
		s.log,
		scheme.Scheme,
		podControllerTestTrustDomain,
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/foo/node",
		},
		s.entryClient,
		PodReconcilerModeServiceAccount,
		"",
		"cluster.local",
		true,
		[]string{},
	)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: corev1.PodSpec{
			NodeName:           "baz",
			ServiceAccountName: "sa1",
		},
		Status: corev1.PodStatus{
			PodIP: "123.123.123.124",
		},
	}
	err := k8sClient.Create(ctx, &pod)
	s.Assert().NoError(err)

	err = k8sClient.Create(ctx, &endpointsToCreate)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makePodID("/ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	if s.Assert().Len(es, 1) {
		s.Assert().ElementsMatch([]string{
			"123-123-123-124.bar.pod.cluster.local",
			"123-123-123-124.bar.pod",
		}, es[0].DnsNames)
		// It's important that the pod name is the first in the list so that it gets used as the DN
		s.Assert().Equal("123-123-123-124.bar.pod.cluster.local", es[0].DnsNames[0])
	}
}

func (s *PodControllerTestSuite) TestSkipsDisabledNamespace() {
	ctx := context.TODO()

	k8sClient := createK8sClient()
	r := NewPodReconciler(
		k8sClient,
		s.log,
		scheme.Scheme,
		podControllerTestTrustDomain,
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/foo/node",
		},
		s.entryClient,
		PodReconcilerModeServiceAccount,
		"",
		"cluster.local",
		true,
		[]string{"bar"},
	)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: corev1.PodSpec{
			NodeName:           "baz",
			ServiceAccountName: "sa1",
		},
		Status: corev1.PodStatus{
			PodIP: "123.123.123.124",
		},
	}
	err := k8sClient.Create(ctx, &pod)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makePodID("/ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es, 0)
}

func createK8sClient() client.Client {
	return fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		Build()
}

// createK8sClientWithEndpoint add Index to client, that is used to filter resources
func createK8sClientWithEndpoint(endpoints *corev1.Endpoints, uid string) client.Client {
	return fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithIndex(endpoints,
			endpointSubsetAddressReferenceField,
			func(client.Object) []string { return []string{uid} }).
		Build()
}
