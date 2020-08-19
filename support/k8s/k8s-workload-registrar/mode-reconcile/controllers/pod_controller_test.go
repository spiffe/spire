package controllers

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeregistrationclient"
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

	ctrl               *gomock.Controller
	ds                 *fakedatastore.DataStore
	registrationClient *fakeregistrationclient.Client

	k8sClient client.Client

	log logr.Logger
}

func (s *PodControllerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())

	s.ds = fakedatastore.New(s.T())
	s.registrationClient = fakeregistrationclient.New(s.T(), fmt.Sprintf("spiffe://%s", podControllerTestTrustDomain), s.ds, nil)

	s.ctrl = mockCtrl

	s.k8sClient = fake.NewFakeClientWithScheme(scheme.Scheme)

	s.log = zap.New()
}

func (s *PodControllerTestSuite) TearDownTest() {
	s.ctrl.Finish()
	s.registrationClient.Close()
}

func (s *PodControllerTestSuite) makePodID(name string) string {
	return fmt.Sprintf("spiffe://%s/%s", podControllerTestTrustDomain, name)
}

func (s *PodControllerTestSuite) TestAddChangeRemovePod() {
	ctx := context.TODO()

	tests := []struct {
		m      PodReconcilerMode
		first  string
		second string
	}{
		{PodReconcilerModeLabel, "label1", "label2"},
		{PodReconcilerModeAnnotation, "annotation1", "annotation2"},
		{PodReconcilerModeServiceAccount, "ns/bar/sa/sa1", "ns/bar/sa/sa2"},
	}

	for _, tt := range tests {
		tt := tt
		s.Run(tt.first, func() {
			r := NewPodReconciler(
				s.k8sClient,
				s.log,
				scheme.Scheme,
				podControllerTestTrustDomain,
				fmt.Sprintf("spiffe://%s/foo/node", podControllerTestTrustDomain),
				s.registrationClient,
				tt.m,
				"spiffe",
				"",
				false,
			)

			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
					Labels: map[string]string{
						"spiffe": "label1",
					},
					Annotations: map[string]string{
						"spiffe": "annotation1",
					},
				},
				Spec: corev1.PodSpec{
					NodeName:           "baz",
					ServiceAccountName: "sa1",
				},
			}

			err := s.k8sClient.Create(ctx, &pod)
			s.Assert().NoError(err)

			_, err = r.Reconcile(ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "foo",
					Namespace: "bar",
				},
			})
			s.Assert().NoError(err)

			es, err := s.registrationClient.ListBySpiffeID(ctx, &registration.SpiffeID{
				Id: s.makePodID(tt.first),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es.Entries, 1)

			pod.Labels["spiffe"] = "label2"
			pod.Annotations["spiffe"] = "annotation2"
			pod.Spec.ServiceAccountName = "sa2"

			err = s.k8sClient.Update(ctx, &pod)
			s.Assert().NoError(err)

			_, err = r.Reconcile(ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "foo",
					Namespace: "bar",
				},
			})
			s.Assert().NoError(err)

			es, err = s.registrationClient.ListBySpiffeID(ctx, &registration.SpiffeID{
				Id: s.makePodID(tt.first),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es.Entries, 0)

			es, err = s.registrationClient.ListBySpiffeID(ctx, &registration.SpiffeID{
				Id: s.makePodID(tt.second),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es.Entries, 1)

			err = s.k8sClient.Delete(ctx, &pod)
			s.Assert().NoError(err)

			_, err = r.Reconcile(ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "foo",
					Namespace: "bar",
				},
			})
			s.Assert().NoError(err)

			es, err = s.registrationClient.ListBySpiffeID(ctx, &registration.SpiffeID{
				Id: s.makePodID(tt.second),
			})
			s.Assert().NoError(err)
			s.Assert().Len(es.Entries, 0)
		})
	}
}

func (s *PodControllerTestSuite) TestAddDnsNames() {
	ctx := context.TODO()

	r := NewPodReconciler(
		s.k8sClient,
		s.log,
		scheme.Scheme,
		podControllerTestTrustDomain,
		fmt.Sprintf("spiffe://%s/foo/node", podControllerTestTrustDomain),
		s.registrationClient,
		PodReconcilerModeServiceAccount,
		"",
		"cluster.local",
		true,
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
	err := s.k8sClient.Create(ctx, &pod)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err := s.registrationClient.ListBySpiffeID(ctx, &registration.SpiffeID{
		Id: s.makePodID("ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es.Entries, 1)
	s.Assert().Equal([]string{"123-123-123-124.bar.pod.cluster.local"}, es.Entries[0].DnsNames)

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

	err = s.k8sClient.Create(ctx, &endpointsToCreate)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	s.Assert().NoError(err)

	es, err = s.registrationClient.ListBySpiffeID(ctx, &registration.SpiffeID{
		Id: s.makePodID("ns/bar/sa/sa1"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es.Entries, 1)
	s.Assert().ElementsMatch([]string{"123-123-123-124.bar.pod.cluster.local", "foo-svc.bar.svc.cluster.local", "foo.foo-svc.bar.svc.cluster.local", "123-123-123-123.foo-svc.bar.svc.cluster.local"}, es.Entries[0].DnsNames)
	// It's important that the pod name is the first in the list so that it gets used as the DN
	s.Assert().Equal("123-123-123-124.bar.pod.cluster.local", es.Entries[0].DnsNames[0])
}
