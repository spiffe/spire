package controllers

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/test/fakes/fakeentryclient"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
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

const nodeControllerTestTrustDomain = "example.test"

func TestNodeController(t *testing.T) {
	spiretest.Run(t, new(NodeControllerTestSuite))
}

type NodeControllerTestSuite struct {
	spiretest.Suite

	ctrl        *gomock.Controller
	ds          *fakedatastore.DataStore
	entryClient *fakeentryclient.Client

	k8sClient client.Client

	log logr.Logger
}

func (s *NodeControllerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())

	s.ds = fakedatastore.New(s.T())
	s.entryClient = fakeentryclient.New(s.T(), spiffeid.RequireTrustDomainFromString(nodeControllerTestTrustDomain), s.ds, nil)

	s.ctrl = mockCtrl

	s.k8sClient = fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()

	s.log = zap.New()
}

func (s *NodeControllerTestSuite) TearDownTest() {
	s.ctrl.Finish()
	s.entryClient.Close()
}

func (s *NodeControllerTestSuite) makeNodeID(node string) *spiretypes.SPIFFEID {
	path, err := spiffeid.JoinPathSegments("foo", "node", node)
	s.Require().NoError(err)
	return &spiretypes.SPIFFEID{
		TrustDomain: nodeControllerTestTrustDomain,
		Path:        path,
	}
}

func (s *NodeControllerTestSuite) TestAddRemoveNode() {
	ctx := context.TODO()

	r := NewNodeReconciler(
		s.k8sClient,
		s.log,
		scheme.Scheme,
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/server",
		},
		"test-cluster",
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/foo/node",
		},
		s.entryClient,
	)

	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: corev1.NodeSpec{},
	}

	err := s.k8sClient.Create(ctx, &node)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "",
			Name:      "foo",
		},
	})
	s.Assert().NoError(err)
	es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makeNodeID("foo"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es, 1)

	err = s.k8sClient.Delete(ctx, &node)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "",
			Name:      "foo",
		},
	})
	s.Assert().NoError(err)

	es, err = listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makeNodeID("foo"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es, 0)
}

func (s *NodeControllerTestSuite) TestRequeuesMissingNode() {
	ctx := context.TODO()

	r := NewNodeReconciler(
		s.k8sClient,
		s.log,
		scheme.Scheme,
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/server",
		},
		"test-cluster",
		&spiretypes.SPIFFEID{
			TrustDomain: nodeControllerTestTrustDomain,
			Path:        "/foo/node",
		},
		s.entryClient,
	)

	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: corev1.NodeSpec{},
	}

	err := s.k8sClient.Create(ctx, &node)
	s.Assert().NoError(err)

	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "",
			Name:      "foo",
		},
	})
	s.Assert().NoError(err)

	es, err := listEntries(ctx, s.entryClient, &entryv1.ListEntriesRequest_Filter{
		BySpiffeId: s.makeNodeID("foo"),
	})
	s.Assert().NoError(err)
	s.Assert().Len(es, 1)

	s.Assert().Len(r.doPollSpire(ctx, s.log), 0)

	// This simulates behavior where Reconcile is not being called for the deletion, for example because the
	// registrar was offline at the point Delete occurs.
	err = s.k8sClient.Delete(ctx, &node)
	s.Assert().NoError(err)

	queue := r.doPollSpire(ctx, s.log)
	s.Assert().Len(queue, 1)
	s.Assert().Equal("foo", queue[0].Object.GetName())
}
