package apiserver

import (
	"testing"

	"github.com/spiffe/spire/test/spiretest"
)

func TestAPIServerClient(t *testing.T) {
	spiretest.Run(t, new(ClientSuite))
}

type ClientSuite struct {
	spiretest.Suite
}

func (s *ClientSuite) SetupTest() {
}

func (s *ClientSuite) TearDownTest() {
}

func (s *ClientSuite) TestGetPodFailsIfNamespaceIsEmpty() {
	client := New("")
	pod, err := client.GetPod("", "POD-NAME")
	s.AssertErrorContains(err, "empty namespace")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetPodFailsIfPodNameIsEmpty() {
	client := New("")
	pod, err := client.GetPod("NAMESPACE", "")
	s.AssertErrorContains(err, "empty pod name")
	s.Nil(pod)
}

func (s *ClientSuite) TestGetNodeFailsIfNodeNameIsEmpty() {
	client := New("")
	node, err := client.GetNode("")
	s.AssertErrorContains(err, "empty node name")
	s.Nil(node)
}

//TODO: Increase coverage of this test suite
