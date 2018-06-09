package dummybuiltin

import (
	"testing"

	"github.com/spiffe/spire/proto/test/dummy"
)

func TestNoStreamBuiltIn(t *testing.T) {
	dummy.TestNoStream(t, dummy.NewDummyBuiltIn(New()))
}

func TestClientStreamBuiltIn(t *testing.T) {
	dummy.TestClientStream(t, dummy.NewDummyBuiltIn(New()))
}

func TestServerStreamBuiltIn(t *testing.T) {
	dummy.TestServerStream(t, dummy.NewDummyBuiltIn(New()))
}

func TestBothStreamBuiltIn(t *testing.T) {
	dummy.TestBothStream(t, dummy.NewDummyBuiltIn(New()))
}
