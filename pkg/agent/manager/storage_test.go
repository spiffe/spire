package manager

import (
	"path"
	"testing"

	"github.com/spiffe/spire/test/util"
)

func TestReadBundle(t *testing.T) {
	expectedBundle, err := util.LoadBundleFixture()
	if err != nil {
		t.Error(err)
		return
	}

	actualBundle, err := ReadBundle(path.Join(util.ProjectRoot(), "test/fixture/certs/bundle.der"))
	if err != nil {
		t.Error(err)
		return
	}

	if len(expectedBundle) != len(actualBundle) {
		t.Errorf("wrong number of certificates, want: %d, got: %d", len(expectedBundle), len(actualBundle))
	}

	for i, c := range expectedBundle {
		if !actualBundle[i].Equal(c) {
			t.Errorf("bundle is not as expected")
			return
		}
	}
}
