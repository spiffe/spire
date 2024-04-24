//go:build windows

package docker

import (
	"errors"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	defaultPluginConfig = ""
)

func TestFailToGetContainerID(t *testing.T) {
	h := &fakeProcessHelper{
		err: errors.New("oh no"),
	}

	p := newTestPlugin(
		t,
		withContainerHelper(h),
		withDocker(dockerError{}),
		withDisabledRetryer(),
	)

	selectorValues, err := doAttest(t, p)
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "workloadattestor(docker): failed to get container ID: oh no")
	require.Empty(t, selectorValues)
}

func TestNoContainerID(t *testing.T) {
	h := &fakeProcessHelper{
		containerID: "",
	}

	p := newTestPlugin(
		t,
		withContainerHelper(h),
		withDocker(dockerError{}),
		withDisabledRetryer(),
	)

	selectorValues, err := doAttest(t, p)
	require.NoError(nil, err)
	require.Empty(t, selectorValues)
}

func verifyConfigDefault(t *testing.T, c *containerHelper) {
	require.NotNil(t, c.ph)
}

func withDefaultDataOpt(testing.TB) testPluginOpt {
	h := &fakeProcessHelper{
		containerID: testContainerID,
	}
	return withContainerHelper(h)
}

func withContainerHelper(h *fakeProcessHelper) testPluginOpt {
	return func(p *Plugin) {
		p.c.ph = h
	}
}

type fakeProcessHelper struct {
	err         error
	containerID string
}

func (f *fakeProcessHelper) GetContainerIDByProcess(int32, hclog.Logger) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	return f.containerID, nil
}
