//go:build windows
// +build windows

package k8s

import (
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/types"
)

type osConfig struct {
	cHelper *fakeContainerHelper
}

func (o *osConfig) getContainerHelper() ContainerHelper {
	return o.cHelper
}

func createOSConfig() *osConfig {
	return &osConfig{
		cHelper: &fakeContainerHelper{},
	}
}

type fakeContainerHelper struct {
	cIDs map[int32]string
	err  error
}

func (h *fakeContainerHelper) GetPodUIDAndContainerID(pID int32, _ hclog.Logger) (types.UID, string, error) {
	if h.err != nil {
		return types.UID(""), "", h.err
	}

	cID, ok := h.cIDs[pID]
	if !ok {
		return types.UID(""), "", nil
	}

	return types.UID(""), cID, nil
}

func (s *Suite) addGetContainerResponsePidInPod() {
	s.oc.cHelper.cIDs = map[int32]string{
		123: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
	}
}

func TestContainerHelper(t *testing.T) {
	fakeHelper := &fakeProcessHelper{}
	cHelper := &containerHelper{
		ph: fakeHelper,
	}

	t.Run("containerID found", func(t *testing.T) {
		fakeHelper.containerID = "123"
		podID, containerID, err := cHelper.GetPodUIDAndContainerID(123, nil)
		require.NoError(t, err)

		assert.Empty(t, podID)
		assert.Equal(t, "123", containerID)
	})

	t.Run("get fails", func(t *testing.T) {
		fakeHelper.err = errors.New("oh no")
		podID, containerID, err := cHelper.GetPodUIDAndContainerID(123, nil)
		spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to get container ID: oh no")

		assert.Empty(t, podID)
		assert.Equal(t, "", containerID)
	})
}

type fakeProcessHelper struct {
	containerID string
	err         error
}

func (f *fakeProcessHelper) GetContainerIDByProcess(pID int32, log hclog.Logger) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	return f.containerID, nil
}
