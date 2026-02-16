//go:build windows

package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-api-sdk/proto/spiffe/reference"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type osConfig struct {
	cHelper *fakeContainerHelper
}

func (o *osConfig) getContainerHelper(_ *Plugin) ContainerHelper {
	return o.cHelper
}

func createOSConfig() *osConfig {
	return &osConfig{
		cHelper: &fakeContainerHelper{},
	}
}

type fakeContainerHelper struct {
	cIDs        map[int32]string
	err         error
	osSelectors []string
	osError     error
}

func (h *fakeContainerHelper) Configure(*HCLConfig, hclog.Logger) error {
	return h.err
}

func (h *fakeContainerHelper) GetOSSelectors(context.Context, hclog.Logger, *corev1.ContainerStatus) ([]string, error) {
	if h.osError != nil {
		return nil, h.osError
	}
	return h.osSelectors, nil
}

func (h *fakeContainerHelper) GetPodUIDAndContainerID(ref *anypb.Any, _ hclog.Logger) (types.UID, string, bool, error) {
	if h.err != nil {
		return types.UID(""), "", false, h.err
	}

	_, pid, err := extractRelevantReference(ref)
	if err != nil {
		return "", "", false, err
	}

	cID, ok := h.cIDs[pid]
	if !ok {
		return types.UID(""), "", false, nil
	}

	return types.UID(""), cID, true, nil
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
		ref, err := buildReferenceWithPID(123)
		require.NoError(t, err)
		podID, containerID, _, err := cHelper.GetPodUIDAndContainerID(ref, nil)
		require.NoError(t, err)

		assert.Empty(t, podID)
		assert.Equal(t, "123", containerID)
	})

	t.Run("get fails", func(t *testing.T) {
		fakeHelper.err = errors.New("oh no")
		ref, err := buildReferenceWithPID(123)
		require.NoError(t, err)
		podID, containerID, _, err := cHelper.GetPodUIDAndContainerID(ref, nil)
		spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to get container ID: oh no")

		assert.Empty(t, podID)
		assert.Equal(t, "", containerID)
	})
}

type fakeProcessHelper struct {
	containerID string
	err         error
}

func (f *fakeProcessHelper) GetContainerIDByProcess(int32, hclog.Logger) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	return f.containerID, nil
}

func buildReferenceWithPID(pid int32) (*anypb.Any, error) {
	pidReference := reference.WorkloadPIDReference{
		Pid: pid,
	}
	return anypb.New(&pidReference)
}
