//go:build !windows

package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/types"
)

const (
	kindPodListFilePath                     = "testdata/kind_pod_list.json"
	crioPodListFilePath                     = "testdata/crio_pod_list.json"
	crioPodListDuplicateContainerIDFilePath = "testdata/crio_pod_list_duplicate_containerId.json"

	cgPidInPodFilePath            = "testdata/cgroups_pid_in_pod.txt"
	cgPidInKindPodFilePath        = "testdata/cgroups_pid_in_kind_pod.txt"
	cgPidInCrioPodFilePath        = "testdata/cgroups_pid_in_crio_pod.txt"
	cgInitPidInPodFilePath        = "testdata/cgroups_init_pid_in_pod.txt"
	cgPidNotInPodFilePath         = "testdata/cgroups_pid_not_in_pod.txt"
	cgSystemdPidInPodFilePath     = "testdata/systemd_cgroups_pid_in_pod.txt"
	cgSystemdCrioPidInPodFilePath = "testdata/systemd_crio_cgroups_pid_in_pod.txt"
)

var (
	pidCgroupPath = fmt.Sprintf("/proc/%v/cgroup", pid)

	testKindPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:gcr.io/spiffe-io/spire-agent:0.8.1"},
		{Type: "k8s", Value: "container-image:gcr.io/spiffe-io/spire-agent@sha256:1e4c481d76e9ecbd3d8684891e0e46aa021a30920ca04936e1fdcc552747d941"},
		{Type: "k8s", Value: "container-name:workload-api-client"},
		{Type: "k8s", Value: "node-name:kind-control-plane"},
		{Type: "k8s", Value: "ns:default"},
		{Type: "k8s", Value: "pod-image-count:1"},
		{Type: "k8s", Value: "pod-image:gcr.io/spiffe-io/spire-agent:0.8.1"},
		{Type: "k8s", Value: "pod-image:gcr.io/spiffe-io/spire-agent@sha256:1e4c481d76e9ecbd3d8684891e0e46aa021a30920ca04936e1fdcc552747d941"},
		{Type: "k8s", Value: "pod-init-image-count:0"},
		{Type: "k8s", Value: "pod-label:app:sample-workload"},
		{Type: "k8s", Value: "pod-label:pod-template-hash:6658cb9566"},
		{Type: "k8s", Value: "pod-name:sample-workload-6658cb9566-5n4b4"},
		{Type: "k8s", Value: "pod-owner-uid:ReplicaSet:349d135e-3781-43e3-bc25-c900aedf1d0c"},
		{Type: "k8s", Value: "pod-owner:ReplicaSet:sample-workload-6658cb9566"},
		{Type: "k8s", Value: "pod-uid:a2830d0d-b0f0-4ff0-81b5-0ee4e299cf80"},
		{Type: "k8s", Value: "sa:default"},
	}

	testCrioPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:gcr.io/spiffe-io/spire-agent:0.8.1"},
		{Type: "k8s", Value: "container-image:gcr.io/spiffe-io/spire-agent@sha256:1e4c481d76e9ecbd3d8684891e0e46aa021a30920ca04936e1fdcc552747d941"},
		{Type: "k8s", Value: "container-name:workload-api-client"},
		{Type: "k8s", Value: "node-name:a37b7d23-d32a-4932-8f33-40950ac16ee9"},
		{Type: "k8s", Value: "ns:sfh-199"},
		{Type: "k8s", Value: "pod-image-count:1"},
		{Type: "k8s", Value: "pod-image:gcr.io/spiffe-io/spire-agent:0.8.1"},
		{Type: "k8s", Value: "pod-image:gcr.io/spiffe-io/spire-agent@sha256:1e4c481d76e9ecbd3d8684891e0e46aa021a30920ca04936e1fdcc552747d941"},
		{Type: "k8s", Value: "pod-init-image-count:0"},
		{Type: "k8s", Value: "pod-label:app:sample-workload"},
		{Type: "k8s", Value: "pod-label:pod-template-hash:6658cb9566"},
		{Type: "k8s", Value: "pod-name:sample-workload-6658cb9566-5n4b4"},
		{Type: "k8s", Value: "pod-owner-uid:ReplicaSet:349d135e-3781-43e3-bc25-c900aedf1d0c"},
		{Type: "k8s", Value: "pod-owner:ReplicaSet:sample-workload-6658cb9566"},
		{Type: "k8s", Value: "pod-uid:a2830d0d-b0f0-4ff0-81b5-0ee4e299cf80"},
		{Type: "k8s", Value: "sa:default"},
	}

	testInitPodSelectors = []*common.Selector{
		{Type: "k8s", Value: "container-image:docker-pullable://quay.io/coreos/flannel@sha256:1b401bf0c30bada9a539389c3be652b58fe38463361edf488e6543c8761d4970"},
		{Type: "k8s", Value: "container-image:quay.io/coreos/flannel:v0.9.0-amd64"},
		{Type: "k8s", Value: "container-name:install-cni"},
		{Type: "k8s", Value: "node-name:k8s-node-1"},
		{Type: "k8s", Value: "ns:kube-system"},
		{Type: "k8s", Value: "pod-image-count:1"},
		{Type: "k8s", Value: "pod-image:docker-pullable://quay.io/coreos/flannel@sha256:1b401bf0c30bada9a539389c3be652b58fe38463361edf488e6543c8761d4970"},
		{Type: "k8s", Value: "pod-image:quay.io/coreos/flannel:v0.9.0-amd64"},
		{Type: "k8s", Value: "pod-init-image-count:1"},
		{Type: "k8s", Value: "pod-init-image:docker-pullable://quay.io/coreos/flannel@sha256:1b401bf0c30bada9a539389c3be652b58fe38463361edf488e6543c8761d4970"},
		{Type: "k8s", Value: "pod-init-image:quay.io/coreos/flannel:v0.9.0-amd64"},
		{Type: "k8s", Value: "pod-label:app:flannel"},
		{Type: "k8s", Value: "pod-label:controller-revision-hash:1846323910"},
		{Type: "k8s", Value: "pod-label:pod-template-generation:1"},
		{Type: "k8s", Value: "pod-label:tier:node"},
		{Type: "k8s", Value: "pod-name:kube-flannel-ds-gp1g9"},
		{Type: "k8s", Value: "pod-owner-uid:DaemonSet:2f0350fc-b29d-11e7-9350-020968147796"},
		{Type: "k8s", Value: "pod-owner:DaemonSet:kube-flannel-ds"},
		{Type: "k8s", Value: "pod-uid:d488cae9-b2a0-11e7-9350-020968147796"},
		{Type: "k8s", Value: "sa:flannel"},
	}
)

func (s *Suite) TestAttestWithInitPidInPod() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestSuccessWithInitPod(p)
}

func (s *Suite) TestAttestWithPidInKindPod() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestSuccessWithKindPod(p)
}

func (s *Suite) TestAttestWithPidInCrioPod() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestSuccessWithCrioPod(p)
}

func (s *Suite) TestAttestWithPidNotInPod() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()
	s.addCgroupsResponse(cgPidNotInPodFilePath)

	selectors, err := p.Attest(context.Background(), pid)
	s.Require().NoError(err)
	s.Require().Empty(selectors)
}

func (s *Suite) TestAttestFailDuplicateContainerId() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestFailWithDuplicateContainerID(p)
}

func (s *Suite) TestAttestWithPidInPodSystemdCgroups() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestSuccessWithPodSystemdCgroups(p)
}

func (s *Suite) TestAttestWithPidInPodSystemdCrioCgroups() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()

	s.requireAttestSuccessWithPodSystemdCrioCgroups(p)
}

func (s *Suite) TestAttestAgainstNodeOverride() {
	s.startInsecureKubelet()
	p := s.loadInsecurePlugin()
	s.addCgroupsResponse(cgPidNotInPodFilePath)

	selectors, err := p.Attest(context.Background(), pid)
	s.Require().NoError(err)
	s.Require().Empty(selectors)
}

func (s *Suite) TestAttestWhenContainerNotReadyButContainerSelectorsDisabled() {
	// This test will not pass on windows since obtaining the container ID is
	// currently required to identify the workload pod in that environment.
	s.startInsecureKubelet()
	p := s.loadInsecurePluginWithExtra("disable_container_selectors = true")
	s.addPodListResponse(podListNotRunningFilePath)
	s.addGetContainerResponsePidInPod()
	s.requireAttestSuccess(p, testPodSelectors)
}

func (s *Suite) addGetContainerResponsePidInPod() {
	s.addCgroupsResponse(cgPidInPodFilePath)
}

func (s *Suite) addCgroupsResponse(fixturePath string) {
	wd, err := os.Getwd()
	s.Require().NoError(err)
	cgroupPath := filepath.Join(s.dir, pidCgroupPath)
	s.Require().NoError(os.MkdirAll(filepath.Dir(cgroupPath), 0755))
	os.Remove(cgroupPath)
	s.Require().NoError(os.Symlink(filepath.Join(wd, fixturePath), cgroupPath))
}

func (s *Suite) requireAttestSuccessWithInitPod(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgInitPidInPodFilePath)
	s.requireAttestSuccess(p, testInitPodSelectors)
}

func (s *Suite) requireAttestSuccessWithKindPod(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(kindPodListFilePath)
	s.addCgroupsResponse(cgPidInKindPodFilePath)
	s.requireAttestSuccess(p, testKindPodSelectors)
}

func (s *Suite) requireAttestSuccessWithCrioPod(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(crioPodListFilePath)
	s.addCgroupsResponse(cgPidInCrioPodFilePath)
	s.requireAttestSuccess(p, testCrioPodSelectors)
}

func (s *Suite) requireAttestFailWithDuplicateContainerID(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(crioPodListDuplicateContainerIDFilePath)
	s.addCgroupsResponse(cgPidInCrioPodFilePath)
	s.requireAttestFailure(p, codes.Internal, "two pods found with same container Id")
}

func (s *Suite) requireAttestSuccessWithPodSystemdCgroups(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(podListFilePath)
	s.addCgroupsResponse(cgSystemdPidInPodFilePath)
	s.requireAttestSuccess(p, testPodAndContainerSelectors)
}

func (s *Suite) requireAttestSuccessWithPodSystemdCrioCgroups(p workloadattestor.WorkloadAttestor) {
	s.addPodListResponse(crioPodListFilePath)
	s.addCgroupsResponse(cgSystemdCrioPidInPodFilePath)
	s.requireAttestSuccess(p, testCrioPodSelectors)
}

func TestGetContainerIDFromCGroups(t *testing.T) {
	makeCGroups := func(groupPaths []string) []cgroups.Cgroup {
		var out []cgroups.Cgroup
		for _, groupPath := range groupPaths {
			out = append(out, cgroups.Cgroup{
				GroupPath: groupPath,
			})
		}
		return out
	}

	for _, tt := range []struct {
		name              string
		cgroupPaths       []string
		expectPodUID      types.UID
		expectContainerID string
		expectCode        codes.Code
		expectMsg         string
	}{
		{
			name:              "no cgroups",
			cgroupPaths:       []string{},
			expectPodUID:      "",
			expectContainerID: "",
			expectCode:        codes.OK,
		},
		{
			name: "no container ID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
			},
			expectPodUID:      "",
			expectContainerID: "",
			expectCode:        codes.OK,
		},
		{
			name: "one container ID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
				"/kubepods/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			},
			expectPodUID:      "2c48913c-b29f-11e7-9350-020968147796",
			expectContainerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			expectCode:        codes.OK,
		},
		{
			name: "pod UID canonicalized",
			cgroupPaths: []string{
				"/user.slice",
				"/kubepods/pod2c48913c_b29f_11e7_9350_020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			},
			expectPodUID:      "2c48913c-b29f-11e7-9350-020968147796",
			expectContainerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			expectCode:        codes.OK,
		},
		{
			name: "cri-o",
			cgroupPaths: []string{
				"0::/../crio-45490e76e0878aaa4d9808f7d2eefba37f093c3efbba9838b6d8ab804d9bd814.scope",
			},
			expectPodUID:      "",
			expectContainerID: "45490e76e0878aaa4d9808f7d2eefba37f093c3efbba9838b6d8ab804d9bd814",
			expectCode:        codes.OK,
		},
		{
			name: "more than one container ID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
				"/kubepods/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
				"/kubepods/kubepods/besteffort/pod2c48913c-b29f-11e7-9350-020968147796/a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38",
			},
			expectPodUID:      "",
			expectContainerID: "",
			expectCode:        codes.FailedPrecondition,
			expectMsg:         "multiple container IDs found in cgroups (9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961, a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38)",
		},
		{
			name: "more than one pod UID in cgroups",
			cgroupPaths: []string{
				"/user.slice",
				"/kubepods/pod11111111-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
				"/kubepods/kubepods/besteffort/pod22222222-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			},
			expectPodUID:      "",
			expectContainerID: "",
			expectCode:        codes.FailedPrecondition,
			expectMsg:         "multiple pod UIDs found in cgroups (11111111-b29f-11e7-9350-020968147796, 22222222-b29f-11e7-9350-020968147796)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			podUID, containerID, err := getPodUIDAndContainerIDFromCGroups(makeCGroups(tt.cgroupPaths))
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				assert.Empty(t, containerID)
				return
			}
			assert.Equal(t, tt.expectPodUID, podUID)
			assert.Equal(t, tt.expectContainerID, containerID)
		})
	}
}

func TestGetPodUIDAndContainerIDFromCGroupPath(t *testing.T) {
	for _, tt := range []struct {
		name              string
		cgroupPath        string
		expectPodUID      types.UID
		expectContainerID string
	}{
		{
			name:              "without QOS",
			cgroupPath:        "/kubepods/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
			expectPodUID:      "2c48913c-b29f-11e7-9350-020968147796",
			expectContainerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
		},
		{
			name:              "with QOS",
			cgroupPath:        "/kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/34a2062fd26c805aa8cf814cdfe479322b791f80afb9ea4db02d50375df14b41",
			expectPodUID:      "2c48913c-b29f-11e7-9350-020968147796",
			expectContainerID: "34a2062fd26c805aa8cf814cdfe479322b791f80afb9ea4db02d50375df14b41",
		},
		{
			name:              "docker for desktop with QOS",
			cgroupPath:        "/kubepods/kubepods/besteffort/pod6bd2a4d3-a55a-4450-b6fd-2a7ecc72c904/a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38",
			expectPodUID:      "6bd2a4d3-a55a-4450-b6fd-2a7ecc72c904",
			expectContainerID: "a55d9ac3b312d8a2627824b6d6dd8af66fbec439bf4e0ec22d6d9945ad337a38",
		},
		{
			name:              "kind with QOS",
			cgroupPath:        "/docker/93529524695bb00d91c1f6dba692ea8d3550c3b94fb2463af7bc9ec82f992d26/kubepods/besteffort/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
			expectPodUID:      "a2830d0d-b0f0-4ff0-81b5-0ee4e299cf80",
			expectContainerID: "09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:              "systemd with QOS and container runtime",
			cgroupPath:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c48913c-b29f-11e7-9350-020968147796.slice/docker-9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961.scope",
			expectPodUID:      "2c48913c-b29f-11e7-9350-020968147796",
			expectContainerID: "9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961",
		},
		{
			name:              "from a different cgroup namespace",
			cgroupPath:        "/../../../burstable/pod095e82d2-713c-467a-a18a-cbb50a075296/6d1234da0f5aa7fa0ccae4c7d2d109929eb9a81694e6357bcd4547ab3985911b",
			expectPodUID:      "095e82d2-713c-467a-a18a-cbb50a075296",
			expectContainerID: "6d1234da0f5aa7fa0ccae4c7d2d109929eb9a81694e6357bcd4547ab3985911b",
		},
		{
			name:              "not kubepods",
			cgroupPath:        "/something/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
			expectPodUID:      "a2830d0d-b0f0-4ff0-81b5-0ee4e299cf80",
			expectContainerID: "09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:              "just pod uid and container",
			cgroupPath:        "/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
			expectPodUID:      "a2830d0d-b0f0-4ff0-81b5-0ee4e299cf80",
			expectContainerID: "09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:       "just container segment",
			cgroupPath: "/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:       "no container segment",
			cgroupPath: "/kubepods/poda2830d0d-b0f0-4ff0-81b5-0ee4e299cf80",
		},
		{
			name:       "no pod uid segment",
			cgroupPath: "/kubepods/09bc3d7ade839efec32b6bec4ec79d099027a668ddba043083ec21d3c3b8f1e6",
		},
		{
			name:              "cri-containerd",
			cgroupPath:        "/kubepods-besteffort-pod72f7f152_440c_66ac_9084_e0fc1d8a910c.slice:cri-containerd:b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2",
			expectPodUID:      "72f7f152-440c-66ac-9084-e0fc1d8a910c",
			expectContainerID: "b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2",
		},
		{
			name:              "cri-o in combination with kubeedge",
			cgroupPath:        "0::/../crio-45490e76e0878aaa4d9808f7d2eefba37f093c3efbba9838b6d8ab804d9bd814.scope",
			expectPodUID:      "",
			expectContainerID: "45490e76e0878aaa4d9808f7d2eefba37f093c3efbba9838b6d8ab804d9bd814",
		},
		{
			name:              "cri-o in combination with minikube",
			cgroupPath:        "9:devices:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod561fd272_d131_47ef_a01b_46a997a778f3.slice/crio-030ded69d4c98fcf69c988f75a5eb3a1b4357e1432bd5510c936a40d7e9a1198.scope",
			expectPodUID:      "561fd272-d131-47ef-a01b-46a997a778f3",
			expectContainerID: "030ded69d4c98fcf69c988f75a5eb3a1b4357e1432bd5510c936a40d7e9a1198",
		},
		{
			name:       "uid generateds by kubernetes",
			cgroupPath: "/kubepods/pod2732ca68f6358eba7703fb6f82a25c94",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("cgroup path=%s", tt.cgroupPath)
			podUID, containerID, ok := getPodUIDAndContainerIDFromCGroupPath(tt.cgroupPath)
			if tt.expectContainerID == "" {
				assert.False(t, ok)
				assert.Empty(t, podUID)
				assert.Empty(t, containerID)
				return
			}
			assert.True(t, ok)
			assert.Equal(t, tt.expectPodUID, podUID)
			assert.Equal(t, tt.expectContainerID, containerID)
		})
	}
}

type osConfig struct {
}

func (o *osConfig) getContainerHelper(p *Plugin) ContainerHelper {
	return &containerHelper{
		rootDir:                p.rootDir,
		useNewContainerLocator: true,
	}
}

func createOSConfig() *osConfig {
	return &osConfig{}
}
