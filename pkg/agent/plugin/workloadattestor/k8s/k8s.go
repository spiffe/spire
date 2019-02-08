package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
)

const (
	defaultMaxPollAttempts   = 5
	defaultPollRetryInterval = time.Millisecond * 300
)

type containerLookup int

const (
	containerInPod = iota
	containerNotInPod
	containerMaybeInPod
)

var k8sErr = errs.Class("k8s")

type k8sPlugin struct {
	kubeletReadOnlyPort int
	maxPollAttempts     int
	pollRetryInterval   time.Duration
	httpClient          httpClient
	fs                  cgroups.FileSystem
	mtx                 *sync.RWMutex
}

type k8sPluginConfig struct {
	KubeletReadOnlyPort int    `hcl:"kubelet_read_only_port"`
	MaxPollAttempts     int    `hcl:"max_poll_attempts"`
	PollRetryInterval   string `hcl:"poll_retry_interval"`
}

type podInfo struct {
	// We only care about namespace, serviceAccountName and containerID
	Metadata struct {
		UID             string            `json:"uid"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
		Containers         []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"containers"`
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status podStatus `json:"status"`
}

type podList struct {
	Items []*podInfo `json:"items"`
}

type podStatus struct {
	InitContainerStatuses []struct {
		Name        string `json:"name"`
		ContainerID string `json:"containerID"`
	} `json:"initContainerStatuses"`
	ContainerStatuses []struct {
		Name        string `json:"name"`
		ContainerID string `json:"containerID"`
	} `json:"containerStatuses"`
}

const (
	selectorType string = "k8s"
)

func (p *k8sPlugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	cgroups, err := cgroups.GetCgroups(req.Pid, p.fs)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}

	var containerID string
	for _, cgroup := range cgroups {
		// We are only interested in kube pods entries. Example entry:
		// 11:hugetlb:/kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
		if len(cgroup.GroupPath) < 9 {
			continue
		}

		substring := cgroup.GroupPath[:9]
		if substring == "/kubepods" {
			parts := strings.Split(cgroup.GroupPath, "/")

			if len(parts) < 5 {
				log.Printf("Kube pod entry found, but without container id: %v", substring)
				continue
			}
			containerID = parts[4]
			break
		}
	}

	// Not a Kubernetes pod
	if containerID == "" {
		return &workloadattestor.AttestResponse{}, nil
	}

	// Poll pod information and search for the pod with the container. If
	// the pod is not found, and there are pods with containers that aren't
	// fully initialized, delay for a little bit and try again.
	for attempt := 1; ; attempt++ {
		list, err := p.getPodListFromInsecureKubeletPort()
		if err != nil {
			return nil, k8sErr.Wrap(err)
		}

		notAllContainersReady := false
		for _, item := range list.Items {
			name, lookup := lookUpContainerInPod(containerID, item.Status)
			switch lookup {
			case containerInPod:
				return &workloadattestor.AttestResponse{
					Selectors: getSelectorsFromPodInfo(item, name),
				}, nil
			case containerMaybeInPod:
				notAllContainersReady = true
			case containerNotInPod:
			}
		}

		// if the container was not located and there were no pods with
		// uninitialized containers, then the search is over.
		if !notAllContainersReady || attempt >= p.maxPollAttempts {
			log.Printf("container id %q not found (attempt %d of %d)", containerID, attempt, p.maxPollAttempts)
			return nil, k8sErr.New("no selectors found")
		}

		// wait a bit for containers to initialize before trying again.
		log.Printf("container id %q not found (attempt %d of %d); trying again in %s", containerID, attempt, p.maxPollAttempts, p.pollRetryInterval)

		select {
		case <-time.After(p.pollRetryInterval):
		case <-ctx.Done():
			return nil, k8sErr.New("no selectors found: %v", ctx.Err())
		}
	}
}

func (p *k8sPlugin) getPodListFromInsecureKubeletPort() (out *podList, err error) {
	httpResp, err := p.httpClient.Get(fmt.Sprintf("http://localhost:%d/pods", p.kubeletReadOnlyPort))
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", httpResp.StatusCode)
	}

	out = new(podList)
	if err := json.NewDecoder(httpResp.Body).Decode(out); err != nil {
		return nil, err
	}

	return out, nil
}

func lookUpContainerInPod(containerID string, status podStatus) (string, containerLookup) {
	notReady := false
	for _, status := range status.ContainerStatuses {
		// TODO: should we be keying off of the status or is the lack of a
		// container id sufficient to know the container is not ready?
		if status.ContainerID == "" {
			notReady = true
			continue
		}

		containerURL, err := url.Parse(status.ContainerID)
		if err != nil {
			log.Printf("malformed container id %q: %v", status.ContainerID, err)
			continue
		}

		if containerID == containerURL.Host {
			return status.Name, containerInPod
		}
	}

	for _, status := range status.InitContainerStatuses {
		// TODO: should we be keying off of the status or is the lack of a
		// container id sufficient to know the container is not ready?
		if status.ContainerID == "" {
			notReady = true
			continue
		}

		containerURL, err := url.Parse(status.ContainerID)
		if err != nil {
			log.Printf("malformed container id %q: %v", status.ContainerID, err)
			continue
		}

		if containerID == containerURL.Host {
			return status.Name, containerInPod
		}
	}

	if notReady {
		return "", containerMaybeInPod
	}

	return "", containerNotInPod
}

func getSelectorsFromPodInfo(info *podInfo, containerName string) []*common.Selector {
	selectors := []*common.Selector{
		makeSelector("sa:%s", info.Spec.ServiceAccountName),
		makeSelector("ns:%s", info.Metadata.Namespace),
		makeSelector("node-name:%s", info.Spec.NodeName),
		makeSelector("pod-uid:%s", info.Metadata.UID),
	}

	for k, v := range info.Metadata.Labels {
		selectors = append(selectors, makeSelector("pod-label:%s:%s", k, v))
	}
	for _, ownerReference := range info.Metadata.OwnerReferences {
		selectors = append(selectors, makeSelector("pod-owner-uid:%s:%s", ownerReference.Kind, ownerReference.UID))
		selectors = append(selectors, makeSelector("pod-owner-name:%s:%s", ownerReference.Kind, ownerReference.Name))
	}

	for _, container := range info.Spec.Containers {
		if container.Name != containerName {
			continue
		}

		selectors = append(selectors,
			makeSelector("container-name:%s", container.Name),
			makeSelector("container-image:%s", container.Image),
		)
		break
	}

	return selectors
}

func makeSelector(format string, args ...interface{}) *common.Selector {
	return &common.Selector{
		Type:  selectorType,
		Value: fmt.Sprintf(format, args...),
	}
}

func (p *k8sPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	// Parse HCL config payload into config struct
	config := new(k8sPluginConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, k8sErr.Wrap(err)
	}

	// set up defaults
	if config.MaxPollAttempts <= 0 {
		config.MaxPollAttempts = defaultMaxPollAttempts
	}

	var err error
	var pollRetryInterval time.Duration
	if config.PollRetryInterval != "" {
		pollRetryInterval, err = time.ParseDuration(config.PollRetryInterval)
		if err != nil {
			return nil, k8sErr.Wrap(err)
		}
	}
	if pollRetryInterval <= 0 {
		pollRetryInterval = defaultPollRetryInterval
	}

	// Set local vars from config struct
	p.kubeletReadOnlyPort = config.KubeletReadOnlyPort
	p.pollRetryInterval = pollRetryInterval
	p.maxPollAttempts = config.MaxPollAttempts
	return &spi.ConfigureResponse{}, nil
}

func (*k8sPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() *k8sPlugin {
	return &k8sPlugin{
		mtx:        &sync.RWMutex{},
		httpClient: &http.Client{},
		fs:         cgroups.OSFileSystem{},
	}
}
