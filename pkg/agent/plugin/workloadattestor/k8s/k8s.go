package k8s

import (
	"bufio"
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
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
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

type k8sPlugin struct {
	kubeletReadOnlyPort int
	maxPollAttempts     int
	pollRetryInterval   time.Duration
	httpClient          httpClient
	fs                  fileSystem
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
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
	} `json:"spec"`
	Status podStatus `json:"status"`
}

type podList struct {
	Items []*podInfo `json:"items"`
}

type podStatus struct {
	InitContainerStatuses []struct {
		ContainerID string `json:"containerID"`
	} `json:"initContainerStatuses"`
	ContainerStatuses []struct {
		ContainerID string `json:"containerID"`
	} `json:"containerStatuses"`
}

const (
	selectorType string = "k8s"
)

func (p *k8sPlugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	resp := workloadattestor.AttestResponse{}

	cgroups, err := getCgroups(fmt.Sprintf("/proc/%v/cgroup", req.Pid), p.fs)
	if err != nil {
		return &resp, err
	}

	var containerID string
	for _, cgroup := range cgroups {
		// We are only interested in kube pods entries. Example entry:
		// 11:hugetlb:/kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
		if len(cgroup[2]) < 9 {
			continue
		}

		substring := cgroup[2][:9]
		if substring == "/kubepods" {
			parts := strings.Split(cgroup[2], "/")

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
		return &resp, nil
	}

	// Poll pod information and search for the pod with the container. If
	// the pod is not found, and there are pods with containers that aren't
	// fully initialized, delay for a little bit and try again.
	for attempt := 1; ; attempt++ {
		list, err := p.getPodListFromInsecureKubeletPort()
		if err != nil {
			return &resp, err
		}

		notAllContainersReady := false
		for _, item := range list.Items {
			switch lookUpContainerInPod(containerID, item.Status) {
			case containerInPod:
				resp.Selectors = getSelectorsFromPodInfo(item)
				return &resp, nil
			case containerMaybeInPod:
				notAllContainersReady = true
			case containerNotInPod:
			}
		}

		// if the container was not located and there were no pods with
		// uninitialized containers, then the search is over.
		if !notAllContainersReady || attempt >= p.maxPollAttempts {
			log.Printf("container id %q not found (attempt %d of %d)", containerID, attempt, p.maxPollAttempts)
			return &resp, fmt.Errorf("no selectors found")
		}

		// wait a bit for containers to initialize before trying again.
		log.Printf("container id %q not found (attempt %d of %d); trying again in %s", containerID, attempt, p.maxPollAttempts, p.pollRetryInterval)

		// TODO: bail early via context cancelation
		time.Sleep(p.pollRetryInterval)
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

func lookUpContainerInPod(containerID string, status podStatus) containerLookup {
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
			return containerInPod
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
			return containerInPod
		}
	}

	if notReady {
		return containerMaybeInPod
	}

	return containerNotInPod
}

func getCgroups(path string, fs fileSystem) (cgroups [][]string, err error) {
	// http://man7.org/linux/man-pages/man7/cgroups.7.html
	// https://www.kernel.org/doc/Documentation/cgroup-v2.txt

	file, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		token := scanner.Text()
		substrings := strings.SplitN(token, ":", 3)
		if len(substrings) < 3 {
			return cgroups, fmt.Errorf("cgroup entry contains %v colons, but expected at least two colons: %v", len(substrings), token)
		}
		cgroups = append(cgroups, substrings)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cgroups, err
}

func getSelectorsFromPodInfo(info *podInfo) []*common.Selector {
	return []*common.Selector{
		{Type: selectorType, Value: fmt.Sprintf("sa:%v", info.Spec.ServiceAccountName)},
		{Type: selectorType, Value: fmt.Sprintf("ns:%v", info.Metadata.Namespace)},
	}
}

func (p *k8sPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &k8sPluginConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	// set up defaults
	if config.MaxPollAttempts <= 0 {
		config.MaxPollAttempts = defaultMaxPollAttempts
	}

	var pollRetryInterval time.Duration
	if config.PollRetryInterval != "" {
		pollRetryInterval, err = time.ParseDuration(config.PollRetryInterval)
		if err != nil {
			return resp, err
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
		fs:         osFS{},
	}
}
