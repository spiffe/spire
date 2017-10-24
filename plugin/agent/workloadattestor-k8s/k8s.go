package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

type k8sPlugin struct {
	kubeletReadOnlyPort int
	httpClient          httpClient
	fs                  fileSystem
	mtx                 *sync.RWMutex
}

type k8sPluginConfig struct {
	KubeletReadOnlyPort int `hcl:"kubelet_read_only_port"`
}

type podList struct {
	// We only care about namespace, serviceAccountName and containerID
	Metadata struct {
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

const (
	selectorType string = "k8s"
)

func (p *k8sPlugin) Attest(req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	log.Printf("Attesting PID: %v", req.Pid)
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

	if containerID == "" {
		log.Printf("No kube pod entry found in /proc/%v/cgroup", req.Pid)
		return &resp, nil
	}

	httpResp, err := p.httpClient.Get(fmt.Sprintf("http://localhost:%v/pods", p.kubeletReadOnlyPort))
	if err != nil {
		return &resp, err
	}
	defer httpResp.Body.Close()
	respBytes, err := ioutil.ReadAll(httpResp.Body)

	var podInfo *podList
	err = json.Unmarshal(respBytes, &podInfo)
	if err != nil {
		return &resp, err
	}

	for _, item := range podInfo.Items {
		for _, status := range item.Status.ContainerStatuses {
			containerURL, err := url.Parse(status.ContainerID)
			if err != nil {
				return &resp, err
			}

			if containerID == containerURL.Host {
				resp.Selectors = append(resp.Selectors, &common.Selector{Type: selectorType, Value: fmt.Sprintf("sa:%v", item.Spec.ServiceAccountName)})
				resp.Selectors = append(resp.Selectors, &common.Selector{Type: selectorType, Value: fmt.Sprintf("ns:%v", item.Metadata.Namespace)})
				log.Printf("Selectors found: %v", resp.Selectors)
				return &resp, nil
			}
		}
	}

	log.Print("No selectors found")
	return &resp, nil
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

	return cgroups, err
}

func (p *k8sPlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
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

	// Set local vars from config struct
	p.kubeletReadOnlyPort = config.KubeletReadOnlyPort
	return &spi.ConfigureResponse{}, nil
}

func (*k8sPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New(client httpClient, fs fileSystem) workloadattestor.WorkloadAttestor {
	return &k8sPlugin{
		mtx:        &sync.RWMutex{},
		httpClient: client,
		fs:         fs,
	}
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: workloadattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"wla_k8s": workloadattestor.WorkloadAttestorPlugin{WorkloadAttestorImpl: New(&http.Client{}, osFS{})},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
