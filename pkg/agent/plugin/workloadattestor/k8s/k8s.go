package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
	corev1 "k8s.io/api/core/v1"
)

const (
	selectorType             = "k8s"
	defaultMaxPollAttempts   = 5
	defaultPollRetryInterval = time.Millisecond * 300
	defaultSecureKubeletPort = 10250
	defaultKubeletCAPath     = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenPath         = "/run/secrets/kubernetes.io/serviceaccount/token"
	defaultNodeNameEnv       = "MY_NODE_NAME"
)

type containerLookup int

const (
	containerInPod = iota
	containerNotInPod
	containerMaybeInPod
)

var k8sErr = errs.Class("k8s")

// k8sHCLConfig holds the configuration parsed from HCL
type k8sHCLConfig struct {
	// KubeletReadOnlyPort defines the read only port for the kubelet
	// (typically 10255). This option is mutally exclusive with
	// KubeletSecurePort.
	KubeletReadOnlyPort int `hcl:"kubelet_read_only_port"`

	// KubeletSecurePort defines the secure port for the kubelet (typically
	// 10250). This option is mutually exclusive with KubeletReadOnlyPort.
	KubeletSecurePort int `hcl:"kubelet_secure_port"`

	// MaxPollAttempts is the maximum number of polling attempts for the
	// container hosting the workload process.
	MaxPollAttempts int `hcl:"max_poll_attempts"`

	// PollRetryInterval is the time in between polling attempts.
	PollRetryInterval string `hcl:"poll_retry_interval"`

	// KubeletCAPath is the path to the CA certificate for authenticating the
	// kubelet over the secure port. Required when using the secure port unless
	// SkipKubeletVerification is set. Defaults to the cluster trust bundle.
	KubeletCAPath string `hcl:"kubelet_ca_path"`

	// SkipKubeletVerification controls whether or not the plugin will
	// verify the certificate presented by the kubelet.
	SkipKubeletVerification bool `hcl:"skip_kubelet_verification"`

	// TokenPath is the path to the bearer token used to authenticate to the
	// secure port. Defaults to the default service account token path unless
	// PrivateKeyPath and CertificatePath are specified.
	TokenPath string `hcl:"token_path"`

	// CertificatePath is the path to a certificate key used for client
	// authentication with the kubelet. Must be used with PrivateKeyPath.
	CertificatePath string `hcl:"certificate_path"`

	// PrivateKeyPath is the path to a private key used for client
	// authentication with the kubelet. Must be used with CertificatePath.
	PrivateKeyPath string `hcl:"private_key_path"`

	// NodeNameEnv is the environment variable used to determine the node name
	// for contacting the kubelet. It defaults to "MY_NODE_NAME". If the
	// environment variable is not set, and NodeName is not specified, the
	// plugin will default to localhost (which requires host networking).
	NodeNameEnv string `hcl:"node_name_env"`

	// NodeName is the node name used when contacting the kubelet. If set, it
	// takes precedence over NodeNameEnv.
	NodeName string `hcl:"node_name"`
}

// k8sConfig holds the configuration distilled from HCL
type k8sConfig struct {
	Transport         *http.Transport
	Token             string
	KubeletURL        url.URL
	MaxPollAttempts   int
	PollRetryInterval time.Duration
}

type k8sPlugin struct {
	fs     cgroups.FileSystem
	clock  clock.Clock
	getenv func(string) string

	mu     sync.RWMutex
	config *k8sConfig
}

func New() *k8sPlugin {
	return &k8sPlugin{
		fs:     cgroups.OSFileSystem{},
		clock:  clock.New(),
		getenv: os.Getenv,
	}
}

func (p *k8sPlugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	containerID, err := p.getContainerIDFromCGroups(req.Pid)
	if err != nil {
		return nil, err
	}

	// Not a Kubernetes pod
	if containerID == "" {
		return &workloadattestor.AttestResponse{}, nil
	}

	// Poll pod information and search for the pod with the container. If
	// the pod is not found, and there are pods with containers that aren't
	// fully initialized, delay for a little bit and try again.
	for attempt := 1; ; attempt++ {
		list, err := getPodListFromKubelet(config.Transport, config.KubeletURL, config.Token)
		if err != nil {
			return nil, err
		}

		notAllContainersReady := false
		for _, item := range list.Items {
			status, lookup := lookUpContainerInPod(containerID, item.Status)
			switch lookup {
			case containerInPod:
				return &workloadattestor.AttestResponse{
					Selectors: getSelectorsFromPodInfo(&item, status),
				}, nil
			case containerMaybeInPod:
				notAllContainersReady = true
			case containerNotInPod:
			}
		}

		// if the container was not located and there were no pods with
		// uninitialized containers, then the search is over.
		if !notAllContainersReady || attempt >= config.MaxPollAttempts {
			log.Printf("container id %q not found (attempt %d of %d)", containerID, attempt, config.MaxPollAttempts)
			return nil, k8sErr.New("no selectors found")
		}

		// wait a bit for containers to initialize before trying again.
		log.Printf("container id %q not found (attempt %d of %d); trying again in %s", containerID, attempt, config.MaxPollAttempts, config.PollRetryInterval)

		select {
		case <-p.clock.After(config.PollRetryInterval):
		case <-ctx.Done():
			return nil, k8sErr.New("no selectors found: %v", ctx.Err())
		}
	}
}

func (p *k8sPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	// Parse HCL config payload into config struct
	config := new(k8sHCLConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, k8sErr.New("unable to decode configuration: %v", err)
	}

	// Determine max poll attempts with default
	maxPollAttempts := config.MaxPollAttempts
	if maxPollAttempts <= 0 {
		maxPollAttempts = defaultMaxPollAttempts
	}

	// Determine poll retry interval with default
	var pollRetryInterval time.Duration
	if config.PollRetryInterval != "" {
		pollRetryInterval, err = time.ParseDuration(config.PollRetryInterval)
		if err != nil {
			return nil, k8sErr.New("unable to parse poll retry interval: %v", err)
		}
	}
	if pollRetryInterval <= 0 {
		pollRetryInterval = defaultPollRetryInterval
	}

	// Determine which kubelet port to hit. Default to the secure port if none
	// is specified (this is backwards compatible because the read-only-port
	// config value has always been required, so it should already be set in
	// existing configurations that rely on it).
	if config.KubeletSecurePort > 0 && config.KubeletReadOnlyPort > 0 {
		return nil, k8sErr.New("cannot use both the read-only and secure port")
	}
	kubeletPort := config.KubeletReadOnlyPort
	scheme := "http"
	if kubeletPort <= 0 {
		kubeletPort = config.KubeletSecurePort
		scheme = "https"
	}
	if kubeletPort <= 0 {
		kubeletPort = defaultSecureKubeletPort
		scheme = "https"
	}

	// Determine the node name
	nodeName := p.getNodeName(config.NodeName, config.NodeNameEnv)

	// Configure the HTTP client
	var token string
	var tlsConfig *tls.Config
	if scheme == "https" {
		// Formulate the kubelet URL.
		tlsConfig = &tls.Config{}
		if config.SkipKubeletVerification {
			tlsConfig.InsecureSkipVerify = true
		} else {
			if nodeName == "" {
				// We're going to reach the kubelet via localhost but the
				// certificate has a DNS SAN with the hostname. Use the
				// hostname for validation.
				tlsConfig.ServerName, err = p.getHostname()
				if err != nil {
					return nil, err
				}
			}

			tlsConfig.RootCAs, err = p.loadKubeletCA(config.KubeletCAPath)
			if err != nil {
				return nil, err
			}
		}

		switch {
		case config.CertificatePath != "" && config.PrivateKeyPath != "":
			kp, err := p.loadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, *kp)
		case config.CertificatePath != "" && config.PrivateKeyPath == "":
			return nil, k8sErr.New("the private key path is required with the certificate path")
		case config.CertificatePath == "" && config.PrivateKeyPath != "":
			return nil, k8sErr.New("the certificate path is required with the private key path")
		case config.CertificatePath == "" && config.PrivateKeyPath == "":
			token, err = p.loadToken(config.TokenPath)
			if err != nil {
				return nil, err
			}
		}
	}

	kubeletHost := nodeName
	if kubeletHost == "" {
		kubeletHost = "127.0.0.1"
	}

	// Set the config
	p.setConfig(&k8sConfig{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Token:             token,
		MaxPollAttempts:   maxPollAttempts,
		PollRetryInterval: pollRetryInterval,
		KubeletURL: url.URL{
			Scheme: scheme,
			Host:   fmt.Sprintf("%s:%d", kubeletHost, kubeletPort),
		},
	})

	return &spi.ConfigureResponse{}, nil
}

func (*k8sPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *k8sPlugin) setConfig(config *k8sConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *k8sPlugin) getConfig() (*k8sConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, k8sErr.New("not configured")
	}
	return p.config, nil
}

func (p *k8sPlugin) getContainerIDFromCGroups(pid int32) (string, error) {
	cgroups, err := cgroups.GetCgroups(pid, p.fs)
	if err != nil {
		return "", k8sErr.Wrap(err)
	}

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
			return parts[4], nil
		}
	}

	return "", nil
}

func (p *k8sPlugin) getHostname() (string, error) {
	hostname := p.getenv("HOSTNAME")
	if hostname != "" {
		return hostname, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", k8sErr.New("unable to determine hostname: %v", err)
	}
	return hostname, nil
}

func (p *k8sPlugin) loadKubeletCA(path string) (*x509.CertPool, error) {
	if path == "" {
		path = defaultKubeletCAPath
	}
	caPEM, err := p.readFile(path)
	if err != nil {
		return nil, k8sErr.New("unable to load kubelet CA: %v", err)
	}
	certs, err := pemutil.ParseCertificates(caPEM)
	if err != nil {
		return nil, k8sErr.New("unable to parse kubelet CA: %v", err)
	}

	cas := x509.NewCertPool()
	for _, cert := range certs {
		cas.AddCert(cert)
	}
	return cas, nil
}

func (p *k8sPlugin) loadX509KeyPair(cert, key string) (*tls.Certificate, error) {
	certPEM, err := p.readFile(cert)
	if err != nil {
		return nil, k8sErr.New("unable to load certificate: %v", err)
	}
	keyPEM, err := p.readFile(key)
	if err != nil {
		return nil, k8sErr.New("unable to load private key: %v", err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, k8sErr.New("unable to load keypair: %v", err)
	}
	return &kp, nil
}

func (p *k8sPlugin) loadToken(path string) (string, error) {
	if path == "" {
		path = defaultTokenPath
	}
	token, err := p.readFile(path)
	if err != nil {
		return "", k8sErr.New("unable to load token: %v", err)
	}
	return strings.TrimSpace(string(token)), nil
}

// readFile reads the contents of a file through the filesystem interface
func (p *k8sPlugin) readFile(path string) ([]byte, error) {
	f, err := p.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

func (p *k8sPlugin) getNodeName(name string, env string) string {
	switch {
	case name != "":
		return name
	case env != "":
		return p.getenv(env)
	default:
		return p.getenv(defaultNodeNameEnv)
	}
}

func getPodListFromKubelet(tr *http.Transport, url url.URL, token string) (*corev1.PodList, error) {
	url.Path = "/pods"
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, k8sErr.New("unable to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, k8sErr.New("unable to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, k8sErr.New("unexpected status code on pods response: %d %s", resp.StatusCode, tryRead(resp.Body))
	}

	out := new(corev1.PodList)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, k8sErr.New("unable to decode kubelet response: %v", err)
	}

	return out, nil
}

func lookUpContainerInPod(containerID string, status corev1.PodStatus) (*corev1.ContainerStatus, containerLookup) {
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
			return &status, containerInPod
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
			return &status, containerInPod
		}
	}

	if notReady {
		return nil, containerMaybeInPod
	}

	return nil, containerNotInPod
}

func getSelectorsFromPodInfo(pod *corev1.Pod, status *corev1.ContainerStatus) []*common.Selector {
	selectors := []*common.Selector{
		makeSelector("sa:%s", pod.Spec.ServiceAccountName),
		makeSelector("ns:%s", pod.Namespace),
		makeSelector("node-name:%s", pod.Spec.NodeName),
		makeSelector("pod-uid:%s", pod.UID),
		makeSelector("container-name:%s", status.Name),
		makeSelector("container-image:%s", status.Image),
	}

	for k, v := range pod.Labels {
		selectors = append(selectors, makeSelector("pod-label:%s:%s", k, v))
	}
	for _, ownerReference := range pod.OwnerReferences {
		selectors = append(selectors, makeSelector("pod-owner:%s:%s", ownerReference.Kind, ownerReference.Name))
		selectors = append(selectors, makeSelector("pod-owner-uid:%s:%s", ownerReference.Kind, ownerReference.UID))
	}

	return selectors
}

func makeSelector(format string, args ...interface{}) *common.Selector {
	return &common.Selector{
		Type:  selectorType,
		Value: fmt.Sprintf(format, args...),
	}
}

func tryRead(r io.Reader) string {
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
