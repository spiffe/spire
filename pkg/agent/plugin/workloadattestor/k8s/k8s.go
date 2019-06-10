package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/agent/workloadattestor"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	corev1 "k8s.io/api/core/v1"
)

const (
	pluginName               = "k8s"
	defaultMaxPollAttempts   = 5
	defaultPollRetryInterval = time.Millisecond * 300
	defaultSecureKubeletPort = 10250
	defaultKubeletCAPath     = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenPath         = "/run/secrets/kubernetes.io/serviceaccount/token"
	defaultNodeNameEnv       = "MY_NODE_NAME"
	defaultReloadInterval    = time.Minute
)

type containerLookup int

const (
	containerInPod = iota
	containerNotInPod
	containerMaybeInPod
)

var k8sErr = errs.Class("k8s")

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *K8SPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, workloadattestor.PluginServer(p))
}

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

	// ReloadInterval controls how often TLS and token configuration is loaded
	// from the disk.
	ReloadInterval string `hcl:"reload_interval"`
}

// k8sConfig holds the configuration distilled from HCL
type k8sConfig struct {
	Secure                  bool
	Port                    int
	MaxPollAttempts         int
	PollRetryInterval       time.Duration
	SkipKubeletVerification bool
	TokenPath               string
	CertificatePath         string
	PrivateKeyPath          string
	KubeletCAPath           string
	NodeName                string
	ReloadInterval          time.Duration

	Client     *kubeletClient
	LastReload time.Time
}

type K8SPlugin struct {
	log    hclog.Logger
	fs     cgroups.FileSystem
	clock  clock.Clock
	getenv func(string) string

	mu     sync.RWMutex
	config *k8sConfig
}

func New() *K8SPlugin {
	return &K8SPlugin{
		fs:     cgroups.OSFileSystem{},
		clock:  clock.New(),
		getenv: os.Getenv,
	}
}

func (p *K8SPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *K8SPlugin) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
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
		list, err := config.Client.GetPodList()
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
			p.log.Warn("container id not found; giving up", "container_id", containerID, "attempt", attempt)
			return nil, k8sErr.New("no selectors found")
		}

		// wait a bit for containers to initialize before trying again.
		p.log.Warn("container id not found", "container_id", containerID, "attempt", attempt, "retry_interval", config.PollRetryInterval)

		select {
		case <-p.clock.After(config.PollRetryInterval):
		case <-ctx.Done():
			return nil, k8sErr.New("no selectors found: %v", ctx.Err())
		}
	}
}

func (p *K8SPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
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

	// Determine reload interval
	var reloadInterval time.Duration
	if config.ReloadInterval != "" {
		reloadInterval, err = time.ParseDuration(config.ReloadInterval)
		if err != nil {
			return nil, k8sErr.New("unable to parse reload interval: %v", err)
		}
	}
	if reloadInterval <= 0 {
		reloadInterval = defaultReloadInterval
	}

	// Determine which kubelet port to hit. Default to the secure port if none
	// is specified (this is backwards compatible because the read-only-port
	// config value has always been required, so it should already be set in
	// existing configurations that rely on it).
	if config.KubeletSecurePort > 0 && config.KubeletReadOnlyPort > 0 {
		return nil, k8sErr.New("cannot use both the read-only and secure port")
	}
	port := config.KubeletReadOnlyPort
	secure := false
	if port <= 0 {
		port = config.KubeletSecurePort
		secure = true
	}
	if port <= 0 {
		port = defaultSecureKubeletPort
		secure = true
	}

	// Determine the node name
	nodeName := p.getNodeName(config.NodeName, config.NodeNameEnv)

	// Configure the kubelet client
	c := &k8sConfig{
		Secure:                  secure,
		Port:                    port,
		MaxPollAttempts:         maxPollAttempts,
		PollRetryInterval:       pollRetryInterval,
		SkipKubeletVerification: config.SkipKubeletVerification,
		TokenPath:               config.TokenPath,
		CertificatePath:         config.CertificatePath,
		PrivateKeyPath:          config.PrivateKeyPath,
		KubeletCAPath:           config.KubeletCAPath,
		NodeName:                nodeName,
		ReloadInterval:          reloadInterval,
	}
	if err := p.reloadKubeletClient(c); err != nil {
		return nil, err
	}

	// Set the config
	p.setConfig(c)
	return &spi.ConfigureResponse{}, nil
}

func (*K8SPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *K8SPlugin) setConfig(config *k8sConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *K8SPlugin) getConfig() (*k8sConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil, k8sErr.New("not configured")
	}
	if err := p.reloadKubeletClient(p.config); err != nil {
		// TODO: log error
	}
	return p.config, nil
}

func (p *K8SPlugin) getContainerIDFromCGroups(pid int32) (string, error) {
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
			id := strings.TrimSuffix(parts[4], ".scope")
			// Trim the id of any container runtime prefixes.  Ex "docker-" or "crio-"
			dash := strings.Index(id, "-")
			if dash > -1 {
				id = id[dash+1:]
			}
			return id, nil
		}
	}

	return "", nil
}

func (p *K8SPlugin) reloadKubeletClient(config *k8sConfig) (err error) {
	// The insecure client only needs to be loaded once.
	if !config.Secure {
		if config.Client == nil {
			config.Client = &kubeletClient{
				URL: url.URL{
					Scheme: "http",
					Host:   fmt.Sprintf("127.0.0.1:%d", config.Port),
				},
			}
		}
		return nil
	}

	// Is the client still fresh?
	if config.Client != nil && p.clock.Now().Sub(config.LastReload) < config.ReloadInterval {
		return nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipKubeletVerification,
	}

	var rootCAs *x509.CertPool
	if !config.SkipKubeletVerification {
		rootCAs, err = p.loadKubeletCA(config.KubeletCAPath)
		if err != nil {
			return err
		}
	}

	switch {
	case config.SkipKubeletVerification:

	// When contacting the kubelet over localhost, skip the hostname validation.
	// Unfortunately Go does not make this straightforward. We disable
	// verification but supply a VerifyPeerCertificate that will be called
	// with the raw kubelet certs that we can verify directly.
	case config.NodeName == "":
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			var certs []*x509.Certificate
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
			}

			// this is improbable.
			if len(certs) == 0 {
				return errors.New("no certs presented by kubelet")
			}

			_, err := certs[0].Verify(x509.VerifyOptions{
				Roots:         rootCAs,
				Intermediates: newCertPool(certs[1:]),
			})
			return err
		}
	default:
		tlsConfig.RootCAs = rootCAs
	}

	var token string
	switch {
	case config.CertificatePath != "" && config.PrivateKeyPath != "":
		kp, err := p.loadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *kp)
	case config.CertificatePath != "" && config.PrivateKeyPath == "":
		return k8sErr.New("the private key path is required with the certificate path")
	case config.CertificatePath == "" && config.PrivateKeyPath != "":
		return k8sErr.New("the certificate path is required with the private key path")
	case config.CertificatePath == "" && config.PrivateKeyPath == "":
		token, err = p.loadToken(config.TokenPath)
		if err != nil {
			return err
		}
	}

	host := config.NodeName
	if host == "" {
		host = "127.0.0.1"
	}

	config.Client = &kubeletClient{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		URL: url.URL{
			Scheme: "https",
			Host:   fmt.Sprintf("%s:%d", host, config.Port),
		},
		Token: token,
	}
	config.LastReload = p.clock.Now()
	return nil
}

func (p *K8SPlugin) loadKubeletCA(path string) (*x509.CertPool, error) {
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

	return newCertPool(certs), nil
}

func (p *K8SPlugin) loadX509KeyPair(cert, key string) (*tls.Certificate, error) {
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

func (p *K8SPlugin) loadToken(path string) (string, error) {
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
func (p *K8SPlugin) readFile(path string) ([]byte, error) {
	f, err := p.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

func (p *K8SPlugin) getNodeName(name string, env string) string {
	switch {
	case name != "":
		return name
	case env != "":
		return p.getenv(env)
	default:
		return p.getenv(defaultNodeNameEnv)
	}
}

type kubeletClient struct {
	Transport *http.Transport
	URL       url.URL
	Token     string
}

func (c *kubeletClient) GetPodList() (*corev1.PodList, error) {
	url := c.URL
	url.Path = "/pods"
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, k8sErr.New("unable to create request: %v", err)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	client := &http.Client{}
	if c.Transport != nil {
		client.Transport = c.Transport
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
		makeSelector("pod-name:%s", pod.Name),
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
		Type:  pluginName,
		Value: fmt.Sprintf(format, args...),
	}
}

func tryRead(r io.Reader) string {
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func newCertPool(certs []*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}
