package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
)

const (
	pluginName               = "k8s"
	defaultMaxPollAttempts   = 60
	defaultPollRetryInterval = time.Millisecond * 500
	defaultSecureKubeletPort = 10250
	defaultKubeletCAPath     = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenPath         = "/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // false positive
	defaultNodeNameEnv       = "MY_NODE_NAME"
	defaultReloadInterval    = time.Minute
)

type containerLookup int

const (
	containerInPod = iota
	containerNotInPod
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// HCLConfig holds the configuration parsed from HCL
type HCLConfig struct {
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

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	log    hclog.Logger
	fs     cgroups.FileSystem
	clock  clock.Clock
	getenv func(string) string

	mu     sync.RWMutex
	config *k8sConfig
}

func New() *Plugin {
	return &Plugin{
		fs:     cgroups.OSFileSystem{},
		clock:  clock.New(),
		getenv: os.Getenv,
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
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
		return &workloadattestorv1.AttestResponse{}, nil
	}

	log := p.log.With(telemetry.ContainerID, containerID)

	// Poll pod information and search for the pod with the container. If
	// the pod is not found then delay for a little bit and try again.
	for attempt := 1; ; attempt++ {
		log = log.With(telemetry.Attempt, attempt)

		list, err := config.Client.GetPodList()
		if err != nil {
			return nil, err
		}

		for _, item := range list.Items {
			item := item
			status, lookup := lookUpContainerInPod(containerID, item.Status)
			switch lookup {
			case containerInPod:
				return &workloadattestorv1.AttestResponse{
					SelectorValues: getSelectorValuesFromPodInfo(&item, status),
				}, nil
			case containerNotInPod:
			}
		}

		// if the container was not located after the maximum number of attempts then the search is over.
		if attempt >= config.MaxPollAttempts {
			log.Warn("Container id not found; giving up")
			return nil, status.Error(codes.DeadlineExceeded, "no selectors found after max poll attempts")
		}

		// wait a bit for containers to initialize before trying again.
		log.Warn("Container id not found", telemetry.RetryInterval, config.PollRetryInterval)

		select {
		case <-p.clock.After(config.PollRetryInterval):
		case <-ctx.Done():
			return nil, status.Errorf(codes.Canceled, "no selectors found: %v", ctx.Err())
		}
	}
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	// Parse HCL config payload into config struct
	config := new(HCLConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
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
			return nil, status.Errorf(codes.InvalidArgument, "unable to parse poll retry interval: %v", err)
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
			return nil, status.Errorf(codes.InvalidArgument, "unable to parse reload interval: %v", err)
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
		return nil, status.Error(codes.InvalidArgument, "cannot use both the read-only and secure port")
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
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) setConfig(config *k8sConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *Plugin) getConfig() (*k8sConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	if err := p.reloadKubeletClient(p.config); err != nil {
		p.log.Warn("Unable to load kubelet client", "err", err)
	}
	return p.config, nil
}

func (p *Plugin) getContainerIDFromCGroups(pid int32) (string, error) {
	cgroups, err := cgroups.GetCgroups(pid, p.fs)
	if err != nil {
		return "", status.Errorf(codes.Internal, "unable to obtain cgroups: %v", err)
	}

	return getContainerIDFromCGroups(cgroups)
}

func (p *Plugin) reloadKubeletClient(config *k8sConfig) (err error) {
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
		InsecureSkipVerify: config.SkipKubeletVerification, //nolint: gosec // intentionally configurable
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
		return status.Error(codes.InvalidArgument, "the private key path is required with the certificate path")
	case config.CertificatePath == "" && config.PrivateKeyPath != "":
		return status.Error(codes.InvalidArgument, "the certificate path is required with the private key path")
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

func (p *Plugin) loadKubeletCA(path string) (*x509.CertPool, error) {
	if path == "" {
		path = defaultKubeletCAPath
	}
	caPEM, err := p.readFile(path)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to load kubelet CA: %v", err)
	}
	certs, err := pemutil.ParseCertificates(caPEM)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse kubelet CA: %v", err)
	}

	return newCertPool(certs), nil
}

func (p *Plugin) loadX509KeyPair(cert, key string) (*tls.Certificate, error) {
	certPEM, err := p.readFile(cert)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to load certificate: %v", err)
	}
	keyPEM, err := p.readFile(key)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to load private key: %v", err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to load keypair: %v", err)
	}
	return &kp, nil
}

func (p *Plugin) loadToken(path string) (string, error) {
	if path == "" {
		path = defaultTokenPath
	}
	token, err := p.readFile(path)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "unable to load token: %v", err)
	}
	return strings.TrimSpace(string(token)), nil
}

// readFile reads the contents of a file through the filesystem interface
func (p *Plugin) readFile(path string) ([]byte, error) {
	f, err := p.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (p *Plugin) getNodeName(name string, env string) string {
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
		return nil, status.Errorf(codes.Internal, "unable to create request: %v", err)
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
		return nil, status.Errorf(codes.Internal, "unable to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "unexpected status code on pods response: %d %s", resp.StatusCode, tryRead(resp.Body))
	}

	out := new(corev1.PodList)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to decode kubelet response: %v", err)
	}

	return out, nil
}

func getContainerIDFromCGroups(cgroups []cgroups.Cgroup) (string, error) {
	var containerID string
	for _, cgroup := range cgroups {
		candidate, ok := getContainerIDFromCGroupPath(cgroup.GroupPath)
		switch {
		case !ok:
			// Cgroup did not contain a container ID.
			continue
		case containerID == "":
			// This is the first container ID found so far.
			containerID = candidate
		case containerID != candidate:
			// More than one container ID found in the cgroups.
			return "", status.Errorf(codes.FailedPrecondition, "multiple container IDs found in cgroups (%s, %s)",
				containerID, candidate)
		}
	}

	return containerID, nil
}

// containerIDRe is the regex used to parse out the container ID from a cgroup
// name. It assumes that any ".scope" suffix has been trimmed off beforehand.
var containerIDRe = regexp.MustCompile(`` +
	// "kubepods" surrounded by punctuation
	`[[:punct:]]kubepods[[:punct:]]` +
	// zero or more punctuation separated "segments" (e.g. "burstable-")
	`(?:[[:^punct:]]+[[:punct:]])*` +
	// "pod"-prefixed Pod UUID (with punctuation separated groups) followed by punctuation
	`pod[[:xdigit:]]{8}[[:punct:]][[:xdigit:]]{4}[[:punct:]][[:xdigit:]]{4}[[:punct:]][[:xdigit:]]{4}[[:punct:]][[:xdigit:]]{12}[[:punct:]]` +
	// zero or more punctuation separated "segments" (e.g. "docker-")
	`(?:[[:^punct:]]+[[:punct:]])*` +
	// non-punctuation end of string, i.e., the container ID
	`([[:^punct:]]+)$`)

func getContainerIDFromCGroupPath(cgroupPath string) (string, bool) {
	// We are only interested in kube pods entries, for example:
	// - /kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
	// - /docker/8d461fa5765781bcf5f7eb192f101bc3103d4b932e26236f43feecfa20664f96/kubepods/besteffort/poddaa5c7ee-3484-4533-af39-3591564fd03e/aff34703e5e1f89443e9a1bffcc80f43f74d4808a2dd22c8f88c08547b323934
	// - /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c48913c-b29f-11e7-9350-020968147796.slice/docker-9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961.scope
	// - /kubepods-besteffort-pod72f7f152_440c_66ac_9084_e0fc1d8a910c.slice:cri-containerd:b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2"

	// First trim off any .scope suffix. This allows for a cleaner regex since
	// we don't have to muck with greediness. TrimSuffix is no-copy so this
	// is cheap.
	cgroupPath = strings.TrimSuffix(cgroupPath, ".scope")

	matches := containerIDRe.FindStringSubmatch(cgroupPath)
	if matches != nil {
		return matches[1], true
	}
	return "", false
}

func lookUpContainerInPod(containerID string, status corev1.PodStatus) (*corev1.ContainerStatus, containerLookup) {
	for _, status := range status.ContainerStatuses {
		// TODO: should we be keying off of the status or is the lack of a
		// container id sufficient to know the container is not ready?
		if status.ContainerID == "" {
			continue
		}

		containerURL, err := url.Parse(status.ContainerID)
		if err != nil {
			log.Printf("Malformed container id %q: %v", status.ContainerID, err)
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
			continue
		}

		containerURL, err := url.Parse(status.ContainerID)
		if err != nil {
			log.Printf("Malformed container id %q: %v", status.ContainerID, err)
			continue
		}

		if containerID == containerURL.Host {
			return &status, containerInPod
		}
	}

	return nil, containerNotInPod
}

func getPodImageIdentifiers(containerStatusArray []corev1.ContainerStatus) map[string]bool {
	// Map is used purely to exclude duplicate selectors, value is unused.
	podImages := make(map[string]bool)
	// Note that for each pod image we generate *2* matching selectors.
	// This is to support matching against ImageID, which has a SHA
	// docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb
	// as well as
	// docker.io/envoyproxy/envoy-alpine:v1.16.0, which does not,
	// while also maintaining backwards compatibility and allowing for dynamic workload registration (k8s operator)
	// when the SHA is not yet known (e.g. before the image pull is initiated at workload creation time)
	// More info here: https://github.com/spiffe/spire/issues/2026
	for _, status := range containerStatusArray {
		podImages[status.ImageID] = true
		podImages[status.Image] = true
	}
	return podImages
}

func getSelectorValuesFromPodInfo(pod *corev1.Pod, status *corev1.ContainerStatus) []string {
	podImageIdentifiers := getPodImageIdentifiers(pod.Status.ContainerStatuses)
	podInitImageIdentifiers := getPodImageIdentifiers(pod.Status.InitContainerStatuses)
	containerImageIdentifiers := getPodImageIdentifiers([]corev1.ContainerStatus{*status})

	selectorValues := []string{
		fmt.Sprintf("sa:%s", pod.Spec.ServiceAccountName),
		fmt.Sprintf("ns:%s", pod.Namespace),
		fmt.Sprintf("node-name:%s", pod.Spec.NodeName),
		fmt.Sprintf("pod-uid:%s", pod.UID),
		fmt.Sprintf("pod-name:%s", pod.Name),
		fmt.Sprintf("container-name:%s", status.Name),
		fmt.Sprintf("pod-image-count:%s", strconv.Itoa(len(pod.Status.ContainerStatuses))),
		fmt.Sprintf("pod-init-image-count:%s", strconv.Itoa(len(pod.Status.InitContainerStatuses))),
	}

	for containerImage := range containerImageIdentifiers {
		selectorValues = append(selectorValues, fmt.Sprintf("container-image:%s", containerImage))
	}
	for podImage := range podImageIdentifiers {
		selectorValues = append(selectorValues, fmt.Sprintf("pod-image:%s", podImage))
	}
	for podInitImage := range podInitImageIdentifiers {
		selectorValues = append(selectorValues, fmt.Sprintf("pod-init-image:%s", podInitImage))
	}

	for k, v := range pod.Labels {
		selectorValues = append(selectorValues, fmt.Sprintf("pod-label:%s:%s", k, v))
	}
	for _, ownerReference := range pod.OwnerReferences {
		selectorValues = append(selectorValues, fmt.Sprintf("pod-owner:%s:%s", ownerReference.Kind, ownerReference.Name))
		selectorValues = append(selectorValues, fmt.Sprintf("pod-owner-uid:%s:%s", ownerReference.Kind, ownerReference.UID))
	}

	return selectorValues
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
