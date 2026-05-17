package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	hcltoken "github.com/hashicorp/hcl/hcl/token"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/reference"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/common/sigstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/valyala/fastjson"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var k8sScheme = runtime.NewScheme()

func init() {
	if err := corev1.AddToScheme(k8sScheme); err != nil {
		panic(fmt.Sprintf("failed to register corev1 scheme: %v", err))
	}
}

const (
	pluginName               = "k8s"
	defaultMaxPollAttempts   = 60
	defaultPollRetryInterval = time.Millisecond * 500
	defaultSecureKubeletPort = 10250
	defaultKubeletCAPath     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenPath         = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // false positive
	defaultNodeNameEnv       = "MY_NODE_NAME"
	defaultReloadInterval    = time.Minute
)

var (
	ErrNamespaceRequired = status.Error(codes.InvalidArgument, "namespace is required when name is set for a namespaced resource")
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
	// (typically 10255). This option is mutually exclusive with
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

	// SkipKubeletVerification controls whether the plugin will
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

	// UseAnonymousAuthentication controls whether communication to the
	// kubelet over the secure port is unauthenticated. This option is mutually
	// exclusive with other authentication configuration fields TokenPath,
	// CertificatePath, and PrivateKeyPath.
	UseAnonymousAuthentication bool `hcl:"use_anonymous_authentication"`

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

	// DisableContainerSelectors disables the gathering of selectors for the
	// specific container running the workload. This allows attestation to
	// succeed with just pod related selectors when the workload pod is known
	// but the container may not be in a ready state at the time of attestation
	// (e.g. when a postStart hook has yet to complete).
	DisableContainerSelectors bool `hcl:"disable_container_selectors"`

	// UseNewContainerLocator, if true, uses the new container locator
	// mechanism instead of the legacy cgroup matchers. Defaults to true if
	// unset. This configurable will be removed in a future release.
	UseNewContainerLocator *bool `hcl:"use_new_container_locator"`

	// VerboseContainerLocatorLogs, if true, dumps extra information to the log
	// about mountinfo and cgroup information used to locate the container.
	VerboseContainerLocatorLogs bool `hcl:"verbose_container_locator_logs"`

	// Sigstore contains sigstore specific configs.
	Sigstore *sigstore.HCLConfig `hcl:"sigstore,omitempty"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

// k8sConfig holds the configuration distilled from HCL
type k8sConfig struct {
	Secure                     bool
	Port                       int
	MaxPollAttempts            int
	PollRetryInterval          time.Duration
	SkipKubeletVerification    bool
	TokenPath                  string
	CertificatePath            string
	PrivateKeyPath             string
	UseAnonymousAuthentication bool
	KubeletCAPath              string
	NodeName                   string
	ReloadInterval             time.Duration
	DisableContainerSelectors  bool
	ContainerHelper            ContainerHelper
	sigstoreConfig             *sigstore.Config

	Client     *kubeletClient
	LastReload time.Time
}

func (p *Plugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *k8sConfig {
	// Parse HCL config payload into config struct
	newConfig := new(HCLConfig)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	pluginconf.ReportUnusedKeys(status, newConfig.UnusedKeyPositions)

	// Determine max poll attempts with default
	maxPollAttempts := newConfig.MaxPollAttempts
	if maxPollAttempts <= 0 {
		maxPollAttempts = defaultMaxPollAttempts
	}

	// Determine poll retry interval with default
	var pollRetryInterval time.Duration
	var err error
	if newConfig.PollRetryInterval != "" {
		pollRetryInterval, err = time.ParseDuration(newConfig.PollRetryInterval)
		if err != nil {
			status.ReportErrorf("unable to parse poll retry interval: %v", err)
		}
	}
	if pollRetryInterval <= 0 {
		pollRetryInterval = defaultPollRetryInterval
	}

	// Determine reload interval
	var reloadInterval time.Duration
	if newConfig.ReloadInterval != "" {
		reloadInterval, err = time.ParseDuration(newConfig.ReloadInterval)
		if err != nil {
			status.ReportErrorf("unable to parse reload interval: %v", err)
		}
	}
	if reloadInterval <= 0 {
		reloadInterval = defaultReloadInterval
	}

	// Determine which kubelet port to hit. Default to the secure port if none
	// is specified (this is backwards compatible because the read-only-port
	// config value has always been required, so it should already be set in
	// existing configurations that rely on it).
	if newConfig.KubeletSecurePort > 0 && newConfig.KubeletReadOnlyPort > 0 {
		status.ReportError("cannot use both the read-only and secure port")
	}

	port := newConfig.KubeletReadOnlyPort
	secure := false
	if port <= 0 {
		port = newConfig.KubeletSecurePort
		secure = true
	}
	if port <= 0 {
		port = defaultSecureKubeletPort
		secure = true
	}

	containerHelper := createHelper(p)
	if err := containerHelper.Configure(newConfig, p.log); err != nil {
		status.ReportError(err.Error())
	}

	// Determine the node name
	nodeName := p.getNodeName(newConfig.NodeName, newConfig.NodeNameEnv)

	var sigstoreConfig *sigstore.Config
	if newConfig.Sigstore != nil {
		sigstoreConfig = sigstore.NewConfigFromHCL(newConfig.Sigstore, p.log)
	}

	// return the kubelet client
	return &k8sConfig{
		Secure:                     secure,
		Port:                       port,
		MaxPollAttempts:            maxPollAttempts,
		PollRetryInterval:          pollRetryInterval,
		SkipKubeletVerification:    newConfig.SkipKubeletVerification,
		TokenPath:                  newConfig.TokenPath,
		CertificatePath:            newConfig.CertificatePath,
		PrivateKeyPath:             newConfig.PrivateKeyPath,
		UseAnonymousAuthentication: newConfig.UseAnonymousAuthentication,
		KubeletCAPath:              newConfig.KubeletCAPath,
		NodeName:                   nodeName,
		ReloadInterval:             reloadInterval,
		DisableContainerSelectors:  newConfig.DisableContainerSelectors,
		ContainerHelper:            containerHelper,
		sigstoreConfig:             sigstoreConfig,
	}
}

type ContainerHelper interface {
	Configure(config *HCLConfig, log hclog.Logger) error
	GetPodUIDAndContainerID(pID int32, log hclog.Logger) (types.UID, string, error)
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	log     hclog.Logger
	clock   clock.Clock
	rootDir string
	getenv  func(string) string

	mu               sync.RWMutex
	config           *k8sConfig
	containerHelper  ContainerHelper
	sigstoreVerifier sigstore.Verifier

	// kubeClient is write-once-read-many. It carries its own RESTMapper
	// internally (accessible via kubeClient.RESTMapper()), so we don't keep
	// a separate field for it. Guarded by a dedicated mutex so the apiserver
	// discovery handshake on first use does not block readers of unrelated
	// plugin state.
	kubeMu     sync.RWMutex
	kubeClient client.Client

	cachedPodList           map[string]*fastjson.Value
	cachedPodListValidUntil time.Time
	singleflight            singleflight.Group
}

func New() *Plugin {
	return &Plugin{
		clock:  clock.New(),
		getenv: os.Getenv,
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest implements the legacy PID-only RPC for callers that haven't moved
// to AttestReference. The shared attestByPID helper produces an
// AttestReferenceResponse; we reuse its SelectorValues since the response
// shapes are identical aside from the type name.
func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	resp, err := p.attestByPID(ctx, req.Pid)
	if err != nil {
		return nil, err
	}
	return &workloadattestorv1.AttestResponse{SelectorValues: resp.SelectorValues}, nil
}

func (p *Plugin) AttestReference(ctx context.Context, req *workloadattestorv1.AttestReferenceRequest) (*workloadattestorv1.AttestReferenceResponse, error) {
	switch req.Reference.TypeUrl {
	case "type.googleapis.com/spiffe.reference.WorkloadPIDReference":
		var pidRef reference.WorkloadPIDReference
		if err := req.Reference.UnmarshalTo(&pidRef); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unable to unmarshal PID reference: %v", err)
		}
		return p.attestByPID(ctx, pidRef.Pid)
	case "type.googleapis.com/spiffe.reference.KubernetesObjectReference":
		var objRef reference.KubernetesObjectReference
		// Parse and validate reference.
		if err := req.Reference.UnmarshalTo(&objRef); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unable to unmarshal object reference: %v", err)
		}
		objType := objRef.GetType()
		if objType == nil {
			return nil, status.Error(codes.InvalidArgument, "object reference is missing type")
		}
		if objType.Plural == "" {
			return nil, status.Error(codes.InvalidArgument, "object reference type is missing plural")
		}
		if objType.Group == "" {
			return nil, status.Error(codes.InvalidArgument, "object reference type is missing group")
		}
		objKey := objRef.GetKey()
		if objKey == nil && objRef.GetUid() == "" {
			return nil, status.Error(codes.InvalidArgument, "object reference is missing key and UID")
		}
		if objKey != nil {
			name := objKey.GetName()
			if name == "" {
				return nil, status.Error(codes.InvalidArgument, "object reference key is missing name")
			}
		}

		// Attest.
		switch {
		// We have special handling for pods.
		case objType.Plural == "pods" && objType.Group == "core":
			return p.attestByPodReference(ctx, &objRef)
		// General case for any other Kubernetes object reference.
		default:
			return p.attestByObjectReference(ctx, &objRef)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported reference type: %s", req.Reference.TypeUrl)
	}
}

func (p *Plugin) attestByPID(ctx context.Context, pid int32) (*workloadattestorv1.AttestReferenceResponse, error) {
	config, containerHelper, sigstoreVerifier, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	podUID, containerID, err := containerHelper.GetPodUIDAndContainerID(pid, p.log)
	if err != nil {
		return nil, err
	}
	podKnown := podUID != ""

	// Not a Kubernetes pod
	if containerID == "" {
		return &workloadattestorv1.AttestReferenceResponse{}, nil
	}

	log := p.log.With(
		telemetry.PodUID, podUID,
		telemetry.ContainerID, containerID,
	)

	// Poll pod information and search for the pod with the container. If
	// the pod is not found then delay for a little bit and try again.
	var scratch []byte
	for attempt := 1; ; attempt++ {
		log = log.With(telemetry.Attempt, attempt)

		podList, err := p.getPodList(ctx, config.Client, config.PollRetryInterval/2)
		if err != nil {
			return nil, err
		}

		var attestResponse *workloadattestorv1.AttestReferenceResponse
		for podKey, podValue := range podList {
			if podKnown {
				if podKey != string(podUID) {
					// The pod holding the container is known. Skip unrelated pods.
					continue
				}
			}

			// Reduce allocations by dumping to the same backing array on
			// each iteration in order to parse out the pod.
			scratch = podValue.MarshalTo(scratch[:0])

			pod := new(corev1.Pod)
			if err := json.Unmarshal(scratch, &pod); err != nil {
				return nil, status.Errorf(codes.Internal, "unable to decode pod info from kubelet response: %v", err)
			}

			var selectorValues []string

			containerStatus, containerFound := lookUpContainerInPod(containerID, pod.Status, log)
			switch {
			case containerFound:
				// The workload container was found in this pod. Add pod
				// selectors. Only add workload container selectors if
				// container selectors have not been disabled.
				selectorValues = append(selectorValues, getSelectorValuesFromPodInfo(pod)...)
				if !config.DisableContainerSelectors {
					selectorValues = append(selectorValues, getSelectorValuesFromWorkloadContainerStatus(containerStatus)...)
				}

				if sigstoreVerifier != nil {
					log.Debug("Attempting to verify sigstore image signature", "image", containerStatus.Image)
					sigstoreSelectors, err := p.sigstoreVerifier.Verify(ctx, containerStatus.ImageID)
					if err != nil {
						return nil, status.Errorf(codes.Internal, "error verifying sigstore image signature for imageID %s: %v", containerStatus.ImageID, err)
					}
					selectorValues = append(selectorValues, sigstoreSelectors...)
				}

			case podKnown && config.DisableContainerSelectors:
				// The workload container was not found (i.e. not ready yet?)
				// but the pod is known. If container selectors have been
				// disabled, then allow the pod selectors to be used.
				selectorValues = append(selectorValues, getSelectorValuesFromPodInfo(pod)...)
			}

			if len(selectorValues) > 0 {
				if attestResponse != nil {
					log.Warn("Two pods found with same container Id")
					return nil, status.Error(codes.Internal, "two pods found with same container Id")
				}
				attestResponse = &workloadattestorv1.AttestReferenceResponse{SelectorValues: selectorValues}
			}
		}

		if attestResponse != nil {
			return attestResponse, nil
		}

		// if the container was not located after the maximum number of attempts then the search is over.
		if attempt >= config.MaxPollAttempts {
			log.Warn("Container id not found; giving up")
			return nil, status.Error(codes.DeadlineExceeded, "no selectors found after max poll attempts")
		}

		// wait a bit for containers to initialize before trying again.
		log.Debug("Container id not found", telemetry.RetryInterval, config.PollRetryInterval)

		select {
		case <-p.clock.After(config.PollRetryInterval):
		case <-ctx.Done():
			return nil, status.Errorf(codes.Canceled, "no selectors found: %v", ctx.Err())
		}
	}
}

// attestByPodReference handles the `pods/core` path: a Kubernetes object
// reference whose resource is the core Pod type. It mirrors the generic
// object path's spec validation (name or uid required, namespace required
// with name on a namespaced resource, namespace forbidden without name) and
// the cross-check ("if both uid and name are supplied, the resolved pod's
// UID MUST match the supplied uid"). Resolution is pod-specific: it tries
// the kubelet pod list first (cheap, node-local, indexed by UID; same path
// the legacy PID flow uses), then falls back to the API server. Selector
// emission uses the pod-shaped vocabulary (sa, ns, pod-uid, pod-name,
// pod-image, pod-label, pod-owner, ...) — distinct from the generic-object
// vocabulary so registration entries can match pod-specific fields like
// container images and service accounts that aren't present on a
// PartialObjectMetadata.
func (p *Plugin) attestByPodReference(ctx context.Context, objRef *reference.KubernetesObjectReference) (*workloadattestorv1.AttestReferenceResponse, error) {
	key := objRef.GetKey()
	namespace := key.GetNamespace()
	name := key.GetName()
	uid := types.UID(objRef.GetUid())

	config, _, _, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	var pod *corev1.Pod
	switch {
	case name != "":
		if namespace == "" {
			return nil, ErrNamespaceRequired
		}
		pod, err = p.findPodByName(ctx, config, namespace, name)
	default:
		pod, err = p.findPodByUID(ctx, config, uid)
	}
	if err != nil {
		return nil, err
	}

	// Per spec: when name (and namespace) and uid are both supplied, the
	// resolved object's UID MUST match the supplied uid.
	if uid != "" && pod.UID != uid {
		return nil, status.Errorf(codes.NotFound, "pod %s/%s has UID %s, expected %s", pod.Namespace, pod.Name, pod.UID, uid)
	}

	return &workloadattestorv1.AttestReferenceResponse{SelectorValues: getSelectorValuesFromPodInfo(pod)}, nil
}

// findPodByName resolves a single pod by its namespaced name. The kubelet
// pod list is iterated first; this is O(n) over the node's pods (the list
// is indexed by UID, not name) but n is small in practice and saves an API
// server round-trip when the pod is local. If the pod isn't on this node
// the apiserver answers a precise Get directly — no list, no client-side
// filter — and `apierrors.IsNotFound` is mapped to `codes.NotFound` so
// callers can distinguish "no such pod" from a transport error.
func (p *Plugin) findPodByName(ctx context.Context, config *k8sConfig, namespace, name string) (*corev1.Pod, error) {
	// Try kubelet pod list first; iterate to find a match by namespace+name.
	podList, err := p.getPodList(ctx, config.Client, config.PollRetryInterval/2)
	if err != nil {
		return nil, err
	}
	for _, podValue := range podList {
		if string(podValue.GetStringBytes("metadata", "namespace")) != namespace {
			continue
		}
		if string(podValue.GetStringBytes("metadata", "name")) != name {
			continue
		}
		return decodePodFromKubelet(podValue)
	}

	// Fallback: direct Get from API server.
	kubeClient, err := p.getOrCreateKubeClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create Kubernetes client: %v", err)
	}
	pod := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "pod %s/%s not found", namespace, name)
		}
		return nil, status.Errorf(codes.Internal, "unable to get pod from Kubernetes API: %v", err)
	}
	return pod, nil
}

// findPodByUID resolves a single pod by its Kubernetes UID. The kubelet pod
// list is checked first because it's already keyed by UID and only contains
// pods scheduled to this node — both common-case wins. If the pod isn't on
// this node, it falls back to a cluster-wide List from the API server, which
// is unavoidable because Kubernetes does not support `metadata.uid` as a
// field selector (the apiserver would not be able to push the filter down,
// so we list and filter client-side regardless).
func (p *Plugin) findPodByUID(ctx context.Context, config *k8sConfig, uid types.UID) (*corev1.Pod, error) {
	// Try kubelet pod list first (already indexed by UID).
	podList, err := p.getPodList(ctx, config.Client, config.PollRetryInterval/2)
	if err != nil {
		return nil, err
	}
	if podValue, ok := podList[string(uid)]; ok {
		return decodePodFromKubelet(podValue)
	}

	// Fallback: list all pods via API server. k8s doesn't support
	// metadata.uid as a field selector, so we list and filter client-side.
	kubeClient, err := p.getOrCreateKubeClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create Kubernetes client: %v", err)
	}
	pods := &corev1.PodList{}
	if err := kubeClient.List(ctx, pods); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to list pods from Kubernetes API: %v", err)
	}
	for i := range pods.Items {
		if pods.Items[i].UID == uid {
			return &pods.Items[i], nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "pod with UID %s not found", uid)
}

// decodePodFromKubelet rehydrates a `corev1.Pod` from the partially-parsed
// JSON the kubelet pod-list path keeps in fastjson form (the cache stores
// pods as `*fastjson.Value` to avoid per-request unmarshalling when no pod
// is needed). The two-stage marshal-then-unmarshal is unavoidable here:
// fastjson is read-only, so the only way to project into a typed struct is
// to serialise back to bytes and let `encoding/json` parse it.
func decodePodFromKubelet(podValue *fastjson.Value) (*corev1.Pod, error) {
	var scratch []byte
	scratch = podValue.MarshalTo(scratch)
	pod := new(corev1.Pod)
	if err := json.Unmarshal(scratch, pod); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to decode pod info from kubelet response: %v", err)
	}
	return pod, nil
}

// attestByObjectReference handles the generic-Kubernetes-object path: any
// resource other than `pods/core`. It resolves the resource's GVK and scope
// via the discovery-backed REST mapper, fetches the object's metadata via
// PartialObjectMetadata, and emits a uniform set of selectors derived from
// `ObjectMeta` (resource, namespace, name, uid, labels, annotations, owner
// references).
func (p *Plugin) attestByObjectReference(ctx context.Context, objRef *reference.KubernetesObjectReference) (*workloadattestorv1.AttestReferenceResponse, error) {
	r := objRef.GetType()
	key := objRef.GetKey()
	namespace := key.GetNamespace()
	name := key.GetName()
	uid := types.UID(objRef.GetUid())

	kubeClient, err := p.getOrCreateKubeClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to set up Kubernetes client: %v", err)
	}
	mapper := kubeClient.RESTMapper()

	// Per the SPIFFE Broker API spec, `core` is the canonical group string
	// for the Kubernetes core API group, but Kubernetes itself uses the
	// empty string on the wire — translate before mapping.
	group := r.GetGroup()
	if group == "core" {
		group = ""
	}
	gvr := schema.GroupVersionResource{Group: group, Resource: r.GetPlural()}
	gvk, err := mapper.KindFor(gvr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unknown Kubernetes resource %s.%s: %v", r.GetPlural(), r.GetGroup(), err)
	}
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "no REST mapping for %s.%s: %v", r.GetPlural(), r.GetGroup(), err)
	}

	namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	switch {
	case namespaced && name != "" && namespace == "":
		return nil, ErrNamespaceRequired
	case !namespaced && namespace != "":
		return nil, status.Error(codes.InvalidArgument, "namespace must be empty for cluster-scoped resource")
	}

	obj, err := p.findObject(ctx, kubeClient, gvk, namespace, name, uid)
	if err != nil {
		return nil, err
	}

	if uid != "" && obj.UID != uid {
		return nil, status.Errorf(codes.NotFound, "%s.%s %s/%s has UID %s, expected %s",
			r.GetPlural(), r.GetGroup(), obj.Namespace, obj.Name, obj.UID, uid)
	}

	return &workloadattestorv1.AttestReferenceResponse{
		SelectorValues: getSelectorValuesFromObjectMeta(r, gvk, obj),
	}, nil
}

// findObject resolves a single Kubernetes object's metadata. When `name` is
// supplied, a direct Get is used (precise; returns NotFound cleanly). When
// only `uid` is supplied, the API server is listed and filtered client-side
// (the apiserver does not support metadata.uid as a field selector).
func (p *Plugin) findObject(ctx context.Context, kubeClient client.Client, gvk schema.GroupVersionKind, namespace, name string, uid types.UID) (*metav1.PartialObjectMetadata, error) {
	if name != "" {
		obj := &metav1.PartialObjectMetadata{}
		obj.SetGroupVersionKind(gvk)
		if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, status.Errorf(codes.NotFound, "%s %s/%s not found", gvk.Kind, namespace, name)
			}
			return nil, status.Errorf(codes.Internal, "unable to get %s: %v", gvk.Kind, err)
		}
		return obj, nil
	}

	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind + "List"})
	if err := kubeClient.List(ctx, list); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to list %s: %v", gvk.Kind, err)
	}
	for i := range list.Items {
		if list.Items[i].UID == uid {
			return &list.Items[i], nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "%s with UID %s not found", gvk.Kind, uid)
}

// getSelectorValuesFromObjectMeta produces the broker-object selector set
// from a resolved Kubernetes object's metadata. The vocabulary is uniform
// across resource types so registration entries can be authored without
// caring whether the workload is a Pod, a Deployment, or a CRD instance.
//
// Selector values (the leading `k8s:` selector type is added by the V1
// wrapper, not here):
//
//	uid:<uid>                                                always
//	resource:<plural>.<group>                                always
//	type:<plural>.<group>                                    alias of resource
//	plural:<plural>                                          always
//	group:<group>                                            always; "core" for core resources
//	apiGroup:<group>                                         alias of group
//	version:<version>                                        always; e.g. "v1", "v1beta1"
//	apiVersion:<apiVersion>                                  Kubernetes wire form: "v1" (core) or "<group>/<version>"
//	kind:<Kind>                                              always; e.g. "Pod", "Deployment"
//	name:<name>                                              always
//	namespace:<namespace>                                    omitted for cluster-scoped objects
//	key:<namespace>/<name>                                   combination of namespace and name
//	label:<key>:<value>                                      one per .metadata.labels entry
//	owner-key:<ownerAPIGroup>/<ownerKind>/<ownerName>        atomic identity of every owner reference by key
//	owner-uid:<ownerAPIGroup>/<ownerKind>/<ownerUID>         atomic identity of every owner reference by UID
//	controller-key:<ownerAPIGroup>/<ownerKind>/<ownerName>   atomic identity of every controller owner reference by key
//	controller-uid:<ownerAPIGroup>/<ownerKind>/<ownerUID>    atomic identity of every controller owner reference by UID
func getSelectorValuesFromObjectMeta(r *reference.KubernetesObjectType, gvk schema.GroupVersionKind, obj *metav1.PartialObjectMetadata) []string {
	objType := r.GetPlural() + "." + r.GetGroup()
	values := []string{
		"uid:" + string(obj.UID),
		"resource:" + objType,
		"type:" + objType,
		"plural:" + r.GetPlural(),
		"group:" + r.GetGroup(),
		"apiGroup:" + r.GetGroup(),
		"version:" + gvk.Version,
		"apiVersion:" + gvk.GroupVersion().String(),
		"kind:" + gvk.Kind,
		"name:" + obj.Name,
	}

	// Namespace and key.
	objKey := obj.Name
	if obj.Namespace != "" {
		objKey = obj.Namespace + "/" + obj.Name
		values = append(values, "namespace:"+obj.Namespace)
	}
	values = append(values, "key:"+objKey)

	// Labels.
	for k, v := range obj.Labels {
		values = append(values, "label:"+k+":"+v)
	}

	// Owners and controllers.
	for _, owner := range obj.OwnerReferences {
		ownerGV, _ := schema.ParseGroupVersion(owner.APIVersion)
		if ownerGV.Group == "" {
			ownerGV.Group = "core"
		}

		// We omit ownerGV.Version here on purpose, the version is
		// not part of the object identity.
		ownerGK := ownerGV.Group + "/" + owner.Kind
		ownerKey := ownerGK + "/" + owner.Name
		ownerUID := ownerGK + "/" + string(owner.UID)
		values = append(values,
			"owner-key:"+ownerKey,
			"owner-uid:"+ownerUID,
		)

		// Also a controller?
		if owner.Controller != nil && *owner.Controller {
			values = append(values,
				"controller-key:"+ownerKey,
				"controller-uid:"+ownerUID,
			)
		}
	}
	return values
}

// getOrCreateKubeClient lazily builds the controller-runtime client. The
// client is paired with a discovery-backed REST mapper (accessible via
// `client.RESTMapper()`) used by the arbitrary-object path to resolve
// plural+group → GVK and determine namespace scoping at runtime. Both
// share an HTTP client to avoid duplicate connection pools and duplicate
// discovery caches. Guarded by a dedicated mutex so the apiserver
// discovery handshake on first use does not block readers of unrelated
// plugin state.
func (p *Plugin) getOrCreateKubeClient() (client.Client, error) {
	p.kubeMu.RLock()
	if p.kubeClient != nil {
		c := p.kubeClient
		p.kubeMu.RUnlock()
		return c, nil
	}
	p.kubeMu.RUnlock()

	p.kubeMu.Lock()
	defer p.kubeMu.Unlock()
	if p.kubeClient != nil {
		return p.kubeClient, nil
	}

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to load Kubernetes client config: %w", err)
	}
	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to build Kubernetes HTTP client: %w", err)
	}
	mapper, err := apiutil.NewDynamicRESTMapper(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to build Kubernetes REST mapper: %w", err)
	}
	c, err := client.New(restConfig, client.Options{
		Scheme:     k8sScheme,
		Mapper:     mapper,
		HTTPClient: httpClient,
		Cache:      &client.CacheOptions{},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create Kubernetes client: %w", err)
	}

	p.kubeClient = c
	return c, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	if err := p.reloadKubeletClient(newConfig); err != nil {
		return nil, err
	}

	var sigstoreVerifier sigstore.Verifier
	if newConfig.sigstoreConfig != nil {
		verifier := sigstore.NewVerifier(newConfig.sigstoreConfig)
		err = verifier.Init(ctx)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error initializing sigstore verifier: %v", err)
		}
		sigstoreVerifier = verifier
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig
	p.containerHelper = newConfig.ContainerHelper
	p.sigstoreVerifier = sigstoreVerifier

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (resp *configv1.ValidateResponse, err error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() (*k8sConfig, ContainerHelper, sigstore.Verifier, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil, nil, nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	if err := p.reloadKubeletClient(p.config); err != nil {
		p.log.Warn("Unable to load kubelet client", "err", err)
	}
	return p.config, p.containerHelper, p.sigstoreVerifier, nil
}

func (p *Plugin) setPodListCache(podList map[string]*fastjson.Value, cacheFor time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cachedPodList = podList
	p.cachedPodListValidUntil = p.clock.Now().Add(cacheFor)
}

func (p *Plugin) getPodListCache() map[string]*fastjson.Value {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.clock.Now().Sub(p.cachedPodListValidUntil) >= 0 {
		return nil
	}

	return p.cachedPodList
}

func (p *Plugin) setContainerHelper(c ContainerHelper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.containerHelper = c
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
	case config.UseAnonymousAuthentication:
	// Don't load credentials if using anonymous authentication
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
		path = p.defaultKubeletCAPath()
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
		path = p.defaultTokenPath()
	}
	token, err := p.readFile(path)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "unable to load token: %v", err)
	}
	return strings.TrimSpace(string(token)), nil
}

// readFile reads the contents of a file through the filesystem interface
func (p *Plugin) readFile(path string) ([]byte, error) {
	f, err := os.Open(filepath.Join(p.rootDir, path))
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

func (p *Plugin) getPodList(ctx context.Context, client *kubeletClient, cacheFor time.Duration) (map[string]*fastjson.Value, error) {
	result := p.getPodListCache()
	if result != nil {
		return result, nil
	}

	podList, err, _ := p.singleflight.Do("podList", func() (any, error) {
		result := p.getPodListCache()
		if result != nil {
			return result, nil
		}

		podListBytes, err := client.GetPodList(ctx)
		if err != nil {
			return nil, err
		}

		var parser fastjson.Parser
		podList, err := parser.ParseBytes(podListBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to parse kubelet response: %v", err)
		}

		items := podList.GetArray("items")
		result = make(map[string]*fastjson.Value, len(items))

		for _, podValue := range items {
			uid := string(podValue.Get("metadata", "uid").GetStringBytes())

			if uid == "" {
				p.log.Warn("Pod has no UID", "pod", podValue)
				continue
			}

			result[uid] = podValue
		}

		p.setPodListCache(result, cacheFor)

		return result, nil
	})
	if err != nil {
		return nil, err
	}

	return podList.(map[string]*fastjson.Value), nil
}

type kubeletClient struct {
	Transport *http.Transport
	URL       url.URL
	Token     string
}

func (c *kubeletClient) GetPodList(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := c.URL
	url.Path = "/pods"
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
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

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to read pods response: %v", err)
	}
	return out, nil
}

func lookUpContainerInPod(containerID string, status corev1.PodStatus, log hclog.Logger) (*corev1.ContainerStatus, bool) {
	for _, status := range status.ContainerStatuses {
		// TODO: should we be keying off of the status or is the lack of a
		// container id sufficient to know the container is not ready?
		if status.ContainerID == "" {
			continue
		}

		containerURL, err := url.Parse(status.ContainerID)
		if err != nil {
			log.With(telemetry.Error, err).
				With(telemetry.ContainerID, status.ContainerID).
				Error("Malformed container id")
			continue
		}

		if containerID == containerURL.Host {
			return &status, true
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
			log.With(telemetry.Error, err).
				With(telemetry.ContainerID, status.ContainerID).
				Error("Malformed container id")
			continue
		}

		if containerID == containerURL.Host {
			return &status, true
		}
	}

	return nil, false
}

func getPodImageIdentifiers(containerStatuses ...corev1.ContainerStatus) map[string]struct{} {
	// Map is used purely to exclude duplicate selectors, value is unused.
	podImages := make(map[string]struct{})
	// Note that for each pod image we generate *2* matching selectors.
	// This is to support matching against ImageID, which has a SHA
	// docker.io/envoyproxy/envoy-alpine@sha256:bf862e5f5eca0a73e7e538224578c5cf867ce2be91b5eaed22afc153c00363eb
	// as well as
	// docker.io/envoyproxy/envoy-alpine:v1.16.0, which does not,
	// while also maintaining backwards compatibility and allowing for dynamic workload registration (k8s operator)
	// when the SHA is not yet known (e.g. before the image pull is initiated at workload creation time)
	// More info here: https://github.com/spiffe/spire/issues/2026
	//
	// Note: The tag-based Image value can be non-deterministic when multiple
	// tags share the same digest, as the CRI API does not standardize which
	// tag to report. Prefer digest-based selectors for reliable matching.
	// See https://github.com/spiffe/spire/issues/4287
	for _, containerStatus := range containerStatuses {
		podImages[containerStatus.ImageID] = struct{}{}
		podImages[containerStatus.Image] = struct{}{}
	}
	return podImages
}

func getSelectorValuesFromPodInfo(pod *corev1.Pod) []string {
	selectorValues := []string{
		fmt.Sprintf("sa:%s", pod.Spec.ServiceAccountName),
		fmt.Sprintf("ns:%s", pod.Namespace),
		fmt.Sprintf("node-name:%s", pod.Spec.NodeName),
		fmt.Sprintf("pod-uid:%s", pod.UID),
		fmt.Sprintf("pod-name:%s", pod.Name),
		fmt.Sprintf("pod-image-count:%s", strconv.Itoa(len(pod.Status.ContainerStatuses))),
		fmt.Sprintf("pod-init-image-count:%s", strconv.Itoa(len(pod.Status.InitContainerStatuses))),
	}

	for podImage := range getPodImageIdentifiers(pod.Status.ContainerStatuses...) {
		selectorValues = append(selectorValues, fmt.Sprintf("pod-image:%s", podImage))
	}
	for podInitImage := range getPodImageIdentifiers(pod.Status.InitContainerStatuses...) {
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

func getSelectorValuesFromWorkloadContainerStatus(status *corev1.ContainerStatus) []string {
	selectorValues := []string{fmt.Sprintf("container-name:%s", status.Name)}
	for containerImage := range getPodImageIdentifiers(*status) {
		selectorValues = append(selectorValues, fmt.Sprintf("container-image:%s", containerImage))
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
