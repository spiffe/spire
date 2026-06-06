package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	hcltoken "github.com/hashicorp/hcl/hcl/token"
	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/broker/brokercontext"
	"github.com/spiffe/spire/pkg/agent/common/sigstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/valyala/fastjson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var k8sScheme = runtime.NewScheme()

func init() {
	if err := metav1.AddMetaToScheme(k8sScheme); err != nil {
		panic(fmt.Sprintf("failed to register metav1 scheme: %v", err))
	}
	if err := corev1.AddToScheme(k8sScheme); err != nil {
		panic(fmt.Sprintf("failed to register corev1 scheme: %v", err))
	}
	if err := authv1.AddToScheme(k8sScheme); err != nil {
		panic(fmt.Sprintf("failed to register authv1 scheme: %v", err))
	}
}

const (
	pluginName                    = "k8s"
	brokerImpersonationReviewVerb = "impersonate-via-spire"
	defaultMaxPollAttempts        = 60
	defaultPollRetryInterval      = time.Millisecond * 500
	defaultSecureKubeletPort      = 10250
	defaultKubeletCAPath          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenPath              = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // false positive
	defaultNodeNameEnv            = "MY_NODE_NAME"
	defaultReloadInterval         = time.Minute

	workloadPIDReferenceTypeURL      = "type.googleapis.com/spiffe.broker.WorkloadPIDReference"
	kubernetesObjectReferenceTypeURL = "type.googleapis.com/spiffe.broker.KubernetesObjectReference"
)

type podReferenceScope string

const (
	podReferenceScopeAgentNode podReferenceScope = "agent_node"
	podReferenceScopeCluster   podReferenceScope = "cluster"
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

	// DisableKubeletClient disables kubelet client setup and kubelet pod-list
	// calls. PID-based workload attestation and agent_node pod reference
	// resolution require the kubelet client.
	DisableKubeletClient bool `hcl:"disable_kubelet_client"`

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

	// EnableNamespaceLabels enables fetching namespace labels from the
	// Kubernetes API server. When enabled, namespace labels are available
	// as selectors. This requires the SPIRE agent service account to have
	// RBAC permissions to get namespaces.
	EnableNamespaceLabels bool `hcl:"enable_namespace_labels"`

	// Sigstore contains sigstore specific configs.
	Sigstore *sigstore.HCLConfig `hcl:"sigstore,omitempty"`

	// Experimental contains experimental configs.
	Experimental *k8sExperimentalHCLConfig `hcl:"experimental"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

type k8sExperimentalHCLConfig struct {
	// APIServer contains Kubernetes API server-specific configs.
	APIServer *k8sAPIServerHCLConfig `hcl:"api_server"`

	// Broker contains SPIFFE Broker API-specific configuration.
	Broker *k8sBrokerHCLConfig `hcl:"broker"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

type k8sBrokerHCLConfig struct {
	// AccessPolicy controls whether the plugin creates SubjectAccessReview
	// requests to authorize broker access to resolved Kubernetes objects.
	AccessPolicy string `hcl:"access_policy"`

	Brokers []k8sBrokerHCLEntry `hcl:"brokers"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

type k8sBrokerHCLEntry struct {
	ID                string `hcl:"id"`
	PodReferenceScope string `hcl:"pod_reference_scope"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

type k8sAPIServerHCLConfig struct {
	Cache *k8sAPIServerCacheHCLConfig `hcl:"cache"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

type k8sAPIServerCacheHCLConfig struct {
	Enabled bool `hcl:"enabled"`

	UnusedKeyPositions map[string][]hcltoken.Pos `hcl:",unusedKeyPositions"`
}

// k8sConfig holds the configuration distilled from HCL
type k8sConfig struct {
	MaxPollAttempts           int
	PollRetryInterval         time.Duration
	DisableKubeletClient      bool
	DisableContainerSelectors bool
	EnableNamespaceLabels     bool
	ContainerHelper           ContainerHelper
	sigstoreConfig            *sigstore.Config
	APIServerCacheEnabled     bool
	Broker                    *k8sBrokerConfig
	podListFetcherConfig      podListFetcherConfig
}

func (p *Plugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *k8sConfig {
	// Parse HCL config payload into config struct
	newConfig := new(HCLConfig)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	pluginconf.ReportUnusedKeys(status, newConfig.UnusedKeyPositions)
	var apiServerCacheEnabled bool
	var brokerConfig *k8sBrokerConfig
	if newConfig.Experimental != nil {
		pluginconf.ReportUnusedKeys(status, newConfig.Experimental.UnusedKeyPositions)
		if newConfig.Experimental.APIServer != nil {
			pluginconf.ReportUnusedKeys(status, newConfig.Experimental.APIServer.UnusedKeyPositions)
			if newConfig.Experimental.APIServer.Cache != nil {
				pluginconf.ReportUnusedKeys(status, newConfig.Experimental.APIServer.Cache.UnusedKeyPositions)
				apiServerCacheEnabled = newConfig.Experimental.APIServer.Cache.Enabled
			}
		}
		brokerConfig = buildBrokerConfig("experimental.broker", newConfig.Experimental.Broker, status)
	}
	validateDisableKubeletClientConfig(newConfig, brokerConfig, status)

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

	kubeletCAPath := newConfig.KubeletCAPath
	if kubeletCAPath == "" {
		kubeletCAPath = p.defaultKubeletCAPath()
	}
	tokenPath := newConfig.TokenPath
	if tokenPath == "" {
		tokenPath = p.defaultTokenPath()
	}

	// Return the plugin and pod list fetcher configuration.
	return &k8sConfig{
		MaxPollAttempts:           maxPollAttempts,
		PollRetryInterval:         pollRetryInterval,
		DisableKubeletClient:      newConfig.DisableKubeletClient,
		DisableContainerSelectors: newConfig.DisableContainerSelectors,
		EnableNamespaceLabels:     newConfig.EnableNamespaceLabels,
		ContainerHelper:           containerHelper,
		sigstoreConfig:            sigstoreConfig,
		APIServerCacheEnabled:     apiServerCacheEnabled,
		Broker:                    brokerConfig,
		podListFetcherConfig: podListFetcherConfig{
			pollRetryInterval:          pollRetryInterval,
			secure:                     secure,
			port:                       port,
			skipKubeletVerification:    newConfig.SkipKubeletVerification,
			tokenPath:                  tokenPath,
			certificatePath:            newConfig.CertificatePath,
			privateKeyPath:             newConfig.PrivateKeyPath,
			useAnonymousAuthentication: newConfig.UseAnonymousAuthentication,
			kubeletCAPath:              kubeletCAPath,
			nodeName:                   nodeName,
			reloadInterval:             reloadInterval,
		},
	}
}

func validateDisableKubeletClientConfig(config *HCLConfig, brokerConfig *k8sBrokerConfig, status *pluginconf.Status) {
	if !config.DisableKubeletClient {
		return
	}

	conflicts := []struct {
		name string
		set  bool
	}{
		{name: "kubelet_read_only_port", set: config.KubeletReadOnlyPort > 0},
		{name: "kubelet_secure_port", set: config.KubeletSecurePort > 0},
		{name: "kubelet_ca_path", set: config.KubeletCAPath != ""},
		{name: "skip_kubelet_verification", set: config.SkipKubeletVerification},
		{name: "token_path", set: config.TokenPath != ""},
		{name: "certificate_path", set: config.CertificatePath != ""},
		{name: "private_key_path", set: config.PrivateKeyPath != ""},
		{name: "use_anonymous_authentication", set: config.UseAnonymousAuthentication},
		{name: "node_name_env", set: config.NodeNameEnv != ""},
		{name: "node_name", set: config.NodeName != ""},
		{name: "reload_interval", set: config.ReloadInterval != ""},
	}
	for _, conflict := range conflicts {
		if conflict.set {
			status.ReportErrorf("disable_kubelet_client cannot be used with %s", conflict.name)
		}
	}

	if brokerConfig == nil {
		return
	}
	for brokerID, brokerEntry := range brokerConfig.Brokers {
		if brokerEntry.PodReferenceScope != podReferenceScopeCluster {
			status.ReportErrorf("experimental.broker.brokers[%s].pod_reference_scope must be \"cluster\" when disable_kubelet_client is true", brokerID)
		}
	}
}

type brokerAccessPolicy string

const (
	brokerAccessPolicyPermissive brokerAccessPolicy = "permissive"
	brokerAccessPolicyEnforced   brokerAccessPolicy = "enforced"
)

type k8sBrokerConfig struct {
	AccessPolicy brokerAccessPolicy
	Brokers      map[string]k8sBrokerEntry
}

type k8sBrokerEntry struct {
	ID                spiffeid.ID
	PodReferenceScope podReferenceScope
}

func buildBrokerConfig(path string, brokerConfig *k8sBrokerHCLConfig, status *pluginconf.Status) *k8sBrokerConfig {
	if brokerConfig == nil {
		return nil
	}

	pluginconf.ReportUnusedKeys(status, brokerConfig.UnusedKeyPositions)
	accessPolicy, _ := buildBrokerAccessPolicy(path, brokerConfig.AccessPolicy, status)
	if len(brokerConfig.Brokers) == 0 {
		status.ReportErrorf("%s.brokers: at least one broker is required", path)
		return &k8sBrokerConfig{
			AccessPolicy: accessPolicy,
			Brokers:      map[string]k8sBrokerEntry{},
		}
	}

	brokers := make(map[string]k8sBrokerEntry, len(brokerConfig.Brokers))
	seen := make(map[string]struct{}, len(brokerConfig.Brokers))
	for i, b := range brokerConfig.Brokers {
		pluginconf.ReportUnusedKeys(status, b.UnusedKeyPositions)
		if b.ID == "" {
			status.ReportErrorf("%s.brokers[%d].id: must be specified", path, i)
			continue
		}
		if _, dup := seen[b.ID]; dup {
			status.ReportErrorf("%s.brokers[%s].id: duplicate broker id", path, b.ID)
			continue
		}
		seen[b.ID] = struct{}{}

		id, err := spiffeid.FromString(b.ID)
		if err != nil {
			status.ReportErrorf("%s.brokers[%s].id: %v", path, b.ID, err)
			continue
		}

		podRefScope, ok := buildPodReferenceScope(path, b.ID, b.PodReferenceScope, status)
		if !ok {
			continue
		}

		brokers[b.ID] = k8sBrokerEntry{
			ID:                id,
			PodReferenceScope: podRefScope,
		}
	}
	return &k8sBrokerConfig{
		AccessPolicy: accessPolicy,
		Brokers:      brokers,
	}
}

func buildBrokerAccessPolicy(path string, hclValue string, status *pluginconf.Status) (brokerAccessPolicy, bool) {
	switch hclValue {
	case string(brokerAccessPolicyPermissive):
		return brokerAccessPolicyPermissive, true
	case string(brokerAccessPolicyEnforced):
		return brokerAccessPolicyEnforced, true
	case "":
		status.ReportErrorf("%s.access_policy: must be specified as one of [permissive, enforced]", path)
		return "", false
	default:
		status.ReportErrorf("%s.access_policy: unsupported value %q; must be one of [permissive, enforced]", path, hclValue)
		return "", false
	}
}

func buildPodReferenceScope(path string, brokerID string, hclValue string, status *pluginconf.Status) (podReferenceScope, bool) {
	switch hclValue {
	case string(podReferenceScopeAgentNode), "":
		return podReferenceScopeAgentNode, true
	case string(podReferenceScopeCluster):
		return podReferenceScopeCluster, true
	default:
		status.ReportErrorf("%s.brokers[%s].pod_reference_scope: unsupported value %q; must be one of [agent_node, cluster]", path, brokerID, hclValue)
		return "", false
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

	// kubeClient is a live, uncached Kubernetes API server client for full
	// objects and writes, like Pod reads and SubjectAccessReview creation.
	// kubeMetadataClient is a Kubernetes API server client used only for
	// PartialObjectMetadata lookups; when
	// experimental.api_server.cache.enabled is true, this client is
	// cache-backed. Both carry their own RESTMapper internally (accessible via
	// client.RESTMapper()), so we don't keep a separate mapper
	// field. Guarded by a dedicated mutex so apiserver discovery handshakes do
	// not block readers of unrelated plugin state.
	kubeMu             sync.RWMutex
	kubeClient         client.Client
	kubeMetadataClient client.Client
	kubeCacheCancel    context.CancelFunc
	kubeCacheDone      chan struct{}

	podListFetcher *podListFetcher
}

func New() *Plugin {
	pluginClock := clock.New()
	p := &Plugin{
		clock:  pluginClock,
		getenv: os.Getenv,
	}
	p.podListFetcher = newPodListFetcher(pluginClock, p.rootDir)
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
	p.podListFetcher.setLogger(log)
}

// Attest implements the PID-based workload attestor RPC. PID handling is
// delegated through AttestReference so both RPCs share behavior, including
// broker checks when broker metadata is present on the context.
func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	ref, err := anypb.New(&broker.WorkloadPIDReference{Pid: req.Pid})
	if err != nil {
		return nil, err
	}
	resp, err := p.AttestReference(ctx, &workloadattestorv1.AttestReferenceRequest{Reference: ref})
	if err != nil {
		return nil, err
	}
	return &workloadattestorv1.AttestResponse{SelectorValues: resp.GetSelectorValues()}, nil
}

func (p *Plugin) AttestReference(ctx context.Context, req *workloadattestorv1.AttestReferenceRequest) (*workloadattestorv1.AttestReferenceResponse, error) {
	config, _, _, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	brokerEntry, result, err := p.attestReference(ctx, config, req)
	if err != nil {
		return nil, err
	}
	if err := p.checkBrokerImpersonationForReference(ctx, config, brokerEntry, result); err != nil {
		return nil, err
	}
	return result.Response, nil
}

func (p *Plugin) attestReference(ctx context.Context, config *k8sConfig, req *workloadattestorv1.AttestReferenceRequest) (*k8sBrokerEntry, *attestReferenceResult, error) {
	reference := req.GetReference()
	if reference == nil {
		return nil, nil, status.Error(codes.InvalidArgument, "workload reference must be provided")
	}

	brokerEntry, err := p.getBrokerEntryIfPresent(ctx, config)
	if err != nil {
		return nil, nil, err
	}

	switch reference.TypeUrl {
	case workloadPIDReferenceTypeURL:
		var pidRef broker.WorkloadPIDReference
		if err := reference.UnmarshalTo(&pidRef); err != nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "unable to unmarshal PID reference: %v", err)
		}
		result, err := p.attestByPIDReference(ctx, pidRef.Pid)
		return brokerEntry, result, err
	case kubernetesObjectReferenceTypeURL:
		var objRef broker.KubernetesObjectReference
		if err := reference.UnmarshalTo(&objRef); err != nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "unable to unmarshal object reference: %v", err)
		}
		if err := validateKubernetesObjectReference(&objRef); err != nil {
			return nil, nil, err
		}
		result, err := p.attestByKubernetesObjectReference(ctx, brokerEntry, &objRef)
		return brokerEntry, result, err
	default:
		return nil, nil, status.Errorf(codes.InvalidArgument, "unsupported reference type: %s", reference.TypeUrl)
	}
}

func validateKubernetesObjectReference(objRef *broker.KubernetesObjectReference) error {
	objType := objRef.GetType()
	if objType == nil {
		return status.Error(codes.InvalidArgument, "object reference is missing type")
	}
	if objType.Plural == "" {
		return status.Error(codes.InvalidArgument, "object reference type is missing plural")
	}
	if objType.Group == "" {
		return status.Error(codes.InvalidArgument, "object reference type is missing group")
	}
	objKey := objRef.GetKey()
	if objKey == nil && objRef.GetUid() == "" {
		return status.Error(codes.InvalidArgument, "object reference is missing key and UID")
	}
	if objKey != nil && objKey.GetName() == "" {
		return status.Error(codes.InvalidArgument, "object reference key is missing name")
	}
	return nil
}

type attestReferenceResult struct {
	Response        *workloadattestorv1.AttestReferenceResponse
	ObjectReference *broker.KubernetesObjectReference
	Namespace       string
	Name            string
}

func (p *Plugin) attestByPIDReference(ctx context.Context, pid int32) (*attestReferenceResult, error) {
	config, containerHelper, sigstoreVerifier, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	if config.DisableKubeletClient {
		return nil, kubeletClientUnavailableError(config)
	}

	podUID, containerID, err := containerHelper.GetPodUIDAndContainerID(pid, p.log)
	if err != nil {
		return nil, err
	}
	podKnown := podUID != ""

	// Not a Kubernetes pod
	if containerID == "" {
		return &attestReferenceResult{Response: &workloadattestorv1.AttestReferenceResponse{}}, nil
	}

	log := p.log.With(
		telemetry.PodUID, podUID,
		telemetry.ContainerID, containerID,
	)

	// Poll pod information and search for the pod with the container. If
	// the pod is not found then wait for the fetcher to provide a newer
	// result and try again.
	var scratch []byte
	var podListVersion uint64
	for attempt := 1; ; attempt++ {
		log := log.With(telemetry.Attempt, attempt)

		// The pod list fetcher takes care of caching and rate-limiting / backoffing.
		podList, podListErr := p.podListFetcher.fetchNext(ctx, podListVersion)
		if podListErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(podListErr, errPodListFetcherClosed) {
				return nil, status.Error(codes.Unavailable, podListErr.Error())
			}
			// Otherwise, we'll log podListErr below, and we may retry.
		} else {
			podListVersion = podList.version
		}

		var result *attestReferenceResult
		for podKey, podValue := range podList.pods {
			if podKnown && podKey != string(podUID) {
				// The pod holding the container is known. Skip unrelated pods.
				continue
			}

			// Reduce allocations by dumping to the same backing array on
			// each iteration in order to parse out the pod.
			scratch = podValue.MarshalTo(scratch[:0])

			pod := new(corev1.Pod)
			if err := json.Unmarshal(scratch, &pod); err != nil {
				return nil, status.Errorf(codes.Unavailable, "unable to decode pod info from kubelet response: %v", err)
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

				if config.EnableNamespaceLabels {
					nsLabels, err := p.getNamespaceLabels(ctx, pod.Namespace)
					if err != nil {
						return nil, status.Errorf(codes.Internal, "unable to get namespace labels for %q: %v", pod.Namespace, err)
					}
					selectorValues = append(selectorValues, getSelectorValuesFromNamespaceLabels(nsLabels)...)
				}

				if sigstoreVerifier != nil {
					log.Debug("Attempting to verify sigstore image signature", "image", containerStatus.Image)
					sigstoreSelectors, err := sigstoreVerifier.Verify(ctx, containerStatus.ImageID)
					if err != nil {
						if ctx.Err() != nil {
							return nil, ctx.Err()
						}
						return nil, status.Errorf(codes.PermissionDenied, "error verifying sigstore image signature for imageID %s: %v", containerStatus.ImageID, err)
					}
					selectorValues = append(selectorValues, sigstoreSelectors...)
				}

			case podKnown && config.DisableContainerSelectors:
				// The workload container was not found (i.e. not ready yet?)
				// but the pod is known. If container selectors have been
				// disabled, then allow the pod selectors to be used.
				selectorValues = append(selectorValues, getSelectorValuesFromPodInfo(pod)...)

				if config.EnableNamespaceLabels {
					nsLabels, err := p.getNamespaceLabels(ctx, pod.Namespace)
					if err != nil {
						return nil, status.Errorf(codes.Internal, "unable to get namespace labels for %q: %v", pod.Namespace, err)
					}
					selectorValues = append(selectorValues, getSelectorValuesFromNamespaceLabels(nsLabels)...)
				}
			}

			if len(selectorValues) > 0 {
				if result != nil {
					log.Warn("Two pods found with same container Id")
					return nil, status.Error(codes.Internal, "two pods found with same container Id")
				}
				result = &attestReferenceResult{
					Response: &workloadattestorv1.AttestReferenceResponse{SelectorValues: selectorValues},
					ObjectReference: &broker.KubernetesObjectReference{
						Type: &broker.KubernetesObjectType{Plural: "pods", Group: "core"},
					},
					Namespace: pod.Namespace,
					Name:      pod.Name,
				}
			}
		}

		if result != nil {
			return result, nil
		}

		// if the container was not located after the maximum number of attempts then the search is over.
		switch {
		case attempt >= config.MaxPollAttempts:
			if podListErr != nil {
				log.Warn("Unable to get pod list; giving up", telemetry.Error, podListErr)
				return nil, status.Error(codes.Unavailable, podListErr.Error())
			}
			log.Warn("Container id not found; giving up")
			return nil, status.Error(codes.DeadlineExceeded, "no selectors found after max poll attempts")
		case podListErr != nil:
			log.Warn("Unable to get pod list; will retry after backoff",
				telemetry.Error, podListErr,
				telemetry.RetryInterval, config.PollRetryInterval)
		default:
			// wait a bit for containers to initialize before trying again.
			log.Debug("Container id not found; will retry after backoff",
				telemetry.RetryInterval, config.PollRetryInterval)
		}
	}
}

func (p *Plugin) attestByKubernetesObjectReference(ctx context.Context, brokerEntry *k8sBrokerEntry, objRef *broker.KubernetesObjectReference) (*attestReferenceResult, error) {
	objType := objRef.GetType()
	switch {
	case objType.Plural == "pods" && objType.Group == "core":
		return p.attestByPodReference(ctx, brokerEntry, objRef)
	default:
		return p.attestByObjectReference(ctx, objRef)
	}
}

func (p *Plugin) checkBrokerImpersonationForReference(ctx context.Context, config *k8sConfig, brokerEntry *k8sBrokerEntry, result *attestReferenceResult) error {
	if brokerEntry == nil {
		return nil
	}
	if config.Broker == nil || config.Broker.AccessPolicy != brokerAccessPolicyEnforced {
		return nil
	}
	objRef := result.ObjectReference
	if objRef == nil {
		return nil
	}
	kubeClient, err := p.getOrCreateKubeClient()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to set up Kubernetes client: %v", err)
	}
	review := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			User: brokerEntry.ID.String(),
			ResourceAttributes: &authv1.ResourceAttributes{
				Group:     kubernetesAPIGroup(objRef.GetType().GetGroup()),
				Resource:  objRef.GetType().GetPlural(),
				Namespace: result.Namespace,
				Name:      result.Name,
				Verb:      brokerImpersonationReviewVerb,
			},
		},
	}
	if err := kubeClient.Create(ctx, review); err != nil {
		return status.Errorf(codes.Internal, "unable to check Kubernetes authorization for broker: %v", err)
	}
	if !review.Status.Allowed {
		return status.Error(codes.PermissionDenied, "Kubernetes authorizer does not allow the broker to use impersonate-via-spire for the referenced object")
	}
	return nil
}

func (p *Plugin) getBrokerEntryIfPresent(ctx context.Context, config *k8sConfig) (*k8sBrokerEntry, error) {
	callerID, ok, err := brokercontext.CallerIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to determine broker caller identity: %v", err)
	}
	if !ok {
		return nil, nil
	}
	if config.Broker == nil {
		return nil, status.Error(codes.Internal, "broker configuration missing")
	}
	brokerEntry, ok := config.Broker.Brokers[callerID.String()]
	if !ok {
		return nil, status.Errorf(codes.PermissionDenied, "broker %q is not configured", callerID.String())
	}
	return &brokerEntry, nil
}

// attestByPodReference handles the `pods/core` path: a Kubernetes object
// reference whose resource is the core Pod type. Reference shape is already
// validated by the AttestReference dispatcher (at least one of key/uid; name
// required when key is set); this function adds the pod-specific namespace
// requirement (pods are always namespaced) and enforces the spec cross-check
// ("if both key and uid are supplied, the resolved pod's UID MUST match the
// supplied uid"). Resolution tries the kubelet pod list first (cheap,
// node-local, indexed by UID — same path the PID-based flow uses). With
// agent_node scope, resolution is limited to that kubelet pod list and does
// not fall back to the API server. Selector emission uses pod-shaped selectors
// (sa, ns, pod-uid, pod-name, pod-image, pod-label, pod-owner, ...), distinct
// from the generic-object vocabulary so registration entries
// can match pod-specific fields like container images and service accounts
// that aren't present on a PartialObjectMetadata.
func (p *Plugin) attestByPodReference(ctx context.Context, brokerEntry *k8sBrokerEntry, objRef *broker.KubernetesObjectReference) (*attestReferenceResult, error) {
	config, _, _, err := p.getConfig()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get config: %v", err)
	}

	key := objRef.GetKey()
	namespace := key.GetNamespace()
	name := key.GetName()
	uid := types.UID(objRef.GetUid())

	var pod *corev1.Pod
	switch {
	case name != "":
		if namespace == "" {
			return nil, ErrNamespaceRequired
		}
		pod, err = p.findPodByName(ctx, config, namespace, name, brokerPodReferenceScope(brokerEntry))
	default:
		pod, err = p.findPodByUID(ctx, config, uid, brokerPodReferenceScope(brokerEntry))
	}
	if err != nil {
		return nil, err
	}

	// Per spec: when name (and namespace) and uid are both supplied, the
	// resolved object's UID MUST match the supplied uid.
	if uid != "" && pod.UID != uid {
		return nil, status.Errorf(codes.NotFound, "pod %s/%s has UID %s, expected %s", pod.Namespace, pod.Name, pod.UID, uid)
	}

	selectorValues := getSelectorValuesFromPodInfo(pod)
	if config.EnableNamespaceLabels {
		nsLabels, err := p.getNamespaceLabels(ctx, pod.Namespace)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get namespace labels for %q: %v", pod.Namespace, err)
		}
		selectorValues = append(selectorValues, getSelectorValuesFromNamespaceLabels(nsLabels)...)
	}

	return &attestReferenceResult{
		Response:        &workloadattestorv1.AttestReferenceResponse{SelectorValues: selectorValues},
		ObjectReference: objRef,
		Namespace:       pod.Namespace,
		Name:            pod.Name,
	}, nil
}

func brokerPodReferenceScope(brokerEntry *k8sBrokerEntry) podReferenceScope {
	if brokerEntry == nil {
		return podReferenceScopeAgentNode
	}
	return brokerEntry.PodReferenceScope
}

// findPodByName resolves a single pod by its namespaced name. The kubelet
// pod list is iterated first; this is O(n) over the node's pods (the list
// is indexed by UID, not name) but n is small in practice and saves an API
// server round-trip when the pod is local. Under agent_node scope, resolution
// stops at the kubelet pod list. Under cluster scope, if the pod is not in the
// kubelet list, the apiserver answers a precise Get directly — no list, no
// client-side filter.
func (p *Plugin) findPodByName(ctx context.Context, config *k8sConfig, namespace, name string, scope podReferenceScope) (*corev1.Pod, error) {
	// Try kubelet pod list first; iterate to find a match by namespace+name.
	podList, err := p.getPodListForReference(ctx, config, scope)
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

	if scope == podReferenceScopeAgentNode {
		return nil, status.Errorf(codes.NotFound, "pod %s/%s not found on agent node", namespace, name)
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
// pods scheduled to this node — both common-case wins. Under agent_node scope,
// resolution stops at the kubelet pod list. Under cluster scope, if the pod is
// not in the kubelet list, it falls back to a cluster-wide
// PartialObjectMetadata List from the API server cache to resolve the pod
// name+namespace, then fetches the full pod with a single live Get. Kubernetes
// does not support `metadata.uid` as a field selector, so we list and filter
// client-side regardless.
func (p *Plugin) findPodByUID(ctx context.Context, config *k8sConfig, uid types.UID, scope podReferenceScope) (*corev1.Pod, error) {
	// Try kubelet pod list first (already indexed by UID).
	podList, err := p.getPodListForReference(ctx, config, scope)
	if err != nil {
		return nil, err
	}
	if podValue, ok := podList[string(uid)]; ok {
		return decodePodFromKubelet(podValue)
	}

	if scope == podReferenceScopeAgentNode {
		return nil, status.Errorf(codes.NotFound, "pod with UID %s not found on agent node", uid)
	}

	// Fallback: list pod metadata to resolve UID -> namespace/name, then do a
	// single live Get for the full pod object.
	kubeMetadataClient, err := p.getOrCreateKubeMetadataClient(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create Kubernetes metadata client: %v", err)
	}
	podMeta, err := p.findObject(ctx, kubeMetadataClient, schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, "", "", uid)
	if err != nil {
		return nil, err
	}

	kubeClient, err := p.getOrCreateKubeClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create Kubernetes client: %v", err)
	}
	pod := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: podMeta.Namespace, Name: podMeta.Name}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "pod %s/%s not found", podMeta.Namespace, podMeta.Name)
		}
		return nil, status.Errorf(codes.Internal, "unable to get pod from Kubernetes API: %v", err)
	}
	if pod.UID != uid {
		return nil, status.Errorf(codes.NotFound, "pod %s/%s has UID %s, expected %s", pod.Namespace, pod.Name, pod.UID, uid)
	}
	return pod, nil
}

func (p *Plugin) getPodListForReference(ctx context.Context, config *k8sConfig, scope podReferenceScope) (map[string]*fastjson.Value, error) {
	if config.DisableKubeletClient {
		if scope != podReferenceScopeCluster {
			return nil, kubeletClientUnavailableError(config)
		}
		return nil, nil
	}

	podList, err := p.fetchKubeletPodList(ctx)
	if err != nil {
		if scope != podReferenceScopeCluster {
			return nil, err
		}
		p.log.Debug("Unable to query kubelet for pod reference; falling back to Kubernetes API", telemetry.Error, err)
		return nil, nil
	}
	return podList, nil
}

func kubeletClientUnavailableError(config *k8sConfig) error {
	if config.DisableKubeletClient {
		return status.Error(codes.FailedPrecondition, "kubelet client is disabled")
	}
	return status.Error(codes.FailedPrecondition, "kubelet client is not configured")
}

func (p *Plugin) fetchKubeletPodList(ctx context.Context) (map[string]*fastjson.Value, error) {
	podList, err := p.podListFetcher.fetchNext(ctx, 0)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return podList.pods, nil
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
// `ObjectMeta` (resource, namespace, name, uid, labels, owner references).
func (p *Plugin) attestByObjectReference(ctx context.Context, objRef *broker.KubernetesObjectReference) (*attestReferenceResult, error) {
	r := objRef.GetType()
	key := objRef.GetKey()
	namespace := key.GetNamespace()
	name := key.GetName()
	uid := types.UID(objRef.GetUid())

	kubeClient, err := p.getOrCreateKubeMetadataClient(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to set up Kubernetes client: %v", err)
	}
	mapper := kubeClient.RESTMapper()

	// Per the SPIFFE Broker API spec, `core` is the canonical group string
	// for the Kubernetes core API group, but Kubernetes itself uses the
	// empty string on the wire — translate before mapping.
	group := kubernetesAPIGroup(r.GetGroup())
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

	selectorValues := getSelectorValuesFromObjectMeta(r, gvk, obj)
	config, _, _, err := p.getConfig()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get config: %v", err)
	}
	if config.EnableNamespaceLabels && namespaced && obj.Namespace != "" {
		nsLabels, err := p.getNamespaceLabels(ctx, obj.Namespace)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get namespace labels for %q: %v", obj.Namespace, err)
		}
		selectorValues = append(selectorValues, getSelectorValuesFromNamespaceLabels(nsLabels)...)
	}

	return &attestReferenceResult{
		Response: &workloadattestorv1.AttestReferenceResponse{
			SelectorValues: selectorValues,
		},
		ObjectReference: objRef,
		Namespace:       obj.Namespace,
		Name:            obj.Name,
	}, nil
}

func kubernetesAPIGroup(group string) string {
	if group == "core" {
		return ""
	}
	return group
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
	// UnsafeDisableDeepCopy lets the cache return references into its store.
	// This path only reads metadata and never mutates returned objects.
	if err := kubeClient.List(ctx, list, client.UnsafeDisableDeepCopy); err != nil {
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
//	plural:<plural>                                          always
//	group:<group>                                            always; "core" for core resources
//	version:<version>                                        always; e.g. "v1", "v1beta1"
//	apiVersion:<apiVersion>                                  Kubernetes wire form: "v1" (core) or "<group>/<version>"
//	kind:<Kind>                                              always; e.g. "Pod", "Deployment"
//	name:<name>                                              always
//	namespace:<namespace>                                    omitted for cluster-scoped objects
//	key:<namespace>/<name>                                   `<namespace>/<name>` for namespaced objects; `<name>` for cluster-scoped
//	label:<key>:<value>                                      one per .metadata.labels entry
//	owner-key:<ownerAPIGroup>/<ownerKind>/<ownerName>        atomic identity of every owner reference by key
//	owner-uid:<ownerAPIGroup>/<ownerKind>/<ownerUID>         atomic identity of every owner reference by UID
//	controller-key:<ownerAPIGroup>/<ownerKind>/<ownerName>   atomic identity of every controller owner reference by key
//	controller-uid:<ownerAPIGroup>/<ownerKind>/<ownerUID>    atomic identity of every controller owner reference by UID
func getSelectorValuesFromObjectMeta(r *broker.KubernetesObjectType, gvk schema.GroupVersionKind, obj *metav1.PartialObjectMetadata) []string {
	objType := r.GetPlural() + "." + r.GetGroup()
	values := []string{
		"uid:" + string(obj.UID),
		"resource:" + objType,
		"plural:" + r.GetPlural(),
		"group:" + r.GetGroup(),
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

// getOrCreateKubeClient lazily builds a live, uncached controller-runtime
// client for full object reads and writes.
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

	restConfig, clientOptions, err := buildKubeClientOptions()
	if err != nil {
		return nil, err
	}
	c, err := client.New(restConfig, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to create Kubernetes client: %w", err)
	}
	p.kubeClient = c
	return c, nil
}

// getOrCreateKubeMetadataClient lazily builds the controller-runtime client
// used for PartialObjectMetadata. When the API server cache is enabled, only
// this client is cache-backed.
func (p *Plugin) getOrCreateKubeMetadataClient(ctx context.Context) (client.Client, error) {
	config, _, _, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	if !config.APIServerCacheEnabled {
		return p.getOrCreateKubeClient()
	}

	p.kubeMu.RLock()
	if p.kubeMetadataClient != nil {
		c := p.kubeMetadataClient
		p.kubeMu.RUnlock()
		return c, nil
	}
	p.kubeMu.RUnlock()

	p.kubeMu.Lock()
	defer p.kubeMu.Unlock()
	if p.kubeMetadataClient != nil {
		return p.kubeMetadataClient, nil
	}

	restConfig, clientOptions, err := buildKubeClientOptions()
	if err != nil {
		return nil, err
	}
	var liveClient client.Client
	if p.kubeClient == nil {
		liveClient, err = client.New(restConfig, clientOptions)
		if err != nil {
			return nil, fmt.Errorf("unable to create Kubernetes client: %w", err)
		}
	}

	// The cache-backed client is used exclusively with PartialObjectMetadata,
	// avoiding full-object cache storage for large resources. Full Pods are
	// fetched through the live client when non-metadata fields are needed.
	kubeCache, err := crcache.New(restConfig, crcache.Options{
		Scheme:           k8sScheme,
		Mapper:           clientOptions.Mapper,
		HTTPClient:       clientOptions.HTTPClient,
		DefaultTransform: crcache.TransformStripManagedFields(),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create Kubernetes cache: %w", err)
	}
	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cacheDone := make(chan struct{})
	go func() {
		defer close(cacheDone)
		if err := kubeCache.Start(cacheCtx); err != nil && cacheCtx.Err() == nil {
			if p.log != nil {
				p.log.Warn("Kubernetes cache stopped unexpectedly", telemetry.Error, err)
			}
		}
	}()
	if !kubeCache.WaitForCacheSync(ctx) {
		cacheCancel()
		<-cacheDone
		return nil, errors.New("timed out waiting for Kubernetes cache to start")
	}

	metadataClientOptions := clientOptions
	metadataClientOptions.Cache = &client.CacheOptions{
		Reader:       kubeCache,
		Unstructured: false, // Avoid caching unwanted large objects.
		DisableFor:   nil,   // No point in disabling for specific types.
	}
	c, err := client.New(restConfig, metadataClientOptions)
	if err != nil {
		cacheCancel()
		<-cacheDone
		return nil, fmt.Errorf("unable to create Kubernetes client: %w", err)
	}

	if p.kubeClient == nil {
		p.kubeClient = liveClient
	}
	p.kubeMetadataClient = c
	p.kubeCacheCancel = cacheCancel
	p.kubeCacheDone = cacheDone
	return c, nil
}

func buildKubeClientOptions() (*rest.Config, client.Options, error) {
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return nil, client.Options{}, fmt.Errorf("unable to load Kubernetes client config: %w", err)
	}
	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, client.Options{}, fmt.Errorf("unable to build Kubernetes HTTP client: %w", err)
	}
	mapper, err := apiutil.NewDynamicRESTMapper(restConfig, httpClient)
	if err != nil {
		return nil, client.Options{}, fmt.Errorf("unable to build Kubernetes REST mapper: %w", err)
	}

	return restConfig, client.Options{
		Scheme:     k8sScheme,
		Mapper:     mapper,
		HTTPClient: httpClient,
	}, nil
}

func (p *Plugin) Close() error {
	p.podListFetcher.close()
	p.kubeMu.Lock()
	cacheCancel := p.kubeCacheCancel
	cacheDone := p.kubeCacheDone
	p.kubeClient = nil
	p.kubeMetadataClient = nil
	p.kubeCacheCancel = nil
	p.kubeCacheDone = nil
	p.kubeMu.Unlock()

	if cacheCancel != nil {
		cacheCancel()
		<-cacheDone
	}
	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
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

	if !newConfig.DisableKubeletClient {
		if err := p.podListFetcher.configure(ctx, newConfig.podListFetcherConfig); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig
	p.containerHelper = newConfig.ContainerHelper
	p.sigstoreVerifier = sigstoreVerifier

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (resp *configv1.ValidateResponse, err error) {
	newConfig, notes, err := pluginconf.Build(req, p.buildConfig)
	if err == nil && !newConfig.DisableKubeletClient {
		err = p.podListFetcher.validate(newConfig.podListFetcherConfig)
		if err != nil {
			notes = append(notes, err.Error())
		}
	}

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
	return p.config, p.containerHelper, p.sigstoreVerifier, nil
}

func (p *Plugin) setContainerHelper(c ContainerHelper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.containerHelper = c
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
	podImages := make(map[string]struct{}, 2*len(containerStatuses))
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

func (p *Plugin) getNamespaceLabels(ctx context.Context, namespace string) (map[string]string, error) {
	kubeClient, err := p.getOrCreateKubeMetadataClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to set up kube client: %w", err)
	}

	obj := &metav1.PartialObjectMetadata{}
	obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
	if err := kubeClient.Get(ctx, client.ObjectKey{Name: namespace}, obj); err != nil {
		return nil, fmt.Errorf("unable to get namespace %q: %w", namespace, err)
	}

	return obj.Labels, nil
}

func getSelectorValuesFromNamespaceLabels(labels map[string]string) []string {
	selectorValues := make([]string, 0, len(labels))
	for k, v := range labels {
		selectorValues = append(selectorValues, fmt.Sprintf("ns-label:%s:%s", k, v))
	}
	return selectorValues
}

func getSelectorValuesFromPodInfo(pod *corev1.Pod) []string {
	selectorValues := []string{
		fmt.Sprintf("sa:%s", pod.Spec.ServiceAccountName),
		fmt.Sprintf("ns:%s", pod.Namespace),
		fmt.Sprintf("node-name:%s", pod.Spec.NodeName),
		fmt.Sprintf("pod-uid:%s", pod.UID),
		fmt.Sprintf("pod-name:%s", pod.Name),
		fmt.Sprintf("pod-image-count:%d", len(pod.Status.ContainerStatuses)),
		fmt.Sprintf("pod-init-image-count:%d", len(pod.Status.InitContainerStatuses)),
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
