//go:build !windows
// +build !windows

package k8s

import (
	"log"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/k8s/sigstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
)

func (p *Plugin) defaultKubeletCAPath() string {
	return defaultKubeletCAPath
}

func (p *Plugin) defaultTokenPath() string {
	return defaultTokenPath
const (
	defaultMaxPollAttempts   = 60
	defaultPollRetryInterval = time.Millisecond * 500
	defaultSecureKubeletPort = 10250
	defaultKubeletCAPath     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenPath         = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // false positive
	defaultNodeNameEnv       = "MY_NODE_NAME"
	defaultReloadInterval    = time.Minute
)

type containerLookup int

const (
	containerInPod = iota
	containerNotInPod
	maximumAmountCache = 10
)

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

	// RekorURL is the URL for the rekor server to use to verify signatures and public keys
	RekorURL string `hcl:"sigstore.rekor_url"`

	// SkippedImages is a list of images that should skip sigstore verification
	SkippedImages []string `hcl:"sigstore.skip_signature_verification_image_list"`

	// AllowedSubjects is a flag indicating whether signature subjects should be compared against the allow-list
	AllowedSubjectListEnabled bool `hcl:"sigstore.enable_allowed_subjects_list"`

	// AllowedSubjects is a list of subjects that should be allowed after verification
	AllowedSubjects []string `hcl:"sigstore.allowed_subjects_list"`
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

	RekorURL      string
	SkippedImages []string

	AllowedSubjectListEnabled bool
	AllowedSubjects           []string

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

	sigstore sigstore.Sigstore
}

func New() *Plugin {
	newcache := sigstore.NewCache(maximumAmountCache)
	return &Plugin{
		fs:       cgroups.OSFileSystem{},
		clock:    clock.New(),
		getenv:   os.Getenv,
		sigstore: sigstore.New(newcache, nil),
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
	p.sigstore.SetLogger(log)
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	podUID, containerID, err := p.getPodUIDAndContainerIDFromCGroups(req.Pid)
	if err != nil {
		return nil, err
	}

	// Not a Kubernetes pod
	if containerID == "" {
		return &workloadattestorv1.AttestResponse{}, nil
	}

	log := p.log.With(
		telemetry.PodUID, podUID,
		telemetry.ContainerID, containerID,
	)

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
			if item.UID != podUID {
				continue
			}

			status, lookup := lookUpContainerInPod(containerID, item.Status)
			switch lookup {
			case containerInPod:
				selectors := getSelectorValuesFromPodInfo(&item, status)
				log.Debug("Attemping to get signature info from image", status.Name)
				sigstoreSelectors, err := p.sigstore.AttestContainerSignatures(ctx, status)
				if err != nil {
					log.Error("Error retrieving signature payload: ", "error", err)
				} else {
					selectors = append(selectors, sigstoreSelectors...)
				}

				return &workloadattestorv1.AttestResponse{
					SelectorValues: selectors,
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

		RekorURL:                  config.RekorURL,
		SkippedImages:             config.SkippedImages,
		AllowedSubjectListEnabled: config.AllowedSubjectListEnabled,
		AllowedSubjects:           config.AllowedSubjects,
	}
	if err := p.reloadKubeletClient(c); err != nil {
		return nil, err
	}
	if p.sigstore != nil {
		if err := configureSigstore(c, p.sigstore); err != nil {
			return nil, err
		}
	}
	// Set the config
	p.setConfig(c)
	return &configv1.ConfigureResponse{}, nil
}

func createHelper(c *Plugin) (ContainerHelper, error) {
	return &containerHelper{
		fs: c.fs,
	}, nil

func configureSigstore(config *k8sConfig, sigstore sigstore.Sigstore) error {
	// Configure sigstore settings
	sigstore.ClearSkipList()
	if config.SkippedImages != nil {
		for _, imageID := range config.SkippedImages {
			sigstore.AddSkippedImage(imageID)
		}
	}
	sigstore.EnableAllowSubjectList(config.AllowedSubjectListEnabled)
	sigstore.ClearAllowedSubjects()
	if config.AllowedSubjects != nil {
		for _, subject := range config.AllowedSubjects {
			sigstore.AddAllowedSubject(subject)
		}
	}
	if config.RekorURL != "" {
		if err := sigstore.SetRekorURL(config.RekorURL); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) setConfig(config *k8sConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

type containerHelper struct {
	fs cgroups.FileSystem
}

func (h *containerHelper) GetPodUIDAndContainerID(pID int32, _ hclog.Logger) (types.UID, string, error) {
	cgroups, err := cgroups.GetCgroups(pID, h.fs)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to obtain cgroups: %v", err)
	}

	return getPodUIDAndContainerIDFromCGroups(cgroups)
}

func getPodUIDAndContainerIDFromCGroups(cgroups []cgroups.Cgroup) (types.UID, string, error) {
	var podUID types.UID
	var containerID string
	for _, cgroup := range cgroups {
		candidatePodUID, candidateContainerID, ok := getPodUIDAndContainerIDFromCGroupPath(cgroup.GroupPath)
		switch {
		case !ok:
			// Cgroup did not contain a container ID.
			continue
		case containerID == "":
			// This is the first container ID found so far.
			podUID = candidatePodUID
			containerID = candidateContainerID
		case containerID != candidateContainerID:
			// More than one container ID found in the cgroups.
			return "", "", status.Errorf(codes.FailedPrecondition, "multiple container IDs found in cgroups (%s, %s)",
				containerID, candidateContainerID)
		case podUID != candidatePodUID:
			// More than one pod UID found in the cgroups.
			return "", "", status.Errorf(codes.FailedPrecondition, "multiple pod UIDs found in cgroups (%s, %s)",
				podUID, candidatePodUID)
		}
	}

	return podUID, containerID, nil
}

// regexes listed here have to exlusively match a cgroup path
// the regexes must include two named groups "poduid" and "containerid"
// if the regex needs to exclude certain substrings, the "mustnotmatch" group can be used
var cgroupREs = []*regexp.Regexp{
	// the regex used to parse out the pod UID and container ID from a
	// cgroup name. It assumes that any ".scope" suffix has been trimmed off
	// beforehand.  CAUTION: we used to verify that the pod and container id were
	// descendants of a kubepods directory, however, as of Kubernetes 1.21, cgroups
	// namespaces are in use and therefore we can no longer discern if that is the
	// case from within SPIRE agent container (since the container itself is
	// namespaced). As such, the regex has been relaxed to simply find the pod UID
	// followed by the container ID with allowances for arbitrary punctuation, and
	// container runtime prefixes, etc.
	regexp.MustCompile(`` +
		// "pod"-prefixed Pod UID (with punctuation separated groups) followed by punctuation
		`[[:punct:]]pod(?P<poduid>[[:xdigit:]]{8}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{12})[[:punct:]]` +
		// zero or more punctuation separated "segments" (e.g. "docker-")
		`(?:[[:^punct:]]+[[:punct:]])*` +
		// non-punctuation end of string, i.e., the container ID
		`(?P<containerid>[[:^punct:]]+)$`),

	// This regex applies for container runtimes, that won't put the PodUID into
	// the cgroup name.
	// Currently only cri-o in combination with kubeedge is known for this abnormally.
	regexp.MustCompile(`` +
		// intentionally empty poduid group
		`(?P<poduid>)` +
		// mustnotmatch group: cgroup path must not include a poduid
		`(?P<mustnotmatch>pod[[:xdigit:]]{8}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{4}[[:punct:]]?[[:xdigit:]]{12}[[:punct:]])?` +
		// /crio-
		`(?:[[:^punct:]]*/*)*crio[[:punct:]]` +
		// non-punctuation end of string, i.e., the container ID
		`(?P<containerid>[[:^punct:]]+)$`),
}

func reSubMatchMap(r *regexp.Regexp, str string) map[string]string {
	match := r.FindStringSubmatch(str)
	if match == nil {
		return nil
	}
	subMatchMap := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i != 0 {
			subMatchMap[name] = match[i]
		}
	}
	return subMatchMap
}

func isValidCGroupPathMatches(matches map[string]string) bool {
	if matches == nil {
		return false
	}
	if matches["mustnotmatch"] != "" {
		return false
	}
	return true
}

func getPodUIDAndContainerIDFromCGroupPath(cgroupPath string) (types.UID, string, bool) {
	// We are only interested in kube pods entries, for example:
	// - /kubepods/burstable/pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
	// - /docker/8d461fa5765781bcf5f7eb192f101bc3103d4b932e26236f43feecfa20664f96/kubepods/besteffort/poddaa5c7ee-3484-4533-af39-3591564fd03e/aff34703e5e1f89443e9a1bffcc80f43f74d4808a2dd22c8f88c08547b323934
	// - /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c48913c-b29f-11e7-9350-020968147796.slice/docker-9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961.scope
	// - /kubepods-besteffort-pod72f7f152_440c_66ac_9084_e0fc1d8a910c.slice:cri-containerd:b2a102854b4969b2ce98dc329c86b4fb2b06e4ad2cc8da9d8a7578c9cd2004a2"
	// - /../../pod2c48913c-b29f-11e7-9350-020968147796/9bca8d63d5fa610783847915bcff0ecac1273e5b4bed3f6fa1b07350e0135961
	// - 0::/../crio-45490e76e0878aaa4d9808f7d2eefba37f093c3efbba9838b6d8ab804d9bd814.scope
	// First trim off any .scope suffix. This allows for a cleaner regex since
	// we don't have to muck with greediness. TrimSuffix is no-copy so this
	// is cheap.
	cgroupPath = strings.TrimSuffix(cgroupPath, ".scope")

	var matchResults map[string]string
	for _, regex := range cgroupREs {
		matches := reSubMatchMap(regex, cgroupPath)
		if isValidCGroupPathMatches(matches) {
			if matchResults != nil {
				log.Printf("More than one regex matches for cgroup %s", cgroupPath)
				return "", "", false
			}
			matchResults = matches
		}
	}

	if matchResults != nil {
		var podUID types.UID
		if matchResults["poduid"] != "" {
			podUID = canonicalizePodUID(matchResults["poduid"])
		}
		return podUID, matchResults["containerid"], true
	}
	return "", "", false
}

// canonicalizePodUID converts a Pod UID, as represented in a cgroup path, into
// a canonical form. Practically this means that we convert any punctuation to
// dashes, which is how the UID is represented within Kubernetes.
func canonicalizePodUID(uid string) types.UID {
	return types.UID(strings.Map(func(r rune) rune {
		if unicode.IsPunct(r) {
			r = '-'
		}
		return r
	}, uid))
}
