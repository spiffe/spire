//go:build !windows

package k8s

import (
	"context"
	"log"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/k8s/sigstore"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (p *Plugin) defaultKubeletCAPath() string {
	return defaultKubeletCAPath
}

func (p *Plugin) defaultTokenPath() string {
	return defaultTokenPath
}

func createHelper(c *Plugin) ContainerHelper {
	return &containerHelper{
		fs: c.fs,
	}
}

type containerHelper struct {
	fs             cgroups.FileSystem
	sigstoreClient sigstore.Sigstore
}

func (h *containerHelper) Configure(config *HCLConfig, log hclog.Logger) error {
	// set experimental flags
	if config.Experimental != nil && config.Experimental.Sigstore != nil {
		if h.sigstoreClient == nil {
			newcache := sigstore.NewCache(maximumAmountCache)
			h.sigstoreClient = sigstore.New(newcache, nil)
		}

		if err := configureSigstoreClient(h.sigstoreClient, config.Experimental.Sigstore, log); err != nil {
			return err
		}
	}

	return nil
}

func (h *containerHelper) GetOSSelectors(ctx context.Context, log hclog.Logger, containerStatus *corev1.ContainerStatus) ([]string, error) {
	var selectors []string
	if h.sigstoreClient != nil {
		log.Debug("Attempting to get signature info for container", telemetry.ContainerName, containerStatus.Name)
		sigstoreSelectors, err := h.sigstoreClient.AttestContainerSignatures(ctx, containerStatus)
		if err != nil {
			log.Error("Error retrieving signature payload", "error", err)
			return nil, status.Errorf(codes.Internal, "error retrieving signature payload: %v", err)
		}
		selectors = append(selectors, sigstoreSelectors...)
	}

	return selectors, nil
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

// regexes listed here have to exclusively match a cgroup path
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
		`(?P<containerid>[[:xdigit:]]{64})$`),

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
		`(?P<containerid>[[:xdigit:]]{64})$`),
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

func configureSigstoreClient(client sigstore.Sigstore, c *SigstoreHCLConfig, log hclog.Logger) error {
	// Rekor URL is required
	if c.RekorURL == nil {
		return status.Errorf(codes.InvalidArgument, "missing Rekor URL")
	}
	if err := client.SetRekorURL(*c.RekorURL); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to set Rekor URL: %v", err)
	}

	// Configure sigstore settings
	enforceSCT := true
	if c.EnforceSCT != nil {
		enforceSCT = *c.EnforceSCT
	}

	client.SetEnforceSCT(enforceSCT)

	client.ClearSkipList()
	if c.SkippedImages != nil {
		client.AddSkippedImages(c.SkippedImages)
	}
	client.SetLogger(log)
	client.ClearAllowedSubjects()
	for issuer, subjects := range c.AllowedSubjects {
		for _, subject := range subjects {
			client.AddAllowedSubject(issuer, subject)
		}
	}
	return nil
}
