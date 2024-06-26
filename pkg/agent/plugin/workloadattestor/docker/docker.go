package docker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/common/sigstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName         = "docker"
	subselectorLabel   = "label"
	subselectorImageID = "image_id"
	subselectorEnv     = "env"
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

// Docker is a subset of the docker client functionality, useful for mocking.
type Docker interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	log     hclog.Logger
	retryer *retryer

	mtx              sync.RWMutex
	docker           Docker
	c                *containerHelper
	sigstoreVerifier sigstore.Verifier
}

func New() *Plugin {
	return &Plugin{
		retryer: newRetryer(),
	}
}

type dockerPluginConfig struct {
	OSConfig `hcl:",squash"`

	// DockerVersion is the API version of the docker daemon. If not specified, the version is negotiated by the client.
	DockerVersion string `hcl:"docker_version" json:"docker_version"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`

	Experimental *experimentalConfig `hcl:"experimental,omitempty"`
}

type experimentalConfig struct {
	// Sigstore contains sigstore specific configs.
	Sigstore *sigstoreHCLConfig `hcl:"sigstore,omitempty"`
}

type sigstoreHCLConfig struct {
	// AllowedIdentities is a list of identities (issuer and subjects) that must match for the signature to be valid.
	AllowedIdentities map[string][]string `hcl:"allowed_identities"`

	// SkippedImages is a list of images that should skip sigstore verification
	SkippedImages []string `hcl:"skipped_images"`

	// RekorURL is the URL for the Rekor transparency log server to use for verifying entries.
	RekorURL *string `hcl:"rekor_url,omitempty"`

	// IgnoreSCT specifies whether to bypass the requirement for a Signed Certificate Timestamp (SCT) during verification.
	// An SCT is proof of inclusion in a Certificate Transparency log.
	IgnoreSCT *bool `hcl:"ignore_sct, omitempty"`

	// IgnoreTlog specifies whether to bypass the requirement for transparency log verification during signature validation.
	IgnoreTlog *bool `hcl:"ignore_tlog, omitempty"`

	// IgnoreAttestations specifies whether to bypass the image attestations verification.
	IgnoreAttestations *bool `hcl:"ignore_attestations, omitempty"`

	// RegistryCredentials is a map of credentials keyed by registry URL
	RegistryCredentials map[string]*registryCredential `hcl:"registry_credentials,omitempty"`
}

type registryCredential struct {
	Username string `hcl:"username,omitempty"`
	Password string `hcl:"password,omitempty"`
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	containerID, err := p.c.getContainerID(req.Pid, p.log)
	switch {
	case err != nil:
		return nil, err
	case containerID == "":
		// Not a docker workload. Nothing more to do.
		return &workloadattestorv1.AttestResponse{}, nil
	}

	var container types.ContainerJSON
	err = p.retryer.Retry(ctx, func() error {
		container, err = p.docker.ContainerInspect(ctx, containerID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	selectors := getSelectorValuesFromConfig(container.Config)

	if p.sigstoreVerifier != nil {
		imageName := container.Config.Image
		imageJSON, _, err := p.docker.ImageInspectWithRaw(ctx, imageName)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect image %q: %w", imageName, err)
		}

		if len(imageJSON.RepoDigests) == 0 {
			return nil, fmt.Errorf("sigstore signature verification failed: no repo digest found for image %s", imageName)
		}

		var verified bool
		// RepoDigests is a list of content-addressable digests of locally available
		// image manifests that the image is referenced from. Multiple manifests can
		// refer to the same image.
		var allErrors []string
		for _, digest := range imageJSON.RepoDigests {
			sigstoreSelectors, err := p.sigstoreVerifier.Verify(ctx, digest)
			if err != nil {
				p.log.Warn("Error verifying sigstore image signature", "image_id", digest, "error", err)
				allErrors = append(allErrors, fmt.Sprintf("image_id %s: %v", digest, err))
				continue
			}
			selectors = append(selectors, sigstoreSelectors...)
			verified = true
			break
		}

		if !verified {
			return nil, fmt.Errorf("sigstore signature verification failed for image %s: %v", imageName, fmt.Sprintf("errors: %s", strings.Join(allErrors, "; ")))
		}
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectors,
	}, nil
}

func getSelectorValuesFromConfig(cfg *container.Config) []string {
	var selectorValues []string
	for label, value := range cfg.Labels {
		selectorValues = append(selectorValues, fmt.Sprintf("%s:%s:%s", subselectorLabel, label, value))
	}
	for _, e := range cfg.Env {
		selectorValues = append(selectorValues, fmt.Sprintf("%s:%s", subselectorEnv, e))
	}
	if cfg.Image != "" {
		selectorValues = append(selectorValues, fmt.Sprintf("%s:%s", subselectorImageID, cfg.Image))
	}
	return selectorValues
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	var err error
	config := &dockerPluginConfig{}
	if err = hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if len(config.UnusedKeyPositions) > 0 {
		var keys []string
		for k := range config.UnusedKeyPositions {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		return nil, status.Errorf(codes.InvalidArgument, "unknown configurations detected: %s", strings.Join(keys, ","))
	}

	containerHelper, err := createHelper(config, p.log)
	if err != nil {
		return nil, err
	}

	var opts []dockerclient.Opt
	dockerHost := getDockerHost(config)
	if dockerHost != "" {
		opts = append(opts, dockerclient.WithHost(dockerHost))
	}
	switch {
	case config.DockerVersion != "":
		opts = append(opts, dockerclient.WithVersion(config.DockerVersion))
	default:
		opts = append(opts, dockerclient.WithAPIVersionNegotiation())
	}

	docker, err := dockerclient.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	var sigstoreVerifier sigstore.Verifier
	if config.Experimental != nil {
		if config.Experimental.Sigstore != nil {
			cfg := newConfigFromHCL(config.Experimental.Sigstore, p.log)
			verifier := sigstore.NewVerifier(cfg)
			err = verifier.Init(ctx)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "error initializing sigstore verifier: %v", err)
			}
			sigstoreVerifier = verifier
		}
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.docker = docker
	p.c = containerHelper
	p.sigstoreVerifier = sigstoreVerifier
	return &configv1.ConfigureResponse{}, nil
}

func newConfigFromHCL(hclConfig *sigstoreHCLConfig, log hclog.Logger) *sigstore.Config {
	config := sigstore.NewConfig()
	config.Logger = log

	if hclConfig.AllowedIdentities != nil {
		config.AllowedIdentities = hclConfig.AllowedIdentities
	}

	if hclConfig.SkippedImages != nil {
		config.SkippedImages = hclConfig.SkippedImages
	}

	if hclConfig.RekorURL != nil {
		config.RekorURL = *hclConfig.RekorURL
	}

	if hclConfig.IgnoreSCT != nil {
		config.IgnoreSCT = *hclConfig.IgnoreSCT
	}

	if hclConfig.IgnoreTlog != nil {
		config.IgnoreTlog = *hclConfig.IgnoreTlog
	}

	if hclConfig.IgnoreAttestations != nil {
		config.IgnoreAttestations = *hclConfig.IgnoreAttestations
	}

	if hclConfig.RegistryCredentials != nil {
		m := make(map[string]*sigstore.RegistryCredential)
		for k, v := range hclConfig.RegistryCredentials {
			m[k] = &sigstore.RegistryCredential{
				Username: v.Username,
				Password: v.Password,
			}
		}
		config.RegistryCredentials = m
	}

	return config
}
