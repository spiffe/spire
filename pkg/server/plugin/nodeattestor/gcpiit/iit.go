package gcpiit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName                  = "gcp_iit"
	tokenAudience               = "spire-gcp-node-attestor" //nolint: gosec // false positive
	googleCertURL               = "https://www.googleapis.com/oauth2/v1/certs"
	defaultMaxMetadataValueSize = 128
)

// Per GCP documentation, IITs are always signed using the RS256 signature algorithm:
// https://cloud.google.com/compute/docs/instances/verifying-instance-identity#verify_signature
var allowedJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *IITAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type jwksRetriever interface {
	retrieveJWKS(context.Context) (*jose.JSONWebKeySet, error)
}

type computeEngineClient interface {
	fetchInstanceMetadata(ctx context.Context, projectID, zone, instanceName string, serviceAccountFile string) (*compute.Instance, error)
}

// IITAttestorPlugin implements node attestation for agents running in GCP.
type IITAttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	config        *IITAttestorConfig
	log           hclog.Logger
	mtx           sync.Mutex
	jwksRetriever jwksRetriever
	client        computeEngineClient
}

// IITAttestorConfig is the config for IITAttestorPlugin.
type IITAttestorConfig struct {
	idPathTemplate      *agentpathtemplate.Template
	trustDomain         spiffeid.TrustDomain
	allowedLabelKeys    map[string]bool
	allowedMetadataKeys map[string]bool

	ProjectIDAllowList   []string `hcl:"projectid_allow_list"`
	AgentPathTemplate    string   `hcl:"agent_path_template"`
	UseInstanceMetadata  bool     `hcl:"use_instance_metadata"`
	AllowedLabelKeys     []string `hcl:"allowed_label_keys"`
	AllowedMetadataKeys  []string `hcl:"allowed_metadata_keys"`
	MaxMetadataValueSize int      `hcl:"max_metadata_value_size"`
	ServiceAccountFile   string   `hcl:"service_account_file"`
}

// New creates a new IITAttestorPlugin.
func New() *IITAttestorPlugin {
	return &IITAttestorPlugin{
		jwksRetriever: newGooglePublicKeyRetriever(googleCertURL),
		client:        googleComputeEngineClient{},
	}
}

// SetLogger sets up plugin logging
func (p *IITAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest implements the server side logic for the gcp iit node attestation plugin.
func (p *IITAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	jwks, err := p.jwksRetriever.retrieveJWKS(stream.Context())
	if err != nil {
		return err
	}

	identityMetadata, err := validateAttestationAndExtractIdentityMetadata(stream, jwks)
	if err != nil {
		return err
	}

	c, err := p.getConfig()
	if err != nil {
		return err
	}

	projectIDMatchesAllowList := false
	for _, projectID := range c.ProjectIDAllowList {
		if identityMetadata.ProjectID == projectID {
			projectIDMatchesAllowList = true
			break
		}
	}
	if !projectIDMatchesAllowList {
		return status.Errorf(codes.PermissionDenied, "identity token project ID %q is not in the allow list", identityMetadata.ProjectID)
	}

	id, err := gcp.MakeAgentID(c.trustDomain, c.idPathTemplate, identityMetadata)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create agent ID: %v", err)
	}

	if err := p.AssessTOFU(stream.Context(), id.String(), p.log); err != nil {
		return err
	}

	var instance *compute.Instance
	if c.UseInstanceMetadata {
		instance, err = p.client.fetchInstanceMetadata(stream.Context(), identityMetadata.ProjectID, identityMetadata.Zone, identityMetadata.InstanceName, c.ServiceAccountFile)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to fetch instance metadata: %v", err)
		}
	}

	selectorValues := []string{
		makeSelectorValue("project-id", identityMetadata.ProjectID),
		makeSelectorValue("zone", identityMetadata.Zone),
		makeSelectorValue("instance-name", identityMetadata.InstanceName),
	}
	if instance != nil {
		instanceSelectors, err := getInstanceSelectorValues(c, instance)
		if err != nil {
			return err
		}
		selectorValues = append(selectorValues, instanceSelectors...)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       id.String(),
				SelectorValues: selectorValues,
				CanReattest:    false,
			},
		},
	})
}

// Configure configures the IITAttestorPlugin.
func (p *IITAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConfig := new(IITAttestorConfig)
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "global configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is invalid: %v", err)
	}

	if len(hclConfig.ProjectIDAllowList) == 0 {
		return nil, status.Error(codes.InvalidArgument, "projectid_allow_list is required")
	}

	tmpl := gcp.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent path template: %q", hclConfig.AgentPathTemplate)
		}
	}

	if len(hclConfig.AllowedLabelKeys) > 0 {
		hclConfig.allowedLabelKeys = make(map[string]bool, len(hclConfig.AllowedLabelKeys))
		for _, key := range hclConfig.AllowedLabelKeys {
			hclConfig.allowedLabelKeys[key] = true
		}
	}

	if len(hclConfig.AllowedMetadataKeys) > 0 {
		hclConfig.allowedMetadataKeys = make(map[string]bool, len(hclConfig.AllowedMetadataKeys))
		for _, key := range hclConfig.AllowedMetadataKeys {
			hclConfig.allowedMetadataKeys[key] = true
		}
	}

	if hclConfig.MaxMetadataValueSize == 0 {
		hclConfig.MaxMetadataValueSize = defaultMaxMetadataValueSize
	}

	hclConfig.idPathTemplate = tmpl
	hclConfig.trustDomain = trustDomain

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = hclConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *IITAttestorPlugin) getConfig() (*IITAttestorConfig, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func getInstanceSelectorValues(config *IITAttestorConfig, instance *compute.Instance) ([]string, error) {
	metadata, err := getInstanceMetadata(instance, config.allowedMetadataKeys, config.MaxMetadataValueSize)
	if err != nil {
		return nil, err
	}

	var selectorValues []string
	for _, tag := range getInstanceTags(instance) {
		selectorValues = append(selectorValues, makeSelectorValue("tag", tag))
	}
	for _, serviceAccount := range getInstanceServiceAccounts(instance) {
		selectorValues = append(selectorValues, makeSelectorValue("sa", serviceAccount))
	}
	for _, label := range getInstanceLabels(instance, config.allowedLabelKeys) {
		selectorValues = append(selectorValues, makeSelectorValue("label", label.key, label.value))
	}
	for _, md := range metadata {
		selectorValues = append(selectorValues, makeSelectorValue("metadata", md.key, md.value))
	}
	return selectorValues, nil
}

type keyValue struct {
	key   string
	value string
}

func validateAttestationAndExtractIdentityMetadata(stream nodeattestorv1.NodeAttestor_AttestServer, jwks *jose.JSONWebKeySet) (gcp.ComputeEngine, error) {
	req, err := stream.Recv()
	if err != nil {
		return gcp.ComputeEngine{}, err
	}

	payload := req.GetPayload()
	if payload == nil {
		return gcp.ComputeEngine{}, status.Errorf(codes.InvalidArgument, "missing attestation payload")
	}

	token, err := jwt.ParseSigned(string(payload), allowedJWTSignatureAlgorithms)
	if err != nil {
		return gcp.ComputeEngine{}, status.Errorf(codes.InvalidArgument, "unable to parse the identity token: %v", err)
	}

	identityToken := &gcp.IdentityToken{}
	if err := token.Claims(jwks, identityToken); err != nil {
		return gcp.ComputeEngine{}, status.Errorf(codes.InvalidArgument, "failed to validate the identity token signature: %v", err)
	}

	if err := identityToken.Validate(jwt.Expected{
		AnyAudience: []string{tokenAudience},
		Time:        time.Now(),
	}); err != nil {
		return gcp.ComputeEngine{}, status.Errorf(codes.PermissionDenied, "failed to validate the identity token claims: %v", err)
	}

	return identityToken.Google.ComputeEngine, nil
}

func getInstanceTags(instance *compute.Instance) []string {
	if instance.Tags != nil {
		return instance.Tags.Items
	}
	return nil
}

func getInstanceServiceAccounts(instance *compute.Instance) []string {
	var sa []string
	for _, serviceAccount := range instance.ServiceAccounts {
		sa = append(sa, serviceAccount.Email)
	}
	return sa
}

func getInstanceLabels(instance *compute.Instance, allowedKeys map[string]bool) []keyValue {
	var labels []keyValue
	for k, v := range instance.Labels {
		if !allowedKeys[k] {
			continue
		}
		labels = append(labels, keyValue{
			key:   k,
			value: v,
		})
	}
	return labels
}

func getInstanceMetadata(instance *compute.Instance, allowedKeys map[string]bool, maxValueSize int) ([]keyValue, error) {
	if instance.Metadata == nil {
		return nil, nil
	}
	var md []keyValue
	for _, item := range instance.Metadata.Items {
		if !allowedKeys[item.Key] {
			continue
		}

		var value string
		if item.Value != nil {
			value = *item.Value
			if len(value) > maxValueSize {
				return nil, status.Errorf(codes.Internal, "metadata %q exceeded value limit (%d > %d)", item.Key, len(value), maxValueSize)
			}
		}
		md = append(md, keyValue{
			key:   item.Key,
			value: value,
		})
	}
	return md, nil
}

func makeSelectorValue(key string, value ...string) string {
	return fmt.Sprintf("%s:%s", key, strings.Join(value, ":"))
}

type googleComputeEngineClient struct{}

func (c googleComputeEngineClient) fetchInstanceMetadata(ctx context.Context, projectID, zone, instanceName string, serviceAccountFile string) (*compute.Instance, error) {
	service, err := c.getService(ctx, serviceAccountFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service client: %w", err)
	}
	instance, err := service.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch instance metadata: %w", err)
	}
	return instance, nil
}

func (c googleComputeEngineClient) getService(ctx context.Context, serviceAccountFile string) (*compute.Service, error) {
	if serviceAccountFile != "" {
		return compute.NewService(ctx, option.WithCredentialsFile(serviceAccountFile))
	}
	return compute.NewService(ctx)
}
