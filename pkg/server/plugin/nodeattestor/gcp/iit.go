package gcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/hashicorp/hcl"

	jwt "github.com/dgrijalva/jwt-go"
	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
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

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *IITAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type tokenKeyRetriever interface {
	retrieveKey(token *jwt.Token) (interface{}, error)
}

type computeEngineClient interface {
	fetchInstanceMetadata(ctx context.Context, projectID, zone, instanceName string, serviceAccountFile string) (*compute.Instance, error)
}

// IITAttestorPlugin implements node attestation for agents running in GCP.
type IITAttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	config            *IITAttestorConfig
	log               hclog.Logger
	mtx               sync.Mutex
	tokenKeyRetriever tokenKeyRetriever
	client            computeEngineClient
}

// IITAttestorConfig is the config for IITAttestorPlugin.
type IITAttestorConfig struct {
	idPathTemplate      *template.Template
	trustDomain         string
	allowedLabelKeys    map[string]bool
	allowedMetadataKeys map[string]bool

	ProjectIDAllowList   []string `hcl:"projectid_allow_list"`
	AgentPathTemplate    string   `hcl:"agent_path_template"`
	UseInstanceMetadata  bool     `hcl:"use_instance_metadata"`
	AllowedLabelKeys     []string `hcl:"allowed_label_keys"`
	AllowedMetadataKeys  []string `hcl:"allowed_metadata_keys"`
	MaxMetadataValueSize int      `hcl:"max_metadata_value_size"`
	ServiceAccountFile   string   `hcl:"service_account_file"`

	// TODO: Remove in 1.1.0
	ProjectIDAllowListDeprecated []string `hcl:"projectid_whitelist"`
}

// New creates a new IITAttestorPlugin.
func New() *IITAttestorPlugin {
	return &IITAttestorPlugin{
		tokenKeyRetriever: newGooglePublicKeyRetriever(googleCertURL),
		client:            googleComputeEngineClient{},
	}
}

// SetLogger sets up plugin logging
func (p *IITAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest implements the server side logic for the gcp iit node attestation plugin.
func (p *IITAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	identityMetadata, err := validateAttestationAndExtractIdentityMetadata(stream, p.tokenKeyRetriever)
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

	id, err := gcp.MakeSpiffeID(c.trustDomain, c.idPathTemplate, identityMetadata)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create spiffe ID: %v", err)
	}

	attested, err := p.IsAttested(stream.Context(), id.String())
	switch {
	case err != nil:
		return err
	case attested:
		return status.Error(codes.PermissionDenied, "IIT has already been used to attest an agent")
	}

	var instance *compute.Instance
	if c.UseInstanceMetadata {
		instance, err = p.client.fetchInstanceMetadata(stream.Context(), identityMetadata.ProjectID, identityMetadata.Zone, identityMetadata.InstanceName, c.ServiceAccountFile)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to fetch instance metadata: %v", err)
		}
	}

	selectorValues := []string{
		makeSelector("project-id", identityMetadata.ProjectID),
		makeSelector("zone", identityMetadata.Zone),
		makeSelector("instance-name", identityMetadata.InstanceName),
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
			},
		},
	})
}

// Configure configures the IITAttestorPlugin.
func (p *IITAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
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
	hclConfig.trustDomain = req.CoreConfiguration.TrustDomain

	// TODO: Remove in 1.1.0
	if len(hclConfig.ProjectIDAllowListDeprecated) > 0 {
		p.log.Warn("The `projectid_whitelist` configurable is deprecated and will be removed in a future release. Please use `projectid_allow_list` instead.")
		hclConfig.ProjectIDAllowList = hclConfig.ProjectIDAllowListDeprecated
	}

	if len(hclConfig.ProjectIDAllowList) == 0 {
		return nil, status.Error(codes.InvalidArgument, "projectid_allow_list is required")
	}

	tmpl := gcp.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = template.New("agent-path").Parse(hclConfig.AgentPathTemplate)
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
		selectorValues = append(selectorValues, makeSelector("tag", tag))
	}
	for _, serviceAccount := range getInstanceServiceAccounts(instance) {
		selectorValues = append(selectorValues, makeSelector("sa", serviceAccount))
	}
	for _, label := range getInstanceLabels(instance, config.allowedLabelKeys) {
		selectorValues = append(selectorValues, makeSelector("label", label.key, label.value))
	}
	for _, md := range metadata {
		selectorValues = append(selectorValues, makeSelector("metadata", md.key, md.value))
	}
	return selectorValues, nil
}

type keyValue struct {
	key   string
	value string
}

func validateAttestationAndExtractIdentityMetadata(stream nodeattestorv1.NodeAttestor_AttestServer, tokenRetriever tokenKeyRetriever) (gcp.ComputeEngine, error) {
	req, err := stream.Recv()
	if err != nil {
		return gcp.ComputeEngine{}, err
	}

	payload := req.GetPayload()
	if payload == nil {
		return gcp.ComputeEngine{}, status.Errorf(codes.InvalidArgument, "missing attestation payload")
	}

	identityToken := &gcp.IdentityToken{}
	_, err = jwt.ParseWithClaims(string(payload), identityToken, tokenRetriever.retrieveKey)
	if err != nil {
		return gcp.ComputeEngine{}, status.Errorf(codes.InvalidArgument, "unable to parse/validate the identity token: %v", err)
	}

	if identityToken.Audience != tokenAudience {
		return gcp.ComputeEngine{}, status.Errorf(codes.PermissionDenied, "unexpected identity token audience %q", identityToken.Audience)
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

func makeSelector(key string, value ...string) string {
	return fmt.Sprintf("%s:%s", key, strings.Join(value, ":"))
}

type googleComputeEngineClient struct {
}

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
