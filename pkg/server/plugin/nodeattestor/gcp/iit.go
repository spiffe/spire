package gcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

const (
	pluginName                  = "gcp_iit"
	tokenAudience               = "spire-gcp-node-attestor"
	googleCertURL               = "https://www.googleapis.com/oauth2/v1/certs"
	defaultMaxMetadataValueSize = 128
)

var (
	pluginErr = errs.Class("gcp-iit")
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IITAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		nodeattestor.PluginServer(p),
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
	config            *IITAttestorConfig
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

	ProjectIDWhitelist   []string `hcl:"projectid_whitelist"`
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
		tokenKeyRetriever: newGooglePublicKeyRetriever(googleCertURL),
		client:            googleComputeEngineClient{},
	}
}

// Attest implements the server side logic for the gcp iit node attestation plugin.
func (p *IITAttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	identityMetadata, err := validateAttestationAndExtractIdentityMetadata(stream, gcp.PluginName, p.tokenKeyRetriever)
	if err != nil {
		return err
	}

	projectIDMatchesWhitelist := false
	for _, projectID := range c.ProjectIDWhitelist {
		if identityMetadata.ProjectID == projectID {
			projectIDMatchesWhitelist = true
			break
		}
	}
	if !projectIDMatchesWhitelist {
		return pluginErr.New("identity token project ID %q is not in the whitelist", identityMetadata.ProjectID)
	}

	id, err := gcp.MakeSpiffeID(c.trustDomain, c.idPathTemplate, identityMetadata)
	if err != nil {
		return pluginErr.New("failed to create spiffe ID: %v", err)
	}

	attested, err := p.IsAttested(stream.Context(), id.String())
	switch {
	case err != nil:
		return pluginErr.Wrap(err)
	case attested:
		return pluginErr.New("IIT has already been used to attest an agent")
	}

	var instance *compute.Instance
	if c.UseInstanceMetadata {
		instance, err = p.client.fetchInstanceMetadata(stream.Context(), identityMetadata.ProjectID, identityMetadata.Zone, identityMetadata.InstanceName, c.ServiceAccountFile)
		if err != nil {
			return pluginErr.New("failed to fetch instance metadata: %v", err)
		}
	}

	selectors := []*common.Selector{
		makeSelector("project-id", identityMetadata.ProjectID),
		makeSelector("zone", identityMetadata.Zone),
		makeSelector("instance-name", identityMetadata.InstanceName),
	}
	if instance != nil {
		instanceSelectors, err := getInstanceSelectors(c, instance)
		if err != nil {
			return err
		}
		selectors = append(selectors, instanceSelectors...)
	}

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   id.String(),
		Selectors: selectors,
	})
}

// Configure configures the IITAttestorPlugin.
func (p *IITAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &IITAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, pluginErr.New("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, pluginErr.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, pluginErr.New("trust_domain is required")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	if len(config.ProjectIDWhitelist) == 0 {
		return nil, pluginErr.New("projectid_whitelist is required")
	}

	tmpl := gcp.DefaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, pluginErr.New("failed to parse agent path template: %q", config.AgentPathTemplate)
		}
	}

	if len(config.AllowedLabelKeys) > 0 {
		config.allowedLabelKeys = make(map[string]bool, len(config.AllowedLabelKeys))
		for _, key := range config.AllowedLabelKeys {
			config.allowedLabelKeys[key] = true
		}
	}

	if len(config.AllowedMetadataKeys) > 0 {
		config.allowedMetadataKeys = make(map[string]bool, len(config.AllowedMetadataKeys))
		for _, key := range config.AllowedMetadataKeys {
			config.allowedMetadataKeys[key] = true
		}
	}

	if config.MaxMetadataValueSize == 0 {
		config.MaxMetadataValueSize = defaultMaxMetadataValueSize
	}

	config.idPathTemplate = tmpl

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and related metadata of the installed plugin.
func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *IITAttestorPlugin) getConfig() (*IITAttestorConfig, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.config == nil {
		return nil, pluginErr.New("not configured")
	}
	return p.config, nil
}

func getInstanceSelectors(config *IITAttestorConfig, instance *compute.Instance) ([]*common.Selector, error) {
	metadata, err := getInstanceMetadata(instance, config.allowedMetadataKeys, config.MaxMetadataValueSize)
	if err != nil {
		return nil, err
	}

	var selectors []*common.Selector
	for _, tag := range getInstanceTags(instance) {
		selectors = append(selectors, makeSelector("tag", tag))
	}
	for _, serviceAccount := range getInstanceServiceAccounts(instance) {
		selectors = append(selectors, makeSelector("sa", serviceAccount))
	}
	for _, label := range getInstanceLabels(instance, config.allowedLabelKeys) {
		selectors = append(selectors, makeSelector("label", label.key, label.value))
	}
	for _, md := range metadata {
		selectors = append(selectors, makeSelector("metadata", md.key, md.value))
	}
	return selectors, nil
}

type keyValue struct {
	key   string
	value string
}

func validateAttestationAndExtractIdentityMetadata(stream nodeattestor.NodeAttestor_AttestServer, pluginName string, tokenRetriever tokenKeyRetriever) (gcp.ComputeEngine, error) {
	req, err := stream.Recv()
	if err != nil {
		return gcp.ComputeEngine{}, err
	}

	attestationData := req.GetAttestationData()
	if attestationData == nil {
		return gcp.ComputeEngine{}, pluginErr.New("request missing attestation data")
	}

	if attestationData.Type != pluginName {
		return gcp.ComputeEngine{}, pluginErr.New("unexpected attestation data type %q", attestationData.Type)
	}

	identityToken := &gcp.IdentityToken{}
	_, err = jwt.ParseWithClaims(string(req.GetAttestationData().Data), identityToken, tokenRetriever.retrieveKey)
	if err != nil {
		return gcp.ComputeEngine{}, pluginErr.New("unable to parse/validate the identity token: %v", err)
	}

	if identityToken.Audience != tokenAudience {
		return gcp.ComputeEngine{}, pluginErr.New("unexpected identity token audience %q", identityToken.Audience)
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
				return nil, pluginErr.New("metadata %q exceeded value limit (%d > %d)", item.Key, len(value), maxValueSize)
			}
		}
		md = append(md, keyValue{
			key:   item.Key,
			value: value,
		})
	}
	return md, nil
}

func makeSelector(key string, value ...string) *common.Selector {
	return &common.Selector{
		Type:  pluginName,
		Value: fmt.Sprintf("%s:%s", key, strings.Join(value, ":")),
	}
}

type googleComputeEngineClient struct {
}

func (c googleComputeEngineClient) fetchInstanceMetadata(ctx context.Context, projectID, zone, instanceName string, serviceAccountPath string) (*compute.Instance, error) {
	service, err := c.getService(ctx, serviceAccountPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service client: %v", err)
	}
	instance, err := service.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch instance metadata: %v", err)
	}
	return instance, nil
}

func (c googleComputeEngineClient) getService(ctx context.Context, serviceAccountFile string) (*compute.Service, error) {
	if serviceAccountFile != "" {
		return compute.NewService(ctx, option.WithCredentialsFile(serviceAccountFile))
	}
	return compute.NewService(ctx)
}
