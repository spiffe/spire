package akeylesskms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/gofrs/uuid/v5"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	AkeylessURL                    = "AKEYLESS_GATEWAY_URL"
	AkeylessAccessType             = "AKEYLESS_ACCESS_TYPE"
	AkeylessAccessID               = "AKEYLESS_ACCESS_ID"
	AkeylessAccessKey              = "AKEYLESS_ACCESS_KEY"
	Credentials                    = "CREDENTIALS"
	AkeylessTargetFolder           = "AKEYLESS_TARGET_FOLDER"
	AkeylessAzureObjectID          = "AKEYLESS_AZURE_OBJECT_ID"
	AkeylessGCPAudience            = "AKEYLESS_GCP_AUDIENCE"
	AkeylessK8SServiceAccountToken = "AKEYLESS_K8S_SERVICE_ACCOUNT_TOKEN"
	AkeylessK8SAuthConfigName      = "AKEYLESS_K8S_AUTH_CONFIG_NAME"
	defaultAkeylessGatewayURL      = "http://localhost:8080/v2"
)

type accessType string

const (
	AccessKey accessType = "access_key"
	AWSIAM    accessType = "aws_iam"
	AzureAD   accessType = "azure_ad"
	GCP       accessType = "gcp"
	K8S       accessType = "k8s"
)

var (
	AklClient *akeyless.V2ApiService
)

// Config defines the configuration for the plugin.
type Config struct {
	log                            hclog.Logger
	TrustDomain                    string
	ServerID                       string
	KeyMetadataFile                string `hcl:"key_metadata_file" json:"key_metadata_file"`
	AkeylessTargetFolder           string `hcl:"target_folder" json:"target_folder"`
	AkeylessGatewayURL             string `hcl:"akeyless_gateway_url" json:"akeyless_gateway_url"`
	AkeylessAccessType             string `hcl:"access_type" json:"access_type"`
	AkeylessAccessID               string `hcl:"access_id" json:"access_id"`
	AkeylessAccessKey              string `hcl:"access_key" json:"access_key"`
	AkeylessAzureObjectID          string `hcl:"azure_object_id" json:"azure_object_id"`
	AkeylessGCPAudience            string `hcl:"gcp_audience" json:"gcp_audience"`
	AkeylessK8SServiceAccountToken string `hcl:"k8s_service_account_token" json:"k8s_service_account_token"`
	AkeylessK8SAuthConfigName      string `hcl:"k8s_auth_config_name" json:"k8s_auth_config_name"`
}

func loadServerID(idPath string) (string, error) {
	// get id from path
	data, err := os.ReadFile(idPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createServerID(idPath)
	case err != nil:
		return "", status.Errorf(codes.Internal, "failed to read server id from path: %v", err)
	}

	// validate what we got is a uuid
	serverID, err := uuid.FromString(string(data))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to parse server id from path: %v", err)
	}
	return serverID.String(), nil
}

func createServerID(idPath string) (string, error) {
	// generate id
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate id for server: %v", err)
	}
	id := u.String()

	// persist id
	err = diskutil.WritePrivateFile(idPath, []byte(id))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to persist server id on path: %v", err)
	}
	return id, nil
}

func ParseAndValidateConfig(req *configv1.ConfigureRequest, log hclog.Logger) (*Config, error) {
	config := &Config{log: log, TrustDomain: req.CoreConfiguration.TrustDomain}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, fmt.Sprintf("failed to decode configuration: %v", err.Error()))
	}

	serverID, err := loadServerID(config.KeyMetadataFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loaded server id", "server_id", serverID)
	config.ServerID = serverID

	if err := config.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, fmt.Sprintf("failed to validate configuration: %v", err.Error()))
	}

	AklClient = createClient(config.AkeylessGatewayURL)

	aklsAccessType := string(config.ClientAuth(AklClient))
	if aklsAccessType == "" {
		return nil, status.Errorf(codes.InvalidArgument, "failed to connect client and detect access type")
	}
	config.AkeylessAccessType = aklsAccessType

	log.Info(fmt.Sprintf("successfully connected using %v access type", config.AkeylessAccessType))

	return config, nil
}

func (c *Config) UsingAccessKey() bool {
	return accessType(c.AkeylessAccessType) == AccessKey
}

func (c *Config) UsingAWS() bool {
	return accessType(c.AkeylessAccessType) == AWSIAM
}

func (c *Config) UsingAzure() bool {
	return accessType(c.AkeylessAccessType) == AzureAD
}

func (c *Config) UsingGCP() bool {
	return accessType(c.AkeylessAccessType) == GCP
}

func (c *Config) UsingK8S() bool {
	return accessType(c.AkeylessAccessType) == K8S
}

func (c *Config) Validate() error {
	// Some basic validation checks.

	if c.AkeylessTargetFolder == "" {
		c.AkeylessTargetFolder = os.Getenv(AkeylessTargetFolder)
	}

	if c.AkeylessGatewayURL == "" {
		c.AkeylessGatewayURL = os.Getenv(AkeylessURL)
	}

	if c.AkeylessAccessType == "" {
		c.AkeylessAccessType = os.Getenv(AkeylessAccessType)
	}

	if c.AkeylessAccessID == "" {
		c.AkeylessAccessID = os.Getenv(AkeylessAccessID)
	}

	if c.AkeylessAccessKey == "" {
		c.AkeylessAccessKey = os.Getenv(AkeylessAccessKey)
	}

	if c.AkeylessAccessKey == "" {
		c.AkeylessAccessKey = os.Getenv(Credentials)
	}

	if c.AkeylessAzureObjectID == "" {
		c.AkeylessAzureObjectID = os.Getenv(AkeylessAzureObjectID)
	}

	if c.AkeylessGCPAudience == "" {
		c.AkeylessGCPAudience = os.Getenv(AkeylessGCPAudience)
	}

	if c.AkeylessK8SServiceAccountToken == "" {
		c.AkeylessK8SServiceAccountToken = os.Getenv(AkeylessK8SServiceAccountToken)
	}

	if c.AkeylessK8SAuthConfigName == "" {
		c.AkeylessK8SAuthConfigName = os.Getenv(AkeylessK8SAuthConfigName)
	}

	if c.AkeylessGatewayURL == "" {
		c.AkeylessGatewayURL = defaultAkeylessGatewayURL
	}

	if c.AkeylessTargetFolder == "" {
		c.AkeylessTargetFolder = "/"
	}

	if !strings.HasSuffix(c.AkeylessTargetFolder, "/") {
		c.AkeylessTargetFolder += "/"
	}

	if c.AkeylessAccessID == "" {
		return fmt.Errorf("AkeylessAccessId not specified")
	}
	return nil
}

func createClient(akeylessGatewayURL string) *akeyless.V2ApiService {
	cfg := &akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: akeylessGatewayURL,
			},
		},
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   55 * time.Second,
					KeepAlive: 55 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
				// the total limit is bounded per host (MaxIdleConnsPerHost)
				// MaxIdleConns: 0,
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     200,
			},
			Timeout: 55 * time.Second,
		},
	}
	return akeyless.NewAPIClient(cfg).V2Api
}

func (c *Config) ClientAuth(aklClient *akeyless.V2ApiService) accessType {
	c.log.Info(fmt.Sprintf("trying to detect privileged credentials for %v", c.AkeylessAccessID))

	if err := c.authWithAccessKey(context.Background(), aklClient); err == nil {
		return AccessKey
	}

	if err := c.authWithAWS(context.Background(), aklClient); err == nil {
		return AWSIAM
	}

	if err := c.authWithAzure(context.Background(), aklClient); err == nil {
		return AzureAD
	}

	if err := c.authWithGCP(context.Background(), aklClient); err == nil {
		return GCP
	}

	if err := c.authWithK8S(context.Background(), aklClient); err == nil {
		return K8S
	}

	return ""
}
