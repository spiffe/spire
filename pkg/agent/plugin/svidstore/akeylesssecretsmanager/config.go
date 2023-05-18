package akeylesssecretsmanager

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/akeylesslabs/akeyless-go/v3"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	AkeylessURL                    = "AKEYLESS_GATEWAY_URL"
	AkeylessAccessType             = "AKEYLESS_ACCESS_TYPE"
	AkeylessAccessID               = "AKEYLESS_ACCESS_ID"
	AkeylessAccessKey              = "AKEYLESS_ACCESS_KEY"
	Credentials                    = "CREDENTIALS"
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
	AkeylessGatewayURL             string `hcl:"akeyless_gateway_url" json:"akeyless_gateway_url"`
	AkeylessAccessType             string `hcl:"akeyless_access_type" json:"akeyless_access_type"`
	AkeylessAccessID               string `hcl:"akeyless_access_key_id" json:"akeyless_access_key_id"`
	AkeylessAccessKey              string `hcl:"akeyless_access_key" json:"akeyless_access_key"`
	AkeylessAzureObjectID          string `hcl:"akeyless_azure_object_id" json:"akeyless_azure_object_id"`
	AkeylessGCPAudience            string `hcl:"akeyless_gcp_audience" json:"akeyless_gcp_audience"`
	AkeylessK8SServiceAccountToken string `hcl:"akeyless_k8s_service_account_token" json:"akeyless_k8s_service_account_token"`
	AkeylessK8SAuthConfigName      string `hcl:"akeyless_k8s_auth_config_name" json:"akeyless_k8s_auth_config_name"`
}

func ParseAndValidateConfig(c string, log hclog.Logger) (*Config, error) {
	config := &Config{log: log}
	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to validate configuration: %v", err)
	}

	AklClient = createClient(config.AkeylessGatewayURL)

	aklsAccessType := string(config.ClientAuth(AklClient))
	if aklsAccessType == "" {
		return nil, status.Errorf(codes.InvalidArgument, "failed to connect client and detect access type")
	}
	if config.AkeylessAccessType == "" {
		config.AkeylessAccessType = aklsAccessType
	}

	log.Info("successfully connected using %s access type", config.AkeylessAccessType)

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
	c.log.Info("trying to detect privileged credentials for %v-%v", c.AkeylessAccessID, c.AkeylessAccessKey)

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
