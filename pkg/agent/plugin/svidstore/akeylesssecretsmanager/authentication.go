package akeylesssecretsmanager

import (
	"context"
	"fmt"

	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/akeylesslabs/akeyless-go/v3"
	log "github.com/hashicorp/go-hclog"

	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/aws"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/azure"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/gcp"
)

const (
	authenticationInterval = time.Second * 870 // 14.5 minutes
)

var (
	akeylessAuthToken string
	mutexAuthToken    = &sync.RWMutex{}
	authenticator     = func(ctx context.Context, aklClient *akeyless.V2ApiService) error { return nil }
)

func setAuthToken(t string) {
	mutexAuthToken.Lock()
	defer mutexAuthToken.Unlock()

	akeylessAuthToken = t
}

func GetAuthToken() string {
	mutexAuthToken.RLock()
	defer mutexAuthToken.RUnlock()

	return akeylessAuthToken
}

func (c *Config) authenticate(ctx context.Context, aklClient *akeyless.V2ApiService, authBody *akeyless.Auth) error {
	authBody.SetAccessId(c.AkeylessAccessID)

	authOut, _, err := aklClient.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return fmt.Errorf("authentication failed %v, %w", c.AkeylessGatewayURL, err)
	}

	setAuthToken(authOut.GetToken())
	return nil
}

func (c *Config) authWithAccessKey(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(AccessKey))
	authBody.SetAccessKey(c.AkeylessAccessKey)
	err := c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.L().Error("authWithAccessKey ERR: %v", err.Error())
	}
	return err
}

func (c *Config) authWithAWS(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(AWSIAM))
	cloudId, err := aws.GetCloudId()
	if err != nil {
		return fmt.Errorf("requested access type %v but failed to get cloud ID, error: %v", AWSIAM, err)
	}
	authBody.SetCloudId(cloudId)
	return c.authenticate(ctx, aklClient, authBody)
}

func (c *Config) authWithAzure(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(AzureAD))
	cloudId, err := azure.GetCloudId(c.AkeylessAzureObjectID)
	if err != nil {
		return fmt.Errorf("requested access type %v but failed to get cloud ID, error: %v", AzureAD, err)
	}
	authBody.SetCloudId(cloudId)
	return c.authenticate(ctx, aklClient, authBody)
}

func (c *Config) authWithGCP(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(GCP))
	cloudId, err := gcp.GetCloudID(c.AkeylessGCPAudience)
	if err != nil {
		return fmt.Errorf("requested access type %v but failed to get cloud ID, error: %v", GCP, err)
	}
	authBody.SetCloudId(cloudId)
	return c.authenticate(ctx, aklClient, authBody)
}

func (c *Config) authWithK8S(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(K8S))
	authBody.SetAccessKey(c.AkeylessAccessKey)
	authBody.SetGatewayUrl(c.AkeylessGatewayURL)
	authBody.SetK8sServiceAccountToken(c.AkeylessK8SServiceAccountToken)
	authBody.SetK8sAuthConfigName(c.AkeylessK8SAuthConfigName)

	err := c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.L().Error("authWithK8S ERR: %v", err.Error())
	}
	return err
}

func (c *Config) StartAuthentication(ctx context.Context, closed chan bool) error {
	accType := c.AkeylessAccessType

	switch accessType(accType) {
	case AccessKey:
		authenticator = c.authWithAccessKey

	case AWSIAM:
		authenticator = c.authWithAWS

	case AzureAD:
		authenticator = c.authWithAzure

	case GCP:
		authenticator = c.authWithGCP

	case K8S:
		authenticator = c.authWithK8S
	}

	// Get new token every authenticationInterval seconds
	runForeverWithContext(ctx, func() error {
		ticker := time.NewTicker(authenticationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				closed <- true
				return nil
			case <-ticker.C:
				log.Default().Info("retrieving new token")
				err := authenticator(ctx, AklClient)
				if err != nil {
					return err
				}
				log.Default().Info("successfully retrieved new token")
			}
		}
	}, closed)

	return nil
}

func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func runForeverWithContext(ctx context.Context, fn func() error, notifier chan bool) {
	runForeverWithContextEx(ctx, fn, "daemon", notifier)
}

func runForeverWithContextEx(ctx context.Context, fn func() error, routineType string, notifier chan bool) {
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				notifier <- true
				return
			case <-t.C:
				func() {
					err := fn()
					if err != nil {
						log.Default().Error("%s %s ended with an error. %s", routineType, getFunctionName(fn), err)
					}
				}()
			}
		}
	}()
}
