package awsiid

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	defaultNewClientCallback = newClient
)

type Client interface {
	ec2.DescribeInstancesAPIClient
	iam.GetInstanceProfileAPIClient
	organizations.ListAccountsAPIClient
	autoscaling.DescribeAutoScalingGroupsAPIClient
	eks.ListNodegroupsAPIClient
	eks.DescribeNodegroupAPIClient
}

type clientsCache struct {
	mtx       sync.RWMutex
	config    *SessionConfig
	orgConfig *orgValidationConfig
	clients   map[string]*cacheEntry
	newClient newClientCallback
}

type cacheEntry struct {
	lock   chan struct{}
	client Client
}

type newClientCallback func(ctx context.Context, config *SessionConfig, region string, assumeRoleARN string, orgRoleARN string) (Client, error)

func newClientsCache(newClient newClientCallback) *clientsCache {
	return &clientsCache{
		clients:   make(map[string]*cacheEntry),
		newClient: newClient,
	}
}

func (cc *clientsCache) configure(config SessionConfig, orgConfig orgValidationConfig) {
	cc.mtx.Lock()
	cc.clients = make(map[string]*cacheEntry)
	cc.config = &config
	cc.orgConfig = &orgConfig
	cc.mtx.Unlock()
}

func (cc *clientsCache) getClient(ctx context.Context, region, accountID string) (Client, error) {
	// Do an initial check to see if p client for this region already exists
	cacheKey := accountID + "@" + region

	// Grab (or create) the cache for the region
	r := cc.getCachedClient(cacheKey)

	// Obtain the "lock" to the region cache
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r.lock <- struct{}{}:
	}

	// "clear" the lock when the function is complete
	defer func() {
		<-r.lock
	}()

	// If the client is populated, return it.
	if r.client != nil {
		return r.client, nil
	}

	if cc.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}

	var assumeRoleArn string
	if cc.config.AssumeRole != "" {
		assumeRoleArn = fmt.Sprintf("arn:%s:iam::%s:role/%s", cc.config.Partition, accountID, cc.config.AssumeRole)
	}

	// If organization attestation feature is enabled, assume org role
	var orgRoleArn string
	if cc.orgConfig.AccountRole != "" {
		orgRoleArn = fmt.Sprintf("arn:%s:iam::%s:role/%s", cc.config.Partition, cc.orgConfig.AccountID, cc.orgConfig.AccountRole)
	}

	client, err := cc.newClient(ctx, cc.config, region, assumeRoleArn, orgRoleArn)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}

	r.client = client
	return client, nil
}

func (cc *clientsCache) getCachedClient(cacheKey string) *cacheEntry {
	cc.mtx.Lock()
	defer cc.mtx.Unlock()
	r, ok := cc.clients[cacheKey]
	if !ok {
		r = &cacheEntry{
			lock: make(chan struct{}, 1),
		}
		cc.clients[cacheKey] = r
	}
	return r
}

func newClient(ctx context.Context, config *SessionConfig, region string, assumeRoleARN string, orgRoleArn string) (Client, error) {
	conf, err := newAWSConfig(ctx, config.AccessKeyID, config.SecretAccessKey, region, assumeRoleARN)
	if err != nil {
		return nil, err
	}

	// If the organizationAttestation feature is enabled, use the role configured for feature.
	orgConf, err := newAWSConfig(ctx, config.AccessKeyID, config.SecretAccessKey, region, orgRoleArn)
	if err != nil {
		return nil, err
	}

	eksClient := eks.NewFromConfig(conf)

	return struct {
		iam.GetInstanceProfileAPIClient
		ec2.DescribeInstancesAPIClient
		organizations.ListAccountsAPIClient
		autoscaling.DescribeAutoScalingGroupsAPIClient
		eks.ListNodegroupsAPIClient
		eks.DescribeNodegroupAPIClient
	}{
		GetInstanceProfileAPIClient:        iam.NewFromConfig(conf),
		DescribeInstancesAPIClient:         ec2.NewFromConfig(conf),
		ListAccountsAPIClient:              organizations.NewFromConfig(orgConf),
		DescribeAutoScalingGroupsAPIClient: autoscaling.NewFromConfig(conf),
		ListNodegroupsAPIClient:            eksClient,
		DescribeNodegroupAPIClient:         eksClient,
	}, nil
}
