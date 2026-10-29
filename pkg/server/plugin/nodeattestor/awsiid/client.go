package awsiid

import (
	"context"
	"fmt"
	"maps"
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
	mtx        sync.RWMutex
	config     *SessionConfig
	partitions map[string]SessionConfig
	orgConfig  *orgValidationConfig
	clients    map[string]*cacheEntry
	newClient  newClientCallback
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

func (cc *clientsCache) configure(config SessionConfig, partitions map[string]SessionConfig, orgConfig orgValidationConfig) {
	cc.mtx.Lock()
	defer cc.mtx.Unlock()
	cc.clients = make(map[string]*cacheEntry)
	cc.config = &config
	cc.partitions = nil
	if partitions != nil {
		cc.partitions = make(map[string]SessionConfig, len(partitions))
		maps.Copy(cc.partitions, partitions)
	}
	cc.orgConfig = &orgConfig
}

func (cc *clientsCache) getClient(ctx context.Context, region, accountID string) (Client, error) {
	cc.mtx.Lock()
	if cc.config == nil {
		cc.mtx.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	config := *cc.config
	orgConfig := *cc.orgConfig
	if cc.partitions != nil {
		partition, err := partitionForRegion(region)
		if err != nil {
			cc.mtx.Unlock()
			return nil, err
		}
		var ok bool
		config, ok = cc.partitions[partition]
		if !ok {
			cc.mtx.Unlock()
			return nil, status.Errorf(codes.PermissionDenied, "no AWS credentials configured for partition %q", partition)
		}
	}
	cacheKey := config.Partition + "@" + accountID + "@" + region
	r, ok := cc.clients[cacheKey]
	if !ok {
		r = &cacheEntry{lock: make(chan struct{}, 1)}
		cc.clients[cacheKey] = r
	}
	cc.mtx.Unlock()

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

	var assumeRoleArn string
	if config.AssumeRole != "" {
		assumeRoleArn = fmt.Sprintf("arn:%s:iam::%s:role/%s", config.Partition, accountID, config.AssumeRole)
	}

	// If organization attestation feature is enabled, assume org role
	var orgRoleArn string
	if orgConfig.AccountRole != "" && region == orgConfig.AccountRegion {
		orgRoleArn = fmt.Sprintf("arn:%s:iam::%s:role/%s", config.Partition, orgConfig.AccountID, orgConfig.AccountRole)
	}

	client, err := cc.newClient(ctx, &config, region, assumeRoleArn, orgRoleArn)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}

	r.client = client
	return client, nil
}

func (cc *clientsCache) checkRegion(region string) error {
	cc.mtx.RLock()
	defer cc.mtx.RUnlock()
	if cc.partitions == nil {
		return nil
	}
	partition, err := partitionForRegion(region)
	if err != nil {
		return err
	}
	if _, ok := cc.partitions[partition]; !ok {
		return status.Errorf(codes.PermissionDenied, "no AWS credentials configured for partition %q", partition)
	}
	return nil
}

func newClient(ctx context.Context, config *SessionConfig, region string, assumeRoleARN string, orgRoleArn string) (Client, error) {
	conf, err := newAWSConfig(ctx, config, region, assumeRoleARN)
	if err != nil {
		return nil, err
	}

	// If the organizationAttestation feature is enabled, use the role configured for feature.
	orgConf, err := newAWSConfig(ctx, config, region, orgRoleArn)
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
