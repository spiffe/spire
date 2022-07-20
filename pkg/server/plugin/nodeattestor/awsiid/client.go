package awsiid

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	defaultNewClientCallback = newClient
)

type Client interface {
	ec2.DescribeInstancesAPIClient
	iam.GetInstanceProfileAPIClient
}

type clientsCache struct {
	mtx       sync.RWMutex
	config    *SessionConfig
	clients   map[string]*cacheEntry
	newClient newClientCallback
}

type cacheEntry struct {
	lock   chan struct{}
	client Client
}

type newClientCallback func(ctx context.Context, config *SessionConfig, region string, asssumeRoleARN string) (Client, error)

func newClientsCache(newClient newClientCallback) *clientsCache {
	return &clientsCache{
		clients:   make(map[string]*cacheEntry),
		newClient: newClient,
	}
}

func (cc *clientsCache) configure(config SessionConfig) {
	cc.mtx.Lock()
	cc.clients = make(map[string]*cacheEntry)
	cc.config = &config
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

	var asssumeRoleArn string
	if cc.config.AssumeRole != "" {
		asssumeRoleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, cc.config.AssumeRole)
	}

	client, err := cc.newClient(ctx, cc.config, region, asssumeRoleArn)
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

func newClient(ctx context.Context, config *SessionConfig, region string, asssumeRoleARN string) (Client, error) {
	conf, err := newAWSConfig(ctx, config.AccessKeyID, config.SecretAccessKey, region, asssumeRoleARN)
	if err != nil {
		return nil, err
	}
	return struct {
		iam.GetInstanceProfileAPIClient
		ec2.DescribeInstancesAPIClient
	}{
		GetInstanceProfileAPIClient: iam.NewFromConfig(conf),
		DescribeInstancesAPIClient:  ec2.NewFromConfig(conf),
	}, nil
}
