package aws

import (
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	defaultNewClientCallback = newClient
)

// IAMClient interface describing used aws iamclient functions, useful for mocking
type IAMClient interface {
	GetInstanceProfileWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.Option) (*iam.GetInstanceProfileOutput, error)
}

// EC2Client interface describing used aws ec2client functions, useful for mocking
type EC2Client interface {
	DescribeInstancesWithContext(ctx aws.Context, input *ec2.DescribeInstancesInput, opts ...request.Option) (*ec2.DescribeInstancesOutput, error)
}

type Client interface {
	EC2Client
	IAMClient
}

type clientsCache struct {
	mu        sync.RWMutex
	config    *SessionConfig
	clients   map[string]Client
	newClient newClientCallback
}

type newClientCallback func(config *SessionConfig, region string) (Client, error)

func newClientsCache(newClient newClientCallback) *clientsCache {
	return &clientsCache{
		clients:   make(map[string]Client),
		newClient: newClient,
	}
}

func (cc *clientsCache) configure(config SessionConfig) {
	cc.mu.Lock()
	cc.clients = make(map[string]Client)
	cc.config = &config
	cc.mu.Unlock()
}

func (cc *clientsCache) getClient(region string) (Client, error) {
	// do an initial check to see if p client for this region already exists
	cc.mu.RLock()
	client, ok := cc.clients[region]
	cc.mu.RUnlock()
	if ok {
		return client, nil
	}

	// no client for this region. make one.
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// more than one thread could be racing to create p client (since we had
	// to drop the read lock to take the write lock), so double check somebody
	// hasn't beat us to it.
	client, ok = cc.clients[region]
	if ok {
		return client, nil
	}

	if cc.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}

	client, err := cc.newClient(cc.config, region)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}

	cc.clients[region] = client
	return client, nil
}

func newClient(config *SessionConfig, region string) (Client, error) {
	sess, err := newAWSSession(config.AccessKeyID, config.SecretAccessKey, region)
	if err != nil {
		return nil, err
	}

	return struct {
		*iam.IAM
		*ec2.EC2
	}{
		IAM: iam.New(sess),
		EC2: ec2.New(sess),
	}, nil
}
