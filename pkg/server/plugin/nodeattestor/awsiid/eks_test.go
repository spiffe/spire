package awsiid

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/require"
)

const (
	testEKSNodeListTTL    = "30s"
	testEKSClusterName    = "test-cluster"
	testEKSNodeGroupName  = "test-nodegroup"
	testASGName           = "test-asg"
	testEKSInstanceID     = "i-1234567890abcdef0"
	testEKSInstanceID2    = "i-abcdef1234567890a"
	testEKSClockMutAfter  = "after"
	testEKSClockMutBefore = "before"
)

func TestIsNodeInCluster(t *testing.T) {
	testEKSValidator := buildEKSValidationClient()
	testEKSClient := newFakeEKSClient()
	testASGClient := newFakeASGClient()

	// pass valid node
	ok, err := testEKSValidator.IsNodeInCluster(context.Background(), testEKSClient, testASGClient, testEKSInstanceID)
	require.NoError(t, err)
	require.True(t, ok)

	// fail when node doesn't exist
	ok, err = testEKSValidator.IsNodeInCluster(context.Background(), testEKSClient, testASGClient, "i-nonexistent")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestCheckIfEKSNodeListIsStale(t *testing.T) {
	testEKSValidator := buildEKSValidationClient()

	testIsStale := testEKSValidator.checkIfEKSNodeListIsStale()
	require.True(t, testIsStale)

	_, err := testEKSValidator.reloadNodeList(context.Background(), newFakeEKSClient(), newFakeASGClient(), false)
	require.NoError(t, err)
	testIsStale = testEKSValidator.checkIfEKSNodeListIsStale()
	require.False(t, testIsStale)
}

func TestReloadNodeList(t *testing.T) {
	testEKSValidator := buildEKSValidationClient()
	testEKSClient := newFakeEKSClient()
	testASGClient := newFakeASGClient()

	t.Run("reload node list with valid config", func(t *testing.T) {
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.NoError(t, err)
		require.Len(t, testEKSValidator.eksNodeList, 2) // Two instances in the test setup
		require.Greater(t, testEKSValidator.eksNodeListValidDuration, time.Now())
		require.Equal(t, testEKSValidator.retries, eksRetries)
	})

	t.Run("reload node list with catch burst", func(t *testing.T) {
		existingValidDuration := testEKSValidator.eksNodeListValidDuration
		testEKSValidator.eksNodeList = make(map[string]struct{})
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, true)
		require.NoError(t, err)
		require.Equal(t, existingValidDuration, testEKSValidator.eksNodeListValidDuration)
		require.Len(t, testEKSValidator.eksNodeList, 2)
	})

	t.Run("reload node list with catch burst and no retries left", func(t *testing.T) {
		// set retry to 0 and make sure the list is not updated
		testEKSValidator.retries = 0
		testEKSValidator.eksNodeList = make(map[string]struct{})
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, true)
		require.NoError(t, err)
		require.Empty(t, testEKSValidator.eksNodeList)
	})

	// make sure retry is reset, once we are over TTL
	// move clock ahead by 1 minute. And as our TTL is 30 seconds, it should refresh the list
	t.Run("refresh cache after TTL expired", func(t *testing.T) {
		testEKSValidator = buildEKSValidationClient()
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.NoError(t, err)
		require.Len(t, testEKSValidator.eksNodeList, 2)
		testEKSValidator.clk = buildEKSNewMockClock(1*time.Minute, testEKSClockMutAfter)
		testEKSValidator.retries = 0 // trigger refresh to reset retries

		_, err = testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.NoError(t, err)
		require.Equal(t, testEKSValidator.retries, eksRetries)
	})

	t.Run("error, list nodegroups call fails", func(t *testing.T) {
		testEKSValidator = buildEKSValidationClient()
		testEKSClient.ListNodegroupsError = errors.New("API error")
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.ErrorContains(t, err, "issue while getting list of EKS Nodegroups")
	})

	t.Run("error, describe nodegroup call fails", func(t *testing.T) {
		testEKSValidator = buildEKSValidationClient()
		testEKSClient = newFakeEKSClient()
		testEKSClient.DescribeNodegroupError = errors.New("API error")
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.ErrorContains(t, err, "issue while getting list of EKS Node Groups")
	})

	t.Run("error, describe auto scaling groups call fails", func(t *testing.T) {
		testEKSValidator = buildEKSValidationClient()
		testEKSClient = newFakeEKSClient()
		testASGClient.DescribeAutoScalingGroupsError = errors.New("ASG API error")
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.ErrorContains(t, err, "issue while getting list of instances in AutoScalingGroup")
	})

	t.Run("error, list nodegroups call fails with pagination", func(t *testing.T) {
		testEKSValidator = buildEKSValidationClient()
		testToken := "randomtoken"
		testEKSClient = newFakeEKSClient()
		testEKSClient.ListNodegroupsOutput = &eks.ListNodegroupsOutput{
			Nodegroups: []string{testEKSNodeGroupName},
			NextToken:  &testToken,
		}
		testASGClient = newFakeASGClient() // Create new ASG client without errors
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.ErrorContains(t, err, "issue while getting list of EKS Nodegroups in pagination")
	})

	t.Run("error, describe auto scaling groups call fails with pagination", func(t *testing.T) {
		testEKSValidator = buildEKSValidationClient()
		testEKSClient = newFakeEKSClient()
		testASGClient = newFakeASGClient()
		testToken := "randomtoken"
		testASGClient.DescribeAutoScalingGroupsOutput = &autoscaling.DescribeAutoScalingGroupsOutput{
			AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
				{
					AutoScalingGroupName: aws.String(testASGName),
					Instances: []autoscalingtypes.Instance{
						{
							InstanceId: aws.String(testEKSInstanceID),
						},
					},
				},
			},
			NextToken: &testToken,
		}
		_, err := testEKSValidator.reloadNodeList(context.Background(), testEKSClient, testASGClient, false)
		require.ErrorContains(t, err, "issue while getting list of instances in AutoScalingGroup in pagination")
	})
}

func TestEKSCheckIfTTLIsExpired(t *testing.T) {
	testEKSValidator := buildEKSValidationClient()

	// expect not expired, move clock back by 1 minute
	testEKSValidator.clk = buildEKSNewMockClock(1*time.Minute, testEKSClockMutBefore)
	expired := testEKSValidator.checkIfTTLIsExpired(time.Now())
	require.False(t, expired)

	// expect expired, move clock forward by 1 minute
	testEKSValidator.clk = buildEKSNewMockClock(1*time.Minute, testEKSClockMutAfter)
	expired = testEKSValidator.checkIfTTLIsExpired(time.Now())
	require.True(t, expired)
}

func TestFetchNodesInNodeGroup(t *testing.T) {
	testEKSValidator := buildEKSValidationClient()
	testEKSClient := newFakeEKSClient()
	testASGClient := newFakeASGClient()

	instances, err := testEKSValidator.fetchNodesInNodeGroup(context.Background(), testEKSClient, testASGClient, testEKSNodeGroupName, testEKSClusterName)
	require.NoError(t, err)
	require.Len(t, instances, 2)
	require.Contains(t, instances, testEKSInstanceID)
	require.Contains(t, instances, testEKSInstanceID2)

	// test with nil ASG name
	testEKSClient.DescribeNodegroupOutput = &eks.DescribeNodegroupOutput{
		Nodegroup: &ekstypes.Nodegroup{
			Resources: &ekstypes.NodegroupResources{
				AutoScalingGroups: []ekstypes.AutoScalingGroup{
					{
						Name: nil, // nil name should be skipped
					},
				},
			},
		},
	}
	instances, err = testEKSValidator.fetchNodesInNodeGroup(context.Background(), testEKSClient, testASGClient, testEKSNodeGroupName, testEKSClusterName)
	require.NoError(t, err)
	require.Empty(t, instances)

	// test with nil instance ID
	testEKSClient = newFakeEKSClient()
	testASGClient.DescribeAutoScalingGroupsOutput = &autoscaling.DescribeAutoScalingGroupsOutput{
		AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
			{
				AutoScalingGroupName: aws.String(testASGName),
				Instances: []autoscalingtypes.Instance{
					{
						InstanceId: nil, // nil instance ID should be skipped
					},
					{
						InstanceId: aws.String(testEKSInstanceID),
					},
				},
			},
		},
	}
	instances, err = testEKSValidator.fetchNodesInNodeGroup(context.Background(), testEKSClient, testASGClient, testEKSNodeGroupName, testEKSClusterName)
	require.NoError(t, err)
	require.Len(t, instances, 1)
	require.Contains(t, instances, testEKSInstanceID)
}

func buildEKSValidationClient() *eksValidator {
	testEKSValidationConfig := &eksValidationConfig{
		EKSClusterNames: []string{testEKSClusterName},
	}
	testEKSValidator := newEKSValidationBase(testEKSValidationConfig)
	_ = testEKSValidator.configure(testEKSValidationConfig)
	return testEKSValidator
}

func buildEKSNewMockClock(t time.Duration, mut string) *clock.Mock {
	testClock := clock.NewMock()
	switch mut {
	case testEKSClockMutAfter:
		testClock.Set(time.Now().UTC())
		testClock.Add(t)
	case testEKSClockMutBefore:
		testClock.Set(time.Now().UTC().Add(-t))
	}
	return testClock
}

// Fake EKS Client

type fakeEKSClient struct {
	ListNodegroupsOutput    *eks.ListNodegroupsOutput
	ListNodegroupsError     error
	DescribeNodegroupOutput *eks.DescribeNodegroupOutput
	DescribeNodegroupError  error
}

func newFakeEKSClient() *fakeEKSClient {
	return &fakeEKSClient{
		ListNodegroupsOutput: &eks.ListNodegroupsOutput{
			Nodegroups: []string{testEKSNodeGroupName},
		},
		DescribeNodegroupOutput: &eks.DescribeNodegroupOutput{
			Nodegroup: &ekstypes.Nodegroup{
				Resources: &ekstypes.NodegroupResources{
					AutoScalingGroups: []ekstypes.AutoScalingGroup{
						{
							Name: aws.String(testASGName),
						},
					},
				},
			},
		},
	}
}

func (c *fakeEKSClient) ListNodegroups(_ context.Context, input *eks.ListNodegroupsInput, _ ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	if c.ListNodegroupsError != nil {
		return nil, c.ListNodegroupsError
	}

	// Handle pagination test case
	if input.NextToken != nil {
		return nil, errors.New("pagination test error")
	}

	return c.ListNodegroupsOutput, nil
}

func (c *fakeEKSClient) DescribeNodegroup(_ context.Context, input *eks.DescribeNodegroupInput, _ ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	if c.DescribeNodegroupError != nil {
		return nil, c.DescribeNodegroupError
	}

	return c.DescribeNodegroupOutput, nil
}

// Fake AutoScaling Client

type fakeASGClient struct {
	DescribeAutoScalingGroupsOutput *autoscaling.DescribeAutoScalingGroupsOutput
	DescribeAutoScalingGroupsError  error
}

func newFakeASGClient() *fakeASGClient {
	return &fakeASGClient{
		DescribeAutoScalingGroupsOutput: &autoscaling.DescribeAutoScalingGroupsOutput{
			AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
				{
					AutoScalingGroupName: aws.String(testASGName),
					Instances: []autoscalingtypes.Instance{
						{
							InstanceId: aws.String(testEKSInstanceID),
						},
						{
							InstanceId: aws.String(testEKSInstanceID2),
						},
					},
				},
			},
		},
	}
}

func (c *fakeASGClient) DescribeAutoScalingGroups(_ context.Context, input *autoscaling.DescribeAutoScalingGroupsInput, _ ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	if c.DescribeAutoScalingGroupsError != nil {
		return nil, c.DescribeAutoScalingGroupsError
	}

	// Handle pagination test case
	if input.NextToken != nil {
		return nil, errors.New("pagination test error")
	}

	return c.DescribeAutoScalingGroupsOutput, nil
}
