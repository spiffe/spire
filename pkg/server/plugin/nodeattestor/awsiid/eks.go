package awsiid

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/hashicorp/go-hclog"
)

type EKSClient interface {
	eks.ListNodegroupsAPIClient
	eks.DescribeNodegroupAPIClient
}

const (
	eksNodeListTTL = "30s" // pull EKS node list again after 30 seconds
	eksRetries     = 5
)

var (
	eksNodeListDuration, _ = time.ParseDuration(eksNodeListTTL)
)

type eksValidationConfig struct {
	EKSClusterNames []string `hcl:"eks_cluster_names"`
}

type eksValidator struct {
	eksNodeList              map[string]struct{}
	eksNodeListValidDuration time.Time
	eksConfig                *eksValidationConfig
	mutex                    sync.RWMutex
	// eksAccountListCacheTTL holds the cache ttl from configuration; otherwise, it will be set to the default value.
	eksAccountListCacheTTL time.Duration
	log                    hclog.Logger
	// retries fix number of retries before ttl is expired.
	retries int
	// require for testing
	clk clock.Clock
}

func newEKSValidationBase(config *eksValidationConfig) *eksValidator {
	client := &eksValidator{
		eksNodeList: make(map[string]struct{}),
		eksConfig:   config,
		retries:     eksRetries,
		clk:         clock.New(),
	}

	return client
}

func (o *eksValidator) getRetries() int {
	o.mutex.RLock()
	defer o.mutex.RUnlock()
	return o.retries
}

func (o *eksValidator) decrRetries() int {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if o.retries > 0 {
		o.retries--
	}

	return o.retries
}

func (o *eksValidator) configure(config *eksValidationConfig) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.eksConfig = config

	// While doing configuration invalidate the map so we don't keep using old one.
	o.eksNodeList = make(map[string]struct{})
	o.retries = eksRetries

	o.eksAccountListCacheTTL = eksNodeListDuration

	return nil
}

func (o *eksValidator) setLogger(log hclog.Logger) {
	o.log = log
}

// IsNodeInCluster method checks if the Node ID attached on the node is part of the EKS cluster.
func (o *eksValidator) IsNodeInCluster(ctx context.Context, eksClient EKSClient, asClient autoscaling.DescribeAutoScalingGroupsAPIClient, nodeID string) (bool, error) {
	reValidatedCache, err := o.validateCache(ctx, eksClient, asClient)
	if err != nil {
		return false, err
	}

	nodeIsmemberOfCluster, err := o.lookupCache(ctx, eksClient, asClient, nodeID, reValidatedCache)
	if err != nil {
		return false, err
	}

	return nodeIsmemberOfCluster, nil
}

// validateCache validates cache and refresh if its stale
func (o *eksValidator) validateCache(ctx context.Context, eksClient EKSClient, asClient autoscaling.DescribeAutoScalingGroupsAPIClient) (bool, error) {
	isStale := o.checkIfEKSNodeListIsStale()
	if !isStale {
		return false, nil
	}

	// cache is stale, reload the account map
	_, err := o.reloadNodeList(ctx, eksClient, asClient, false)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (o *eksValidator) lookupCache(ctx context.Context, eksClient EKSClient, asClient autoscaling.DescribeAutoScalingGroupsAPIClient, nodeID string, reValidatedCache bool) (bool, error) {
	o.mutex.RLock()
	eksNodeList := o.eksNodeList
	o.mutex.RUnlock()

	_, nodeIsMemberOfCluster := eksNodeList[nodeID]

	// Retry if it doesn't exist in cache and cache was not revalidated
	if !nodeIsMemberOfCluster && !reValidatedCache {
		eksAccountList, err := o.refreshCache(ctx, eksClient, asClient)
		if err != nil {
			o.log.Error("Failed to refresh cache, while validating node id: %v", nodeID, "error", err.Error())
			return false, err
		}
		_, nodeIsMemberOfCluster = eksAccountList[nodeID]
	}

	return nodeIsMemberOfCluster, nil
}

// refreshCache refreshes list with new cache if cache miss happens and check if element exist
func (o *eksValidator) refreshCache(ctx context.Context, eksClient EKSClient, asClient autoscaling.DescribeAutoScalingGroupsAPIClient) (map[string]struct{}, error) {
	remTries := o.getRetries()

	eksNodeList := make(map[string]struct{})
	if remTries <= 0 {
		return eksNodeList, nil
	}

	eksNodeList, err := o.reloadNodeList(ctx, eksClient, asClient, true)
	if err != nil {
		return nil, err
	}

	o.decrRetries()

	return eksNodeList, nil
}

// checkIfEKSNodeListIsStale checks if the cached org account list is stale.
func (o *eksValidator) checkIfEKSNodeListIsStale() bool {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Map is empty that means this is first time plugin is being initialised
	if len(o.eksNodeList) == 0 {
		return true
	}

	return o.checkIfTTLIsExpired(o.eksNodeListValidDuration)
}

// reloadNodeList gets the list of nodes belonging to the EKS cluster and catch them
func (o *eksValidator) reloadNodeList(ctx context.Context, eksClient EKSClient, asClient autoscaling.DescribeAutoScalingGroupsAPIClient, catchBurst bool) (map[string]struct{}, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	// Make sure: we are not doing cache burst and account map is not updated recently from different go routine.
	if !catchBurst && len(o.eksNodeList) != 0 && !o.checkIfTTLIsExpired(o.eksNodeListValidDuration) {
		return o.eksNodeList, nil
	}

	// Avoid if other thread has already updated the map
	if catchBurst && o.retries == 0 {
		return o.eksNodeList, nil
	}

	// Build new EKS nodes list
	eksNodeMap := make(map[string]struct{})

	// Get the list of node groups belonging to the EKS clusters
	for _, clusterName := range o.eksConfig.EKSClusterNames {
		listNodegroupsOp, err := eksClient.ListNodegroups(ctx, &eks.ListNodegroupsInput{
			ClusterName: &clusterName,
		})
		if err != nil {
			return nil, fmt.Errorf("issue while getting list of EKS Nodegroups: %w", err)
		}

		for {
			for _, ng := range listNodegroupsOp.Nodegroups {
				instances, err := o.fetchNodesInNodeGroup(ctx, eksClient, asClient, ng, clusterName)
				if err != nil {
					return nil, err
				}

				for _, instance := range instances {
					eksNodeMap[instance] = struct{}{}
				}
			}

			if listNodegroupsOp.NextToken == nil {
				break
			}

			listNodegroupsOp, err = eksClient.ListNodegroups(ctx, &eks.ListNodegroupsInput{
				ClusterName: &clusterName,
				NextToken:   listNodegroupsOp.NextToken,
			})
			if err != nil {
				return nil, fmt.Errorf("issue while getting list of EKS Nodegroups in pagination: %w", err)
			}
		}
	}

	// Update timestamp, if it was not invoked as part of cache miss.
	if !catchBurst {
		o.eksNodeListValidDuration = o.clk.Now().UTC().Add(o.eksAccountListCacheTTL)
		// Also reset the retries
		o.retries = orgAccountRetries
	}

	// Overwrite the cache/list
	o.eksNodeList = eksNodeMap

	return o.eksNodeList, nil
}

// reloadNodeList gets the list of nodes belonging to the EKS cluster and catch them
func (o *eksValidator) fetchNodesInNodeGroup(ctx context.Context, eksClient EKSClient, asClient autoscaling.DescribeAutoScalingGroupsAPIClient, nodeGroup, clusterName string) ([]string, error) {
	// Get the list of node groups belonging to the EKS cluster
	describeNodegroupOp, err := eksClient.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
		ClusterName:   &clusterName,
		NodegroupName: &nodeGroup,
	})
	if err != nil {
		return nil, fmt.Errorf("issue while getting list of EKS Node Groups: %w", err)
	}

	instances := make([]string, 0)
	for _, asg := range describeNodegroupOp.Nodegroup.Resources.AutoScalingGroups {
		if asg.Name == nil {
			continue
		}

		// Get the list of instances in the AutoScalingGroup
		describeASGOp, err := asClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
			AutoScalingGroupNames: []string{*asg.Name},
		})

		if err != nil {
			return nil, fmt.Errorf("issue while getting list of instances in AutoScalingGroup: %w", err)
		}

		for {
			for _, ag := range describeASGOp.AutoScalingGroups {
				for _, instance := range ag.Instances {
					if instance.InstanceId == nil {
						continue
					}
					instances = append(instances, *instance.InstanceId)
				}
			}

			if describeASGOp.NextToken == nil {
				break
			}

			describeASGOp, err = asClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
				AutoScalingGroupNames: []string{*asg.Name},
				NextToken:             describeASGOp.NextToken,
			})
			if err != nil {
				return nil, fmt.Errorf("issue while getting list of instances in AutoScalingGroup in pagination: %w", err)
			}
		}
	}

	return instances, nil
}

// checkIFTTLIsExpire check if the creation time is pass defined ttl
func (o *eksValidator) checkIfTTLIsExpired(ttl time.Time) bool {
	currTimeStamp := o.clk.Now().UTC()
	return currTimeStamp.After(ttl)
}
