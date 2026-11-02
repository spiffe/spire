package awsiid

import (
	"context"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestPartitionForRegion(t *testing.T) {
	for region, partition := range map[string]string{
		"us-east-1":      "aws",
		"eu-central-1":   "aws",
		"ap-southeast-4": "aws",
		"cn-north-1":     "aws-cn",
		"cn-northwest-1": "aws-cn",
		"us-gov-west-1":  "aws-us-gov",
		"us-gov-east-1":  "aws-us-gov",
		"eusc-de-east-1": "aws-eusc",
	} {
		require.Equal(t, partition, partitionForRegion(region), "region %q", region)
	}
}

func TestClientsCachePartitions(t *testing.T) {
	type call struct {
		partition     string
		region        string
		assumeRoleARN string
		orgRoleARN    string
	}
	var calls []call
	cache := newClientsCache(func(_ context.Context, config *SessionConfig, region string, assumeRoleARN string, orgRoleARN string) (Client, error) {
		calls = append(calls, call{config.Partition, region, assumeRoleARN, orgRoleARN})
		return newFakeClient(), nil
	})

	t.Run("without partitions every region uses the top-level config", func(t *testing.T) {
		calls = nil
		cache.configure(SessionConfig{Partition: "aws", AssumeRole: "delegate"}, nil, orgValidationConfig{})

		_, err := cache.getClient(context.Background(), "us-gov-west-1", "123456789012")
		require.NoError(t, err)
		require.Equal(t, []call{{"aws", "us-gov-west-1", "arn:aws:iam::123456789012:role/delegate", ""}}, calls)
	})

	t.Run("with partitions each region uses its partition's config", func(t *testing.T) {
		calls = nil
		cache.configure(SessionConfig{}, map[string]*SessionConfig{
			"aws":        {Partition: "aws", AssumeRole: "commercial-delegate"},
			"aws-us-gov": {Partition: "aws-us-gov", AssumeRole: "govcloud-delegate"},
		}, orgValidationConfig{AccountID: "210987654321", AccountRole: "org-role"})

		_, err := cache.getClient(context.Background(), "us-east-1", "123456789012")
		require.NoError(t, err)
		_, err = cache.getClient(context.Background(), "us-gov-west-1", "123456789012")
		require.NoError(t, err)
		require.Equal(t, []call{
			{"aws", "us-east-1", "arn:aws:iam::123456789012:role/commercial-delegate", "arn:aws:iam::210987654321:role/org-role"},
			{"aws-us-gov", "us-gov-west-1", "arn:aws-us-gov:iam::123456789012:role/govcloud-delegate", "arn:aws-us-gov:iam::210987654321:role/org-role"},
		}, calls)
	})

	t.Run("a region in an unconfigured partition is rejected", func(t *testing.T) {
		calls = nil
		cache.configure(SessionConfig{}, map[string]*SessionConfig{
			"aws": {Partition: "aws"},
		}, orgValidationConfig{})

		_, err := cache.getClient(context.Background(), "cn-north-1", "123456789012")
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, `region "cn-north-1" is in partition "aws-cn", which is not configured`)
		require.Empty(t, calls)
	})
}
