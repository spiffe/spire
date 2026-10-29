package awsiid

import (
	"fmt"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func rejectDuplicatePartitionCredentials(hclText string) error {
	parsed, err := hcl.Parse(hclText)
	if err != nil {
		return err
	}
	root, ok := parsed.Node.(*ast.ObjectList)
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	for _, block := range root.Items {
		if len(block.Keys) == 0 || block.Keys[0].Token.Value() != "partition_credentials" {
			continue
		}
		object, ok := block.Val.(*ast.ObjectType)
		if !ok {
			continue
		}
		for _, entry := range object.List.Items {
			if len(entry.Keys) == 0 {
				continue
			}
			partition := fmt.Sprint(entry.Keys[0].Token.Value())
			if seen[partition] {
				return fmt.Errorf("duplicate partition credential entry %q", partition)
			}
			seen[partition] = true
		}
	}
	return nil
}

// Only regions with known instance identity document CAs are admitted here.
// New regions must be reviewed before their credentials can be routed.
var iidRegionPartitions = map[string]string{
	"af-south-1":     "aws",
	"ap-east-1":      "aws",
	"ap-east-2":      "aws",
	"ap-northeast-1": "aws",
	"ap-northeast-2": "aws",
	"ap-northeast-3": "aws",
	"ap-south-1":     "aws",
	"ap-south-2":     "aws",
	"ap-southeast-1": "aws",
	"ap-southeast-2": "aws",
	"ap-southeast-3": "aws",
	"ap-southeast-4": "aws",
	"ap-southeast-5": "aws",
	"ap-southeast-6": "aws",
	"ap-southeast-7": "aws",
	"ca-central-1":   "aws",
	"ca-west-1":      "aws",
	"cn-north-1":     "aws-cn",
	"cn-northwest-1": "aws-cn",
	"eu-central-1":   "aws",
	"eu-central-2":   "aws",
	"eu-north-1":     "aws",
	"eu-south-1":     "aws",
	"eu-south-2":     "aws",
	"eu-west-1":      "aws",
	"eu-west-2":      "aws",
	"eu-west-3":      "aws",
	"il-central-1":   "aws",
	"me-central-1":   "aws",
	"me-south-1":     "aws",
	"mx-central-1":   "aws",
	"sa-east-1":      "aws",
	"us-east-1":      "aws",
	"us-east-2":      "aws",
	"us-gov-east-1":  "aws-us-gov",
	"us-gov-west-1":  "aws-us-gov",
	"us-west-1":      "aws",
	"us-west-2":      "aws",
}

func partitionForRegion(region string) (string, error) {
	if partition, ok := iidRegionPartitions[region]; ok {
		return partition, nil
	}
	return "", status.Errorf(codes.InvalidArgument, "unsupported AWS region %q", region)
}
