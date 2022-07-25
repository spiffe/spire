package awsiid

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/stretchr/testify/require"
)

var (
	templateWithTags = agentpathtemplate.MustParse("/{{ .Tags.a }}/{{ .Tags.b }}")
	trustDomain      = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestMakeSpiffeID(t *testing.T) {
	tests := []struct {
		name              string
		agentPathTemplate *agentpathtemplate.Template
		doc               imds.InstanceIdentityDocument
		tags              instanceTags
		want              string
	}{
		{
			name:              "default",
			agentPathTemplate: defaultAgentPathTemplate,
			doc: imds.InstanceIdentityDocument{
				Region:     "region",
				InstanceID: "instanceID",
				AccountID:  "accountID",
			},
			want: "spiffe://example.org/spire/agent/aws_iid/accountID/region/instanceID",
		},
		{
			name:              "instance tags",
			agentPathTemplate: templateWithTags,
			tags: instanceTags{
				"a": "c",
				"b": "d",
			},
			want: "spiffe://example.org/spire/agent/c/d",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := makeAgentID(trustDomain, tt.agentPathTemplate, tt.doc, tt.tags)
			require.NoError(t, err)
			require.Equal(t, got.String(), tt.want)
		})
	}
}
