package aws

import (
	"testing"
	"text/template"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	templateWithTags = template.Must(template.New("agent-svid").Parse("{{ .Tags.a }}/{{ .Tags.b }}"))
	trustDomain      = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestMakeSpiffeID(t *testing.T) {
	tests := []struct {
		name              string
		trustDomain       spiffeid.TrustDomain
		agentPathTemplate *template.Template
		doc               ec2metadata.EC2InstanceIdentityDocument
		tags              instanceTags
		want              string
	}{
		{
			name:              "default",
			trustDomain:       trustDomain,
			agentPathTemplate: defaultAgentPathTemplate,
			doc: ec2metadata.EC2InstanceIdentityDocument{
				Region:     "region",
				InstanceID: "instanceID",
				AccountID:  "accountID",
			},
			want: "spiffe://example.org/spire/agent/aws_iid/accountID/region/instanceID",
		},
		{
			name:              "instance tags",
			trustDomain:       trustDomain,
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
			got, err := makeSpiffeID(tt.trustDomain, tt.agentPathTemplate, tt.doc, tt.tags)
			require.NoError(t, err)
			require.Equal(t, got.String(), tt.want)
		})
	}
}
