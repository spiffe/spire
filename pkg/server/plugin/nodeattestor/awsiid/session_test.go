package awsiid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/require"
)

type fakeWebIdentitySTSClient struct {
	inputs []*sts.AssumeRoleWithWebIdentityInput
}

func (c *fakeWebIdentitySTSClient) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	c.inputs = append(c.inputs, input)
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("WEBIDENTITYKEYID"),
			SecretAccessKey: aws.String("WEBIDENTITYSECRET"),
			SessionToken:    aws.String("WEBIDENTITYTOKEN"),
			Expiration:      aws.Time(time.Now().Add(time.Hour)),
		},
	}, nil
}

func TestNewAWSConfigWebIdentity(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("projected-token"), 0o600))

	fake := new(fakeWebIdentitySTSClient)
	var stsRegion string
	orig := newWebIdentitySTSClient
	newWebIdentitySTSClient = func(conf aws.Config) stscreds.AssumeRoleWithWebIdentityAPIClient {
		stsRegion = conf.Region
		return fake
	}
	t.Cleanup(func() { newWebIdentitySTSClient = orig })

	conf, err := newAWSConfig(context.Background(), &SessionConfig{
		WebIdentityRoleARN:   "arn:aws-us-gov:iam::123456789012:role/spire-server",
		WebIdentityTokenFile: tokenFile,
	}, "us-gov-west-1", "")
	require.NoError(t, err)

	creds, err := conf.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "WEBIDENTITYKEYID", creds.AccessKeyID)
	require.Equal(t, "WEBIDENTITYSECRET", creds.SecretAccessKey)
	require.Equal(t, "WEBIDENTITYTOKEN", creds.SessionToken)

	require.Equal(t, "us-gov-west-1", stsRegion)
	require.Len(t, fake.inputs, 1)
	require.Equal(t, "arn:aws-us-gov:iam::123456789012:role/spire-server", aws.ToString(fake.inputs[0].RoleArn))
	require.Equal(t, "projected-token", aws.ToString(fake.inputs[0].WebIdentityToken))
}
