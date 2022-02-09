package awssecret

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSecretsManagerClient struct {
	storage map[string]string
}

func (sm *fakeSecretsManagerClient) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if value, ok := sm.storage[*input.SecretId]; ok {
		return &secretsmanager.GetSecretValueOutput{
			ARN:          input.SecretId,
			SecretString: &value,
		}, nil
	}
	return nil, fmt.Errorf("secret not found")
}

func newFakeSecretsManagerClient(ctx context.Context, config *Configuration, region string) (secretsManagerClient, error) {
	sm := new(fakeSecretsManagerClient)

	if region == "" {
		return nil, &aws.MissingRegionError{}
	}

	cert, err := os.ReadFile("testdata/keys/EC/cert.pem")
	if err != nil {
		return nil, err
	}

	key, err := os.ReadFile("testdata/keys/EC/private_key.pem")
	if err != nil {
		return nil, err
	}

	alternativeKey, err := os.ReadFile("testdata/keys/EC/alternative_key.pem")
	if err != nil {
		return nil, err
	}

	sm.storage = map[string]string{
		"cert":            string(cert),
		"key":             string(key),
		"alternative_key": string(alternativeKey),
		"invalid_cert":    "no a certificate",
		"invalid_key":     "no a key",
	}

	return sm, nil
}
