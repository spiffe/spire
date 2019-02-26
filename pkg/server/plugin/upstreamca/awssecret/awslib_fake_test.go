package awssecret

import (
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type fakeSecretsManagerClient struct {
	storage map[string]string
}

func (sm *fakeSecretsManagerClient) GetSecretValueWithContext(ctx aws.Context, input *secretsmanager.GetSecretValueInput, opt ...request.Option) (*secretsmanager.GetSecretValueOutput, error) {

	if value, ok := sm.storage[*input.SecretId]; ok {
		return &secretsmanager.GetSecretValueOutput{
			ARN:          input.SecretId,
			SecretString: &value,
		}, nil
	} else {
		return nil, fmt.Errorf("secret not found")
	}
}

func newFakeSecretsManagerClient(config *AWSSecretConfiguration, region string) (secretsManagerClient, error) {
	sm := new(fakeSecretsManagerClient)

	cert, err := ioutil.ReadFile("_test_data/keys/EC/cert.pem")
	if err != nil {
		return nil, err
	}

	key, err := ioutil.ReadFile("_test_data/keys/EC/private_key.pem")
	if err != nil {
		return nil, err
	}

	sm.storage = map[string]string{
		"cert": string(cert),
		"key":  string(key),
	}

	return sm, nil
}
