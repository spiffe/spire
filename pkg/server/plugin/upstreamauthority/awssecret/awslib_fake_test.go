package awssecret

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

type fakeSecretsManagerClient struct {
	storage map[string]string
}

type testKeysAndCerts struct {
	rootKey          *ecdsa.PrivateKey
	rootCert         *x509.Certificate
	alternativeKey   *ecdsa.PrivateKey
	intermediateKey  *ecdsa.PrivateKey
	intermediateCert *x509.Certificate
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

func generateTestData(t *testing.T, clk clock.Clock) (*testKeysAndCerts, func(context.Context, *Configuration, string) (secretsManagerClient, error)) {
	var keys testkey.Keys

	rootKey := keys.NewEC256(t)
	rootCertificate := createCertificate(t, clk, "spiffe://root", rootKey, nil, nil)

	intermediateKey := keys.NewEC256(t)
	intermediateCertificate := createCertificate(t, clk, "spiffe://intermediate", intermediateKey, rootCertificate, rootKey)

	alternativeKey := keys.NewEC256(t)

	sm := new(fakeSecretsManagerClient)

	sm.storage = map[string]string{
		"cert":              certToPEMstr(rootCertificate),
		"key":               keyToPEMstr(t, rootKey),
		"alternative_key":   keyToPEMstr(t, alternativeKey),
		"bundle":            certToPEMstr(rootCertificate),
		"intermediate_cert": certToPEMstr(intermediateCertificate),
		"intermediate_key":  keyToPEMstr(t, intermediateKey),
		"invalid_cert":      "no a certificate",
		"invalid_key":       "no a key",
	}

	keysAndCerts := &testKeysAndCerts{
		rootKey:          rootKey,
		rootCert:         rootCertificate,
		alternativeKey:   alternativeKey,
		intermediateKey:  intermediateKey,
		intermediateCert: intermediateCertificate,
	}

	makeSecretsManagerClient := func(ctx context.Context, config *Configuration, region string) (secretsManagerClient, error) {
		if region == "" {
			return nil, &aws.MissingRegionError{}
		}
		return sm, nil
	}

	return keysAndCerts, makeSecretsManagerClient
}

func createCertificate(
	t *testing.T, clk clock.Clock,
	uri string,
	key crypto.Signer,
	parent *x509.Certificate,
	parentKey crypto.Signer,
) *x509.Certificate {
	now := clk.Now()

	u, err := url.Parse(uri)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
		URIs:                  []*url.URL{u},
	}

	// Making the template and key their own parents
	// generates a self-signed certificate
	if parent == nil {
		parent = template
		parentKey = key
	}

	return testca.CreateCertificate(t, template, parent, key.Public(), parentKey)
}

func certToPEMstr(cert *x509.Certificate) string {
	return string(pemutil.EncodeCertificate(cert))
}

func keyToPEMstr(t *testing.T, key *ecdsa.PrivateKey) string {
	data, err := pemutil.EncodeECPrivateKey(key)
	require.NoError(t, err)

	return string(data)
}
