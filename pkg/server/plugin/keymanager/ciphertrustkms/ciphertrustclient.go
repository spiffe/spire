package ciphertrustkms

import (
	"context"

	"google.golang.org/api/option"
)

type cloudKeyManagementServiceCipherTrust interface {
	AsymmetricSignCipherTrust(ctx context.Context, KeyName string, keyVersion int, data []byte) (*SignResponse, error)
	ListCryptoKeysCipherTrust(ctx context.Context, filter string) (*CipherTrustCryptoKeysList, error)
	ListCryptoKeyVersionsCipherTrust(ctx context.Context, id string, filter string) (*CipherTrustCryptoKeysList, error)
	GetPublicKeyCipherTrust(ctx context.Context, key *Key) (*CipherTrustCryptoKey, error)
	CreateCryptoKeyCipherTrust(ctx context.Context, cryptoKeyId string, labels map[string]string) (*CipherTrustCryptoKey, error)
	CreateCryptoKeyVersionCipherTrust(ctx context.Context, keyId string) (*CipherTrustCryptoKey, error)
	UpdateCryptoKeyCipherTrust(ctx context.Context, cryptokey *Key) (*Key, error)
}

type kmsClientCipherTrust struct {
	internalclient *clientApi
}

func (c *kmsClientCipherTrust) AsymmetricSignCipherTrust(ctx context.Context, KeyName string, keyVersion int, data []byte) (*SignResponse, error) {
	return c.internalclient.SignMessage(KeyName, keyVersion, data)
}

func (c *kmsClientCipherTrust) GetPublicKeyCipherTrust(ctx context.Context, key *Key) (*CipherTrustCryptoKey, error) {
	return c.internalclient.GetPubKey(key.Resource.ID)
}

func (c *kmsClientCipherTrust) ListCryptoKeyVersionsCipherTrust(ctx context.Context, id string, filter string) (*CipherTrustCryptoKeysList, error) {
	return c.internalclient.ListCrytoKeyVersions(id, filter)
}

func (c *kmsClientCipherTrust) ListCryptoKeysCipherTrust(ctx context.Context, filter string) (*CipherTrustCryptoKeysList, error) {
	return c.internalclient.ListCryptoKeys(ctx, filter)
}

func (c *kmsClientCipherTrust) CreateCryptoKeyCipherTrust(ctx context.Context, cryptoKeyId string, labels map[string]string) (*CipherTrustCryptoKey, error) {
	return c.internalclient.CreateKey(cryptoKeyId, labels)
}

func (c *kmsClientCipherTrust) CreateCryptoKeyVersionCipherTrust(ctx context.Context, keyId string) (*CipherTrustCryptoKey, error) {
	return c.internalclient.CreateKeyVersion(keyId)
}

func (c *kmsClientCipherTrust) UpdateCryptoKeyCipherTrust(ctx context.Context, cryptokey *Key) (*Key, error) {
	return c.internalclient.UpdateKeyLabel(cryptokey.Name, cryptokey.ID, cryptokey.Labels, cryptokey.Labels)
}
func newKMSClient(ctx context.Context, opts ...option.ClientOption) (cloudKeyManagementServiceCipherTrust, error) {
	client := new(clientApi)
	return &kmsClientCipherTrust{
		internalclient: client,
	}, nil
}
