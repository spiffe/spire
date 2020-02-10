// Provides interfaces and adapters for the KeyManager service
//
// Generated code. Do not modify by hand.
package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"google.golang.org/grpc"
)

type GenerateKeyRequest = keymanager.GenerateKeyRequest                       //nolint: golint
type GenerateKeyResponse = keymanager.GenerateKeyResponse                     //nolint: golint
type GetPublicKeyRequest = keymanager.GetPublicKeyRequest                     //nolint: golint
type GetPublicKeyResponse = keymanager.GetPublicKeyResponse                   //nolint: golint
type GetPublicKeysRequest = keymanager.GetPublicKeysRequest                   //nolint: golint
type GetPublicKeysResponse = keymanager.GetPublicKeysResponse                 //nolint: golint
type HashAlgorithm = keymanager.HashAlgorithm                                 //nolint: golint
type KeyManagerClient = keymanager.KeyManagerClient                           //nolint: golint
type KeyManagerServer = keymanager.KeyManagerServer                           //nolint: golint
type KeyType = keymanager.KeyType                                             //nolint: golint
type PSSOptions = keymanager.PSSOptions                                       //nolint: golint
type PublicKey = keymanager.PublicKey                                         //nolint: golint
type SignDataRequest = keymanager.SignDataRequest                             //nolint: golint
type SignDataRequest_HashAlgorithm = keymanager.SignDataRequest_HashAlgorithm //nolint: golint
type SignDataRequest_PssOptions = keymanager.SignDataRequest_PssOptions       //nolint: golint
type SignDataResponse = keymanager.SignDataResponse                           //nolint: golint
type UnimplementedKeyManagerServer = keymanager.UnimplementedKeyManagerServer //nolint: golint

const (
	Type                                     = "KeyManager"
	HashAlgorithm_SHA224                     = keymanager.HashAlgorithm_SHA224                     //nolint: golint
	HashAlgorithm_SHA256                     = keymanager.HashAlgorithm_SHA256                     //nolint: golint
	HashAlgorithm_SHA384                     = keymanager.HashAlgorithm_SHA384                     //nolint: golint
	HashAlgorithm_SHA3_224                   = keymanager.HashAlgorithm_SHA3_224                   //nolint: golint
	HashAlgorithm_SHA3_256                   = keymanager.HashAlgorithm_SHA3_256                   //nolint: golint
	HashAlgorithm_SHA3_384                   = keymanager.HashAlgorithm_SHA3_384                   //nolint: golint
	HashAlgorithm_SHA3_512                   = keymanager.HashAlgorithm_SHA3_512                   //nolint: golint
	HashAlgorithm_SHA512                     = keymanager.HashAlgorithm_SHA512                     //nolint: golint
	HashAlgorithm_SHA512_224                 = keymanager.HashAlgorithm_SHA512_224                 //nolint: golint
	HashAlgorithm_SHA512_256                 = keymanager.HashAlgorithm_SHA512_256                 //nolint: golint
	HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM = keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM //nolint: golint
	KeyType_EC_P256                          = keymanager.KeyType_EC_P256                          //nolint: golint
	KeyType_EC_P384                          = keymanager.KeyType_EC_P384                          //nolint: golint
	KeyType_RSA_1024                         = keymanager.KeyType_RSA_1024                         //nolint: golint
	KeyType_RSA_2048                         = keymanager.KeyType_RSA_2048                         //nolint: golint
	KeyType_RSA_4096                         = keymanager.KeyType_RSA_4096                         //nolint: golint
	KeyType_UNSPECIFIED_KEY_TYPE             = keymanager.KeyType_UNSPECIFIED_KEY_TYPE             //nolint: golint
)

// KeyManager is the client interface for the service type KeyManager interface.
type KeyManager interface {
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the KeyManager plugin.
func PluginServer(server KeyManagerServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server KeyManagerServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	keymanager.RegisterKeyManagerServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the KeyManager plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(keymanager.NewKeyManagerClient(conn))
}

func AdaptPluginClient(client KeyManagerClient) KeyManager {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client KeyManagerClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GenerateKey(ctx context.Context, in *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	return a.client.GenerateKey(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) GetPublicKey(ctx context.Context, in *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	return a.client.GetPublicKey(ctx, in)
}

func (a pluginClientAdapter) GetPublicKeys(ctx context.Context, in *GetPublicKeysRequest) (*GetPublicKeysResponse, error) {
	return a.client.GetPublicKeys(ctx, in)
}

func (a pluginClientAdapter) SignData(ctx context.Context, in *SignDataRequest) (*SignDataResponse, error) {
	return a.client.SignData(ctx, in)
}
