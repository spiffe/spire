package gcpkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
	"testing"

	"cloud.google.com/go/iam"
	"github.com/googleapis/gax-go/v2"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/api/iterator"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeCryptoKeyIterator struct {
	nextErr error

	index      int
	cryptoKeys []*kmspb.CryptoKey
}

func (i *fakeCryptoKeyIterator) Next() (cryptoKey *kmspb.CryptoKey, err error) {
	if i.nextErr != nil {
		return nil, i.nextErr
	}

	if i.index >= len(i.cryptoKeys) {
		return nil, iterator.Done
	}

	cryptoKey = i.cryptoKeys[i.index]
	i.index++
	return cryptoKey, nil
}

type fakeCryptoKeyVersionIterator struct {
	nextErr error

	index             int
	cryptoKeyVersions []*kmspb.CryptoKeyVersion
}

func (i *fakeCryptoKeyVersionIterator) Next() (cryptoKeyVersion *kmspb.CryptoKeyVersion, err error) {
	if i.nextErr != nil {
		return nil, i.nextErr
	}

	if i.index >= len(i.cryptoKeyVersions) {
		return nil, iterator.Done
	}

	cryptoKeyVersion = i.cryptoKeyVersions[i.index]
	i.index++
	return cryptoKeyVersion, nil
}

type fakeCryptoKey struct {
	*kmspb.CryptoKey
	fakeCryptoKeyVersions map[string]*fakeCryptoKeyVersion
}

type fakeCryptoKeyVersion struct {
	*kmspb.CryptoKeyVersion

	privateKey crypto.Signer
	publicKey  *kmspb.PublicKey
}

type fakeStore struct {
	fakeCryptoKeys map[string]*fakeCryptoKey

	clk *clock.Mock
}

func (fs *fakeStore) fetchCryptoKeyVersion(name string) (*fakeCryptoKeyVersion, error) {
	parent := path.Dir(path.Dir(name))
	fakeCryptoKey, ok := fs.fakeCryptoKeys[parent]
	if !ok {
		return nil, fmt.Errorf("could not get parent CryptoKey for %q CryptoKeyVersion", name)
	}

	version := path.Base(name)
	fakeCryptokeyVersion, ok := fakeCryptoKey.fakeCryptoKeyVersions[version]
	if ok {
		return fakeCryptokeyVersion, nil
	}

	return nil, fmt.Errorf("could not find CryptoKeyVersion %q", version)
}

func (fs *fakeStore) putCryptoKey(fakeCryptoKey *fakeCryptoKey) {
	fs.fakeCryptoKeys[fakeCryptoKey.Name] = fakeCryptoKey
}

func (fs *fakeStore) putCryptoKeyVersion(parent string, fakeCryptoKeyVersion *fakeCryptoKeyVersion) {
	fs.fakeCryptoKeys[parent].fakeCryptoKeyVersions[path.Base(fakeCryptoKeyVersion.Name)] = fakeCryptoKeyVersion
}

type fakeIAMHandle struct {
	expectedPolicy *iam.Policy3

	policyErr    error
	setPolicyErr error
}

func (h *fakeIAMHandle) V3() iamHandler3 {
	return &fakeIAMHandle3{
		expectedPolicy: h.expectedPolicy,
		policyErr:      h.policyErr,
		setPolicyErr:   h.setPolicyErr,
	}
}

type fakeIAMHandle3 struct {
	expectedPolicy *iam.Policy3

	policyErr    error
	setPolicyErr error
}

func (h3 *fakeIAMHandle3) Policy(context.Context) (*iam.Policy3, error) {
	if h3.policyErr != nil {
		return nil, h3.policyErr
	}
	return &iam.Policy3{}, nil
}

func (h3 *fakeIAMHandle3) SetPolicy(ctx context.Context, policy *iam.Policy3) error {
	if h3.expectedPolicy != nil {
		if !reflect.DeepEqual(h3.expectedPolicy, policy) {
			return fmt.Errorf("unexpected policy: %v", policy)
		}
	}

	return h3.setPolicyErr
}

type fakeKMSClient struct {
	t *testing.T

	asymmetricSignErr          error
	closeErr                   error
	createCryptoKeyErr         error
	destroyCryptoKeyVersionErr error
	destroyTime                *timestamppb.Timestamp
	fakeIAMHandle              *fakeIAMHandle
	getCryptoKeyVersionErr     error
	getPublicKeyErr            error
	getTokeninfoErr            error
	listCryptoKeysErr          error
	listCryptoKeyVersionsErr   error
	opts                       []option.ClientOption
	pemCrc32C                  *wrapperspb.Int64Value
	signatureCrc32C            *wrapperspb.Int64Value
	store                      fakeStore
	testKeys                   testkey.Keys
	tokeninfo                  *oauth2.Tokeninfo
	updateCryptoKeyErr         error
}

func (k *fakeKMSClient) AsymmetricSign(ctx context.Context, signReq *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if k.asymmetricSignErr != nil {
		return nil, k.asymmetricSignErr
	}

	if signReq.Digest == nil {
		return nil, status.Error(codes.InvalidArgument, "plugin should be signing over a digest")
	}

	fakeCryptoKeyVersion, err := k.store.fetchCryptoKeyVersion(signReq.Name)
	if err != nil {
		return nil, err
	}

	signRSA := func(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		if _, ok := fakeCryptoKeyVersion.privateKey.(*rsa.PrivateKey); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid signing algorithm for RSA key")
		}
		return fakeCryptoKeyVersion.privateKey.Sign(rand.Reader, digest, opts)
	}
	signECDSA := func(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		if _, ok := fakeCryptoKeyVersion.privateKey.(*ecdsa.PrivateKey); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid signing algorithm for ECDSA key")
		}
		return fakeCryptoKeyVersion.privateKey.Sign(rand.Reader, digest, opts)
	}

	cryptoKeyName := path.Dir(path.Dir(signReq.Name))
	fck, ok := k.store.fakeCryptoKeys[cryptoKeyName]
	if !ok {
		return nil, fmt.Errorf("could not find CryptoKey %q", cryptoKeyName)
	}
	var signature []byte
	switch fck.VersionTemplate.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		signature, err = signECDSA(signReq.Digest.GetSha256(), crypto.SHA256)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		signature, err = signECDSA(signReq.Digest.GetSha384(), crypto.SHA384)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		signature, err = signRSA(signReq.Digest.GetSha256(), crypto.SHA256)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		signature, err = signRSA(signReq.Digest.GetSha256(), crypto.SHA256)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signing algorithm: %s", fck.VersionTemplate.Algorithm)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to sign digest: %v", err)
	}

	signatureCrc32C := &wrapperspb.Int64Value{Value: int64(crc32Checksum(signature))}
	if k.signatureCrc32C != nil {
		// Override the SignatureCrc32C value
		signatureCrc32C = k.signatureCrc32C
	}

	return &kmspb.AsymmetricSignResponse{
		Signature:       signature,
		SignatureCrc32C: signatureCrc32C,
		Name:            signReq.Name,
	}, nil
}

func (k *fakeKMSClient) Close() error {
	return k.closeErr
}

func (k *fakeKMSClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	if k.createCryptoKeyErr != nil {
		return nil, k.createCryptoKeyErr
	}

	cryptoKey := &kmspb.CryptoKey{
		Name:            path.Join(req.Parent, req.CryptoKeyId),
		Labels:          req.CryptoKey.Labels,
		VersionTemplate: req.CryptoKey.VersionTemplate,
	}
	version := "1"
	fckv, err := k.createFakeCryptoKeyVersion(cryptoKey, version)
	if err != nil {
		return nil, err
	}

	fck := &fakeCryptoKey{
		CryptoKey: cryptoKey,
		fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
			version: fckv,
		},
	}
	k.store.putCryptoKey(fck)

	return cryptoKey, nil
}

func (k *fakeKMSClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if k.createCryptoKeyErr != nil {
		return nil, k.createCryptoKeyErr
	}

	fck, ok := k.store.fakeCryptoKeys[req.Parent]
	if !ok {
		return nil, fmt.Errorf("could not find parent CryptoKey %q", req.Parent)
	}
	fckv, err := k.createFakeCryptoKeyVersion(fck.CryptoKey, fmt.Sprint(len(fck.fakeCryptoKeyVersions)+1))
	if err != nil {
		return nil, err
	}
	k.store.putCryptoKeyVersion(req.Parent, fckv)

	return &kmspb.CryptoKeyVersion{
		Algorithm: req.CryptoKeyVersion.Algorithm,
		Name:      fckv.Name,
		State:     kmspb.CryptoKeyVersion_ENABLED,
	}, nil
}

func (k *fakeKMSClient) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if k.destroyCryptoKeyVersionErr != nil {
		return nil, k.destroyCryptoKeyVersionErr
	}

	fckv, err := k.store.fetchCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, err
	}

	var destroyTime *timestamppb.Timestamp
	if k.destroyTime != nil {
		destroyTime = k.destroyTime
	} else {
		destroyTime = timestamppb.Now()
	}

	cryptoKeyVersion := &kmspb.CryptoKeyVersion{
		DestroyTime: destroyTime,
		Name:        fckv.Name,
		State:       kmspb.CryptoKeyVersion_DESTROY_SCHEDULED,
	}
	fckv.CryptoKeyVersion = cryptoKeyVersion
	k.store.putCryptoKeyVersion(path.Dir(path.Dir(fckv.CryptoKeyVersion.Name)), fckv)

	return cryptoKeyVersion, nil
}

func (k *fakeKMSClient) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if k.getCryptoKeyVersionErr != nil {
		return nil, k.getCryptoKeyVersionErr
	}

	fakeCryptoKeyVersion, err := k.store.fetchCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, err
	}

	return fakeCryptoKeyVersion.CryptoKeyVersion, nil
}

func (k *fakeKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	if k.getPublicKeyErr != nil {
		return nil, k.getPublicKeyErr
	}

	fakeCryptoKeyVersion, err := k.store.fetchCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, err
	}

	if k.pemCrc32C != nil {
		// Override pemCrc32C
		fakeCryptoKeyVersion.publicKey.PemCrc32C = k.pemCrc32C
	}

	return fakeCryptoKeyVersion.publicKey, nil
}

func (k *fakeKMSClient) GetTokeninfo() (*oauth2.Tokeninfo, error) {
	return k.tokeninfo, k.getTokeninfoErr
}

func (k *fakeKMSClient) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...gax.CallOption) cryptoKeyIterator {
	if k.listCryptoKeysErr != nil {
		return &fakeCryptoKeyIterator{nextErr: k.listCryptoKeysErr}
	}
	var cryptoKeys []*kmspb.CryptoKey

	for _, fck := range k.store.fakeCryptoKeys {
		// Make sure that it's within the same Key Ring.
		// The Key Ring name es specified in req.Parent.
		// The Key Ring name is three levels up from the CryptoKey name.
		if req.Parent != path.Dir(path.Dir(path.Dir(fck.Name))) {
			// Key Ring doesn't match.
			continue
		}

		// We Have a simplified filtering logic in this fake implementation,
		// where we only care about the spire-active label.
		if req.Filter != "" {
			if !strings.Contains(req.Filter, "labels.spire-active = true") {
				{
					k.t.Fatal("Unsupported filter in ListCryptoKeys request")
				}
				if fck.Labels[labelNameActive] != "true" {
					continue
				}
			}
		}

		cryptoKeys = append(cryptoKeys, fck.CryptoKey)
	}

	return &fakeCryptoKeyIterator{cryptoKeys: cryptoKeys}
}

func (k *fakeKMSClient) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...gax.CallOption) cryptoKeyVersionIterator {
	if k.listCryptoKeyVersionsErr != nil {
		return &fakeCryptoKeyVersionIterator{nextErr: k.listCryptoKeyVersionsErr}
	}

	var cryptoKeyVersions []*kmspb.CryptoKeyVersion
	fck, ok := k.store.fakeCryptoKeys[req.Parent]
	if !ok {
		return &fakeCryptoKeyVersionIterator{nextErr: errors.New("parent CryptoKey not found")}
	}

	for _, fckv := range fck.fakeCryptoKeyVersions {
		// We Have a simplified filtering logic in this fake implementation,
		// where we only support filtering by enabled status.
		if req.Filter != "" {
			if req.Filter != "state = "+kmspb.CryptoKeyVersion_ENABLED.String() {
				k.t.Fatal("Unsupported filter in ListCryptoKeyVersions request")
			}
			if fckv.State != kmspb.CryptoKeyVersion_ENABLED {
				continue
			}
		}
		cryptoKeyVersions = append(cryptoKeyVersions, fckv.CryptoKeyVersion)
	}

	return &fakeCryptoKeyVersionIterator{cryptoKeyVersions: cryptoKeyVersions}
}

func (k *fakeKMSClient) ResourceIAM(string) iamHandler {
	return k.fakeIAMHandle
}

func (k *fakeKMSClient) UpdateCryptoKey(ctx context.Context, req *kmspb.UpdateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	if k.updateCryptoKeyErr != nil {
		return nil, k.updateCryptoKeyErr
	}

	fck, ok := k.store.fakeCryptoKeys[req.CryptoKey.Name]
	if !ok {
		return nil, fmt.Errorf("cryptoKey %q not found", req.CryptoKey.Name)
	}
	fck.CryptoKey = req.CryptoKey
	return fck.CryptoKey, nil
}

func (k *fakeKMSClient) createFakeCryptoKeyVersion(cryptoKey *kmspb.CryptoKey, version string) (*fakeCryptoKeyVersion, error) {
	var privateKey crypto.Signer
	switch cryptoKey.VersionTemplate.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		privateKey = k.testKeys.NewEC256(k.t)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		privateKey = k.testKeys.NewEC384(k.t)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		privateKey = k.testKeys.NewRSA2048(k.t)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		privateKey = k.testKeys.NewRSA4096(k.t)
	default:
		return nil, fmt.Errorf("unknown algorithm %q", cryptoKey.VersionTemplate.Algorithm)
	}

	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	pemCert := new(bytes.Buffer)
	if err = pem.Encode(pemCert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pkixData,
	}); err != nil {
		return nil, err
	}

	return &fakeCryptoKeyVersion{
		privateKey: privateKey,
		publicKey: &kmspb.PublicKey{
			Pem:       pemCert.String(),
			PemCrc32C: &wrapperspb.Int64Value{Value: int64(crc32Checksum(pemCert.Bytes()))},
		},
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Name:      path.Join(cryptoKey.Name, "cryptoKeyVersions", version),
			Algorithm: cryptoKey.VersionTemplate.Algorithm,
		},
	}, nil
}

func (k *fakeKMSClient) getDefaultPolicy() *iam.Policy3 {
	policy := new(iam.Policy3)
	policy.Bindings = []*iampb.Binding{
		{
			Role:    "roles/cloudkms.signerVerifier",
			Members: []string{fmt.Sprintf("serviceAccount:%s", k.tokeninfo.Email)},
		},
	}
	return policy
}

func (k *fakeKMSClient) putFakeCryptoKeys(fakeCryptoKeys []fakeCryptoKey) {
	for _, fakeCryptoKey := range fakeCryptoKeys {
		newFakeCryptoKey := fakeCryptoKey
		k.store.putCryptoKey(&newFakeCryptoKey)
	}
}

func newKMSClientFake(t *testing.T, c *clock.Mock) *fakeKMSClient {
	return &fakeKMSClient{
		fakeIAMHandle: &fakeIAMHandle{},
		store:         newFakeStore(c),
		t:             t,
		tokeninfo: &oauth2.Tokeninfo{
			Email: "email@example.org",
		},
	}
}

func newFakeStore(c *clock.Mock) fakeStore {
	return fakeStore{
		fakeCryptoKeys: make(map[string]*fakeCryptoKey),
		clk:            c,
	}
}
