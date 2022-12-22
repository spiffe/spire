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
	"sync"
	"testing"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/api/iterator"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeCryptoKeyIterator struct {
	mu sync.RWMutex

	index      int
	cryptoKeys []*kmspb.CryptoKey
	nextErr    error
}

func (i *fakeCryptoKeyIterator) Next() (cryptoKey *kmspb.CryptoKey, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()

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
	mu sync.RWMutex

	index             int
	cryptoKeyVersions []*kmspb.CryptoKeyVersion
	nextErr           error
}

func (i *fakeCryptoKeyVersionIterator) Next() (cryptoKeyVersion *kmspb.CryptoKeyVersion, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()

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
	mu sync.RWMutex
	*kmspb.CryptoKey
	fakeCryptoKeyVersions map[string]*fakeCryptoKeyVersion
}

func (fck *fakeCryptoKey) fetchFakeCryptoKeyVersions() map[string]*fakeCryptoKeyVersion {
	fck.mu.RLock()
	defer fck.mu.RUnlock()

	if fck.fakeCryptoKeyVersions == nil {
		return nil
	}

	fakeCryptoKeyVersions := make(map[string]*fakeCryptoKeyVersion, len(fck.fakeCryptoKeyVersions))
	for key, fakeCryptoKeyVersion := range fck.fakeCryptoKeyVersions {
		fakeCryptoKeyVersions[key] = fakeCryptoKeyVersion
	}
	return fakeCryptoKeyVersions
}

func (fck *fakeCryptoKey) getLabelValue(key string) string {
	fck.mu.RLock()
	defer fck.mu.RUnlock()

	return fck.Labels[key]
}

func (fck *fakeCryptoKey) getName() string {
	fck.mu.RLock()
	defer fck.mu.RUnlock()

	return fck.Name
}

func (fck *fakeCryptoKey) putFakeCryptoKeyVersion(fckv *fakeCryptoKeyVersion) {
	fck.mu.Lock()
	defer fck.mu.Unlock()

	fck.fakeCryptoKeyVersions[path.Base(fckv.Name)] = fckv
}

type fakeCryptoKeyVersion struct {
	*kmspb.CryptoKeyVersion

	privateKey crypto.Signer
	publicKey  *kmspb.PublicKey
}

type fakeStore struct {
	mu             sync.RWMutex
	fakeCryptoKeys map[string]*fakeCryptoKey

	clk *clock.Mock
}

func (fs *fakeStore) fetchFakeCryptoKey(name string) (*fakeCryptoKey, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	fakeCryptoKey, ok := fs.fakeCryptoKeys[name]
	return fakeCryptoKey, ok
}

func (fs *fakeStore) fetchFakeCryptoKeys() map[string]*fakeCryptoKey {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.fakeCryptoKeys == nil {
		return nil
	}

	fakeCryptoKeys := make(map[string]*fakeCryptoKey, len(fs.fakeCryptoKeys))
	for key, fakeCryptoKey := range fs.fakeCryptoKeys {
		fakeCryptoKeys[key] = fakeCryptoKey
	}
	return fakeCryptoKeys
}

func (fs *fakeStore) fetchFakeCryptoKeyVersion(name string) (fakeCryptoKeyVersion, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	parent := path.Dir(path.Dir(name))
	fakeCryptoKey, ok := fs.fakeCryptoKeys[parent]
	if !ok {
		return fakeCryptoKeyVersion{}, fmt.Errorf("could not get parent CryptoKey for %q CryptoKeyVersion", name)
	}

	version := path.Base(name)
	fakeCryptoKey.mu.RLock()
	defer fakeCryptoKey.mu.RUnlock()
	fakeCryptokeyVersion, ok := fakeCryptoKey.fakeCryptoKeyVersions[version]
	if ok {
		return *fakeCryptokeyVersion, nil
	}

	return fakeCryptoKeyVersion{}, fmt.Errorf("could not find CryptoKeyVersion %q", version)
}

func (fs *fakeStore) putFakeCryptoKey(fck *fakeCryptoKey) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.fakeCryptoKeys[fck.Name] = fck
}

type fakeIAMHandle struct {
	mu             sync.RWMutex
	expectedPolicy *iam.Policy3
	policyErr      error
	setPolicyErr   error
}

func (h *fakeIAMHandle) V3() iamHandler3 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return &fakeIAMHandle3{
		expectedPolicy: h.expectedPolicy,
		policyErr:      h.policyErr,
		setPolicyErr:   h.setPolicyErr,
	}
}

func (h *fakeIAMHandle) setExpectedPolicy(expectedPolicy *iam.Policy3) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.expectedPolicy = expectedPolicy
}

func (h *fakeIAMHandle) setPolicyError(fakeError error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.policyErr = fakeError
}

func (h *fakeIAMHandle) setSetPolicyErr(fakeError error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.setPolicyErr = fakeError
}

type fakeIAMHandle3 struct {
	mu             sync.RWMutex
	expectedPolicy *iam.Policy3
	policyErr      error
	setPolicyErr   error
}

func (h3 *fakeIAMHandle3) Policy(context.Context) (*iam.Policy3, error) {
	h3.mu.RLock()
	defer h3.mu.RUnlock()

	if h3.policyErr != nil {
		return nil, h3.policyErr
	}
	return &iam.Policy3{}, nil
}

func (h3 *fakeIAMHandle3) SetPolicy(ctx context.Context, policy *iam.Policy3) error {
	h3.mu.Lock()
	defer h3.mu.Unlock()

	if h3.expectedPolicy != nil {
		if !reflect.DeepEqual(h3.expectedPolicy, policy) {
			return fmt.Errorf("unexpected policy: %v", policy)
		}
	}

	return h3.setPolicyErr
}

type fakeKMSClient struct {
	t *testing.T

	mu                           sync.RWMutex
	asymmetricSignErr            error
	closeErr                     error
	createCryptoKeyErr           error
	initialCryptoKeyVersionState kmspb.CryptoKeyVersion_CryptoKeyVersionState
	destroyCryptoKeyVersionErr   error
	destroyTime                  *timestamppb.Timestamp
	fakeIAMHandle                *fakeIAMHandle
	getCryptoKeyVersionErr       error
	getPublicKeyErrs             []error
	getTokeninfoErr              error
	listCryptoKeysErr            error
	listCryptoKeyVersionsErr     error
	opts                         []option.ClientOption
	pemCrc32C                    *wrapperspb.Int64Value
	signatureCrc32C              *wrapperspb.Int64Value
	store                        fakeStore
	tokeninfo                    *oauth2.Tokeninfo
	updateCryptoKeyErr           error
	keyIsDisabled                bool
}

func (k *fakeKMSClient) setAsymmetricSignErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.asymmetricSignErr = fakeError
}

func (k *fakeKMSClient) setCreateCryptoKeyErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.createCryptoKeyErr = fakeError
}

func (k *fakeKMSClient) setInitialCryptoKeyVersionState(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) {
	k.initialCryptoKeyVersionState = state
}

func (k *fakeKMSClient) setDestroyCryptoKeyVersionErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.destroyCryptoKeyVersionErr = fakeError
}

func (k *fakeKMSClient) setDestroyTime(fakeDestroyTime *timestamppb.Timestamp) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.destroyTime = fakeDestroyTime
}

func (k *fakeKMSClient) setGetCryptoKeyVersionErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.getCryptoKeyVersionErr = fakeError
}

func (k *fakeKMSClient) setIsKeyDisabled(ok bool) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.keyIsDisabled = ok
}

func (k *fakeKMSClient) setGetPublicKeySequentialErrs(fakeError error, count int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	fakeErrors := make([]error, count)
	for i := 0; i < count; i++ {
		fakeErrors[i] = fakeError
	}
	k.getPublicKeyErrs = fakeErrors
}

func (k *fakeKMSClient) nextGetPublicKeySequentialErr() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.getPublicKeyErrs) == 0 {
		return nil
	}
	err := k.getPublicKeyErrs[0]
	k.getPublicKeyErrs = k.getPublicKeyErrs[1:]
	return err
}

func (k *fakeKMSClient) setGetTokeninfoErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.getTokeninfoErr = fakeError
}

func (k *fakeKMSClient) setListCryptoKeysErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.listCryptoKeysErr = fakeError
}

func (k *fakeKMSClient) setPEMCrc32C(pemCrc32C *wrapperspb.Int64Value) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.pemCrc32C = pemCrc32C
}

func (k *fakeKMSClient) setSignatureCrc32C(signatureCrc32C *wrapperspb.Int64Value) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.signatureCrc32C = signatureCrc32C
}

func (k *fakeKMSClient) setUpdateCryptoKeyErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.updateCryptoKeyErr = fakeError
}

func (k *fakeKMSClient) AsymmetricSign(ctx context.Context, signReq *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.asymmetricSignErr != nil {
		return nil, k.asymmetricSignErr
	}

	if signReq.Digest == nil {
		return nil, status.Error(codes.InvalidArgument, "plugin should be signing over a digest")
	}

	fakeCryptoKeyVersion, err := k.store.fetchFakeCryptoKeyVersion(signReq.Name)
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
	fck, ok := k.store.fetchFakeCryptoKey(cryptoKeyName)
	if !ok {
		return nil, status.Errorf(codes.Internal, "could not find CryptoKey %q", cryptoKeyName)
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
	k.mu.RLock()
	defer k.mu.RUnlock()

	return k.closeErr
}

func (k *fakeKMSClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

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
	k.store.putFakeCryptoKey(fck)

	return cryptoKey, nil
}

func (k *fakeKMSClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

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

	fck.putFakeCryptoKeyVersion(fckv)

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

	parent := path.Dir(path.Dir(req.Name))
	fck, ok := k.store.fetchFakeCryptoKey(parent)
	if !ok {
		return nil, fmt.Errorf("could not get parent CryptoKey for %q CryptoKeyVersion", parent)
	}

	fckv, err := k.store.fetchFakeCryptoKeyVersion(req.Name)
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
	fck.putFakeCryptoKeyVersion(&fckv)

	return cryptoKeyVersion, nil
}

func (k *fakeKMSClient) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.getCryptoKeyVersionErr != nil {
		return nil, k.getCryptoKeyVersionErr
	}

	fakeCryptoKeyVersion, err := k.store.fetchFakeCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, err
	}

	if k.keyIsDisabled {
		fakeCryptoKeyVersion.CryptoKeyVersion.State = kmspb.CryptoKeyVersion_DISABLED
	}
	return fakeCryptoKeyVersion.CryptoKeyVersion, nil
}

func (k *fakeKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	getPublicKeyErr := k.nextGetPublicKeySequentialErr()

	if getPublicKeyErr != nil {
		return nil, getPublicKeyErr
	}

	fakeCryptoKeyVersion, err := k.store.fetchFakeCryptoKeyVersion(req.Name)
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
	k.mu.RLock()
	defer k.mu.RUnlock()

	return k.tokeninfo, k.getTokeninfoErr
}

func (k *fakeKMSClient) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...gax.CallOption) cryptoKeyIterator {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.listCryptoKeysErr != nil {
		return &fakeCryptoKeyIterator{nextErr: k.listCryptoKeysErr}
	}
	var cryptoKeys []*kmspb.CryptoKey
	fakeCryptoKeys := k.store.fetchFakeCryptoKeys()

	for _, fck := range fakeCryptoKeys {
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
	k.mu.RLock()
	defer k.mu.RUnlock()

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
	k.mu.RLock()
	defer k.mu.RUnlock()

	return k.fakeIAMHandle
}

func (k *fakeKMSClient) UpdateCryptoKey(ctx context.Context, req *kmspb.UpdateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	if k.updateCryptoKeyErr != nil {
		return nil, k.updateCryptoKeyErr
	}

	fck, ok := k.store.fetchFakeCryptoKey(req.CryptoKey.Name)
	if !ok {
		return nil, fmt.Errorf("could not find CryptoKey %q", req.CryptoKey.Name)
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	fck.mu.Lock()
	defer fck.mu.Unlock()

	fck.CryptoKey = req.CryptoKey
	return fck.CryptoKey, nil
}

func (k *fakeKMSClient) createFakeCryptoKeyVersion(cryptoKey *kmspb.CryptoKey, version string) (*fakeCryptoKeyVersion, error) {
	var privateKey crypto.Signer
	var testKeys testkey.Keys

	switch cryptoKey.VersionTemplate.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		privateKey = testKeys.NewEC256(k.t)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		privateKey = testKeys.NewEC384(k.t)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		privateKey = testKeys.NewRSA2048(k.t)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		privateKey = testKeys.NewRSA4096(k.t)
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
			State:     k.initialCryptoKeyVersionState,
			Algorithm: cryptoKey.VersionTemplate.Algorithm,
		},
	}, nil
}

func (k *fakeKMSClient) getDefaultPolicy() *iam.Policy3 {
	k.mu.RLock()
	defer k.mu.RUnlock()

	policy := new(iam.Policy3)
	policy.Bindings = []*iampb.Binding{
		{
			Role:    "roles/cloudkms.signerVerifier",
			Members: []string{fmt.Sprintf("serviceAccount:%s", k.tokeninfo.Email)},
		},
	}
	return policy
}

func (k *fakeKMSClient) putFakeCryptoKeys(fakeCryptoKeys []*fakeCryptoKey) {
	for _, fck := range fakeCryptoKeys {
		k.store.putFakeCryptoKey(&fakeCryptoKey{
			CryptoKey:             fck.CryptoKey,
			fakeCryptoKeyVersions: fck.fakeCryptoKeyVersions,
		})
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
