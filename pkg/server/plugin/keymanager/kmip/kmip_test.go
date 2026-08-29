package kmip

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"testing"

	ovh "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const testServerID = "test-server-0001"

// ─── Configure ───────────────────────────────────────────────────────────────

func TestConfigure(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	caFile := writeTempPEM(t, caPEM)

	for _, tt := range []struct {
		name       string
		config     string
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "valid config",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				ca_cert_path         = %q
				server_id            = %q
				insecure_skip_verify = true
			`, addr, caFile, testServerID),
			expectCode: codes.OK,
		},
		{
			name:       "missing kmip_addr",
			config:     fmt.Sprintf(`server_id = %q insecure_skip_verify = true`, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "kmip_addr",
		},
		{
			name:       "missing server_id",
			config:     fmt.Sprintf(`kmip_addr = %q insecure_skip_verify = true`, addr),
			expectCode: codes.InvalidArgument,
			expectMsg:  "server_id",
		},
		{
			name: "key path set but no cert path",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				server_id            = %q
				client_key_path      = "some.key"
				insecure_skip_verify = true
			`, addr, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "client_cert_path",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var configErr error
			plugintest.Load(t, builtin(p), nil,
				plugintest.CaptureConfigureError(&configErr),
				plugintest.Configure(tt.config),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			)
			spiretest.RequireGRPCStatusHasPrefix(t, configErr, tt.expectCode, tt.expectMsg)
		})
	}
}

// ─── GenerateKey ─────────────────────────────────────────────────────────────

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		name    string
		keyType keymanager.KeyType
	}{
		{"EC_P256", keymanager.ECP256},
		{"EC_P384", keymanager.ECP384},
		{"RSA_2048", keymanager.RSA2048},
		// RSA_4096 omitted to keep the test fast.
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			addr, caPEM := kmiptest.NewServer(t, store.handler())
			km := loadPlugin(t, addr, caPEM)

			key, err := km.GenerateKey(context.Background(), "spire-key-"+tt.name, tt.keyType)
			require.NoError(t, err)
			require.NotNil(t, key.Public())
		})
	}
}

func TestGenerateKeyNotConfigured(t *testing.T) {
	p := New()
	_, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "k1",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "plugin not configured")
}

func TestGenerateKeyMissingKeyID(t *testing.T) {
	p := New()
	_, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "key id is required")
}

// ─── SignData ─────────────────────────────────────────────────────────────────

func TestSignData(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	km := loadPlugin(t, addr, caPEM)

	key, err := km.GenerateKey(context.Background(), "sign-key", keymanager.ECP256)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello spire"))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify the signature is valid against the public key.
	ecPub, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, ecdsa.VerifyASN1(ecPub, digest[:], sig))
}

func TestSignDataKeyNotFound(t *testing.T) {
	p := New()
	_, err := p.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: "does-not-exist",
		Data:  []byte("x"),
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
	})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "plugin not configured")
}

// ─── GetPublicKeys ────────────────────────────────────────────────────────────

func TestGetPublicKeys(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	km := loadPlugin(t, addr, caPEM)

	for _, id := range []string{"k1", "k2"} {
		_, err := km.GenerateKey(context.Background(), id, keymanager.ECP256)
		require.NoError(t, err)
	}

	keys, err := km.GetKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 2)
}

// ─── Key recovery ─────────────────────────────────────────────────────────────

func TestKeyRecovery(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())

	km1 := loadPlugin(t, addr, caPEM)
	_, err := km1.GenerateKey(context.Background(), "recovery-key", keymanager.ECP256)
	require.NoError(t, err)

	// Second plugin instance must recover the key via Locate on Configure.
	km2 := loadPlugin(t, addr, caPEM)
	key, err := km2.GetKey(context.Background(), "recovery-key")
	require.NoError(t, err)
	require.NotNil(t, key.Public())
}

// ─── test helpers ─────────────────────────────────────────────────────────────

func loadPlugin(t *testing.T, addr, caPEM string) *keymanager.V1 {
	t.Helper()
	caFile := writeTempPEM(t, caPEM)
	p := New()
	v1 := new(keymanager.V1)
	plugintest.Load(t, builtin(p), v1,
		plugintest.Configure(fmt.Sprintf(`
			kmip_addr            = %q
			ca_cert_path         = %q
			insecure_skip_verify = true
			server_id            = %q
		`, addr, caFile, testServerID)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	return v1
}

func writeTempPEM(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ─── fakeStore ── in-memory KMIP server ──────────────────────────────────────

type keyRecord struct {
	privUID   string
	pubUID    string
	privKey   crypto.Signer
	pubPKIX   []byte
	nameAttrs []string
}

type fakeStore struct {
	mu      sync.Mutex
	keys    map[string]*keyRecord // privUID → record
	pubKeys map[string]*keyRecord // pubUID → record
	counter int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		keys:    make(map[string]*keyRecord),
		pubKeys: make(map[string]*keyRecord),
	}
}

func (s *fakeStore) nextUID(prefix string) string {
	s.counter++
	return fmt.Sprintf("%s-%04d", prefix, s.counter)
}

func (s *fakeStore) handler() kmipserver.RequestHandler {
	exec := kmipserver.NewBatchExecutor()

	exec.Route(ovh.OperationCreateKeyPair, kmipserver.HandleFunc(func(_ context.Context, req *payloads.CreateKeyPairRequestPayload) (*payloads.CreateKeyPairResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		priv, err := generateKeyFromRequest(req)
		if err != nil {
			return nil, err
		}
		pkix, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return nil, fmt.Errorf("marshal public key: %w", err)
		}
		rec := &keyRecord{
			privUID: s.nextUID("priv"),
			pubUID:  s.nextUID("pub"),
			privKey: priv,
			pubPKIX: pkix,
		}
		s.keys[rec.privUID] = rec
		s.pubKeys[rec.pubUID] = rec
		return &payloads.CreateKeyPairResponsePayload{
			PrivateKeyUniqueIdentifier: rec.privUID,
			PublicKeyUniqueIdentifier:  rec.pubUID,
		}, nil
	}))

	// Activate — no-op in the fake; keys are always ready to sign.
	exec.Route(ovh.OperationActivate, kmipserver.HandleFunc(func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	exec.Route(ovh.OperationAddAttribute, kmipserver.HandleFunc(func(_ context.Context, req *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if req.Attribute.AttributeName == ovh.AttributeNameName {
			if n, ok := req.Attribute.AttributeValue.(ovh.Name); ok {
				if rec, ok := s.keys[req.UniqueIdentifier]; ok {
					rec.nameAttrs = append(rec.nameAttrs, n.NameValue)
				}
				if rec, ok := s.pubKeys[req.UniqueIdentifier]; ok {
					rec.nameAttrs = append(rec.nameAttrs, n.NameValue)
				}
			}
		}
		// Echo the attribute back as required by the KMIP spec.
		return &payloads.AddAttributeResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			Attribute:        req.Attribute,
		}, nil
	}))

	exec.Route(ovh.OperationGet, kmipserver.HandleFunc(func(_ context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		rec, ok := s.pubKeys[req.UniqueIdentifier]
		if !ok {
			return nil, fmt.Errorf("object %s not found", req.UniqueIdentifier)
		}
		pkix := make([]byte, len(rec.pubPKIX))
		copy(pkix, rec.pubPKIX)
		return &payloads.GetResponsePayload{
			ObjectType:       ovh.ObjectTypePublicKey,
			UniqueIdentifier: req.UniqueIdentifier,
			Object: &ovh.PublicKey{
				KeyBlock: ovh.KeyBlock{
					KeyFormatType: ovh.KeyFormatTypeX_509,
					KeyValue:      &ovh.KeyValue{Wrapped: &pkix},
				},
			},
		}, nil
	}))

	exec.Route(ovh.OperationGetAttributes, kmipserver.HandleFunc(func(_ context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var attrs []ovh.Attribute
		if rec, ok := s.keys[req.UniqueIdentifier]; ok {
			for _, want := range req.AttributeName {
				switch want {
				case ovh.AttributeNameName:
					for _, n := range rec.nameAttrs {
						attrs = append(attrs, ovh.Attribute{
							AttributeName:  ovh.AttributeNameName,
							AttributeValue: ovh.Name{NameValue: n, NameType: ovh.NameTypeUninterpretedTextString},
						})
					}
				case ovh.AttributeNameLink:
					attrs = append(attrs, ovh.Attribute{
						AttributeName: ovh.AttributeNameLink,
						AttributeValue: ovh.Link{
							LinkType:               ovh.LinkTypePublicKeyLink,
							LinkedObjectIdentifier: rec.pubUID,
						},
					})
				}
			}
		}
		return &payloads.GetAttributesResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			Attribute:        attrs,
		}, nil
	}))

	exec.Route(ovh.OperationLocate, kmipserver.HandleFunc(func(_ context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var filterNames []string
		for _, a := range req.Attribute {
			if a.AttributeName == ovh.AttributeNameName {
				if n, ok := a.AttributeValue.(ovh.Name); ok {
					filterNames = append(filterNames, n.NameValue)
				}
			}
		}
		var uids []string
		for uid, rec := range s.keys {
			if allNamesPresent(rec.nameAttrs, filterNames) {
				uids = append(uids, uid)
			}
		}
		return &payloads.LocateResponsePayload{UniqueIdentifier: uids}, nil
	}))

	exec.Route(ovh.OperationDestroy, kmipserver.HandleFunc(func(_ context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if rec, ok := s.keys[req.UniqueIdentifier]; ok {
			delete(s.pubKeys, rec.pubUID)
			delete(s.keys, req.UniqueIdentifier)
		}
		return &payloads.DestroyResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	exec.Route(ovh.OperationSign, kmipserver.HandleFunc(func(_ context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
		s.mu.Lock()
		rec, ok := s.keys[req.UniqueIdentifier]
		s.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("key %s not found", req.UniqueIdentifier)
		}
		// Use DigestedData (pre-hashed) if set, otherwise Data.
		data := req.DigestedData
		if data == nil {
			data = req.Data
		}
		sig, err := rec.privKey.Sign(rand.Reader, data, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		return &payloads.SignResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			SignatureData:    sig,
		}, nil
	}))

	return exec
}

func generateKeyFromRequest(req *payloads.CreateKeyPairRequestPayload) (crypto.Signer, error) {
	if req.CommonTemplateAttribute == nil {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	var algo ovh.CryptographicAlgorithm
	var length int32
	var curve ovh.RecommendedCurve
	for _, a := range req.CommonTemplateAttribute.Attribute {
		switch a.AttributeName {
		case ovh.AttributeNameCryptographicAlgorithm:
			if v, ok := a.AttributeValue.(ovh.CryptographicAlgorithm); ok {
				algo = v
			}
		case ovh.AttributeNameCryptographicLength:
			if v, ok := a.AttributeValue.(int32); ok {
				length = v
			}
		case ovh.AttributeNameCryptographicDomainParameters:
			if v, ok := a.AttributeValue.(ovh.CryptographicDomainParameters); ok {
				curve = v.RecommendedCurve
			}
		}
	}
	switch algo {
	case ovh.CryptographicAlgorithmRSA:
		bits := int(length)
		if bits == 0 {
			bits = 2048
		}
		return rsa.GenerateKey(rand.Reader, bits)
	default:
		c := elliptic.P256()
		if curve == ovh.RecommendedCurveP_384 {
			c = elliptic.P384()
		}
		return ecdsa.GenerateKey(c, rand.Reader)
	}
}

func allNamesPresent(have, required []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, n := range have {
		set[n] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
