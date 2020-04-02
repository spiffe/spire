package fakeupstreamauthority

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	x509RootKey = testkey.MustEC256()
	x509IntKey  = testkey.MustEC256()
)

type Config struct {
	TrustDomain                 string
	UseIntermediate             bool
	DisallowPublishJWTKey       bool
	MutateMintX509CAResponse    func(*upstreamauthority.MintX509CAResponse)
	MutatePublishJWTKeyResponse func(*upstreamauthority.PublishJWTKeyResponse)
}

type UpstreamAuthority struct {
	t      *testing.T
	config Config

	x509CAMtx        sync.RWMutex
	x509CA           *x509svid.UpstreamCA
	x509CASN         int64
	x509Root         *x509.Certificate
	x509Intermediate *x509.Certificate
	x509Roots        []*x509.Certificate

	jwtKeysMtx sync.RWMutex
	jwtKeys    []*common.PublicKey

	streamsMtx           sync.Mutex
	mintX509CAStreams    map[chan struct{}]struct{}
	publishJWTKeyStreams map[chan struct{}]struct{}
}

func New(t *testing.T, config Config) *UpstreamAuthority {
	ua := &UpstreamAuthority{
		t:                    t,
		config:               config,
		mintX509CAStreams:    make(map[chan struct{}]struct{}),
		publishJWTKeyStreams: make(map[chan struct{}]struct{}),
	}
	ua.RotateX509CA()
	return ua
}

func (ua *UpstreamAuthority) MintX509CA(request *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	streamCh := ua.newMintX509CAStream()
	defer ua.removeMintX509CAStream(streamCh)

	ctx := stream.Context()

	x509CAChain, err := ua.mintX509CA(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return err
	}

	if err := ua.sendMintX509CAResponse(stream, &upstreamauthority.MintX509CAResponse{
		X509CaChain:       certsDER(x509CAChain),
		UpstreamX509Roots: certsDER(ua.X509Roots()),
	}); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-streamCh:
			if err := ua.sendMintX509CAResponse(stream, &upstreamauthority.MintX509CAResponse{
				UpstreamX509Roots: certsDER(ua.X509Roots()),
			}); err != nil {
				return err
			}
		}
	}
}

func (ua *UpstreamAuthority) PublishJWTKey(req *upstreamauthority.PublishJWTKeyRequest, stream upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	if ua.config.DisallowPublishJWTKey {
		return status.Error(codes.Unimplemented, "disallowed")
	}

	streamCh := ua.newPublishJWTKeyStream()
	defer ua.removePublishJWTKeyStream(streamCh)

	ctx := stream.Context()

	ua.AppendJWTKey(req.JwtKey)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-streamCh:
			if err := ua.sendPublishJWTKeyStream(stream, &upstreamauthority.PublishJWTKeyResponse{
				UpstreamJwtKeys: ua.JWTKeys(),
			}); err != nil {
				return err
			}
		}
	}
}

func (ua *UpstreamAuthority) RotateX509CA() {
	ua.x509CAMtx.Lock()
	defer ua.x509CAMtx.Unlock()

	var caCert *x509.Certificate
	var caKey crypto.Signer
	if ua.config.UseIntermediate {
		ua.createIntermediateCertificate()
		caCert = ua.x509Intermediate
		caKey = x509IntKey
	} else {
		ua.createRootCertificate()
		caCert = ua.x509Root
		caKey = x509RootKey
	}

	ua.x509CA = x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, caKey),
		ua.config.TrustDomain,
		x509svid.UpstreamCAOptions{})

	ua.TriggerX509RootsChanged()
}

func (ua *UpstreamAuthority) X509Root() *x509.Certificate {
	ua.x509CAMtx.RLock()
	defer ua.x509CAMtx.RUnlock()
	return ua.x509Root
}

func (ua *UpstreamAuthority) X509Roots() []*x509.Certificate {
	ua.x509CAMtx.RLock()
	defer ua.x509CAMtx.RUnlock()
	return ua.x509Roots
}

func (ua *UpstreamAuthority) X509Intermediate() *x509.Certificate {
	ua.x509CAMtx.RLock()
	defer ua.x509CAMtx.RUnlock()
	return ua.x509Intermediate
}

func (ua *UpstreamAuthority) JWTKeys() []*common.PublicKey {
	ua.jwtKeysMtx.RLock()
	defer ua.jwtKeysMtx.RUnlock()
	return ua.jwtKeys
}

func (ua *UpstreamAuthority) AppendJWTKey(jwtKey *common.PublicKey) {
	ua.jwtKeysMtx.Lock()
	defer ua.jwtKeysMtx.Unlock()
	ua.jwtKeys = append(ua.jwtKeys, jwtKey)
	ua.TriggerJWTKeysChanged()
}

func (ua *UpstreamAuthority) TriggerX509RootsChanged() {
	ua.streamsMtx.Lock()
	defer ua.streamsMtx.Unlock()
	for streamCh := range ua.mintX509CAStreams {
		select {
		case streamCh <- struct{}{}:
		default:
		}
	}
}

func (ua *UpstreamAuthority) TriggerJWTKeysChanged() {
	ua.streamsMtx.Lock()
	defer ua.streamsMtx.Unlock()
	for streamCh := range ua.publishJWTKeyStreams {
		select {
		case streamCh <- struct{}{}:
		default:
		}
	}
}

func (ua *UpstreamAuthority) newMintX509CAStream() chan struct{} {
	streamCh := make(chan struct{}, 1)
	ua.streamsMtx.Lock()
	ua.mintX509CAStreams[streamCh] = struct{}{}
	ua.streamsMtx.Unlock()
	return streamCh
}

func (ua *UpstreamAuthority) removeMintX509CAStream(streamCh chan struct{}) {
	ua.streamsMtx.Lock()
	delete(ua.mintX509CAStreams, streamCh)
	ua.streamsMtx.Unlock()
}

func (ua *UpstreamAuthority) mintX509CA(ctx context.Context, csr []byte, preferredTTL time.Duration) ([]*x509.Certificate, error) {
	ua.x509CAMtx.RLock()
	defer ua.x509CAMtx.RUnlock()

	caCert, err := ua.x509CA.SignCSR(ctx, csr, preferredTTL)
	if err != nil {
		return nil, err
	}
	x509CAChain := []*x509.Certificate{caCert}
	if ua.x509Intermediate != nil {
		x509CAChain = append(x509CAChain, ua.x509Intermediate)
	}
	return x509CAChain, nil
}

func (ua *UpstreamAuthority) sendMintX509CAResponse(stream upstreamauthority.UpstreamAuthority_MintX509CAServer, resp *upstreamauthority.MintX509CAResponse) error {
	if ua.config.MutateMintX509CAResponse != nil {
		ua.config.MutateMintX509CAResponse(resp)
	}
	return stream.Send(resp)
}

func (ua *UpstreamAuthority) newPublishJWTKeyStream() chan struct{} {
	streamCh := make(chan struct{}, 1)
	ua.streamsMtx.Lock()
	ua.publishJWTKeyStreams[streamCh] = struct{}{}
	ua.streamsMtx.Unlock()
	return streamCh
}

func (ua *UpstreamAuthority) removePublishJWTKeyStream(streamCh chan struct{}) {
	ua.streamsMtx.Lock()
	delete(ua.publishJWTKeyStreams, streamCh)
	ua.streamsMtx.Unlock()
}

func (ua *UpstreamAuthority) sendPublishJWTKeyStream(stream upstreamauthority.UpstreamAuthority_PublishJWTKeyServer, resp *upstreamauthority.PublishJWTKeyResponse) error {
	if ua.config.MutatePublishJWTKeyResponse != nil {
		ua.config.MutatePublishJWTKeyResponse(resp)
	}
	return stream.Send(resp)
}

func (ua *UpstreamAuthority) createRootCertificate() {
	template := createCATemplate("FAKEUPSTREAMAUTHORITY-ROOT", ua.nextX509CASN())
	ua.x509Root = createCertificate(ua.t, template, template, &x509RootKey.PublicKey, x509RootKey)
	ua.x509Roots = append(ua.x509Roots, ua.x509Root)
}

func (ua *UpstreamAuthority) createIntermediateCertificate() {
	if ua.x509Root == nil {
		ua.createRootCertificate()
	}
	template := createCATemplate("FAKEUPSTREAMAUTHORITY-INT", ua.nextX509CASN())
	ua.x509Intermediate = createCertificate(ua.t, template, ua.x509Root, &x509IntKey.PublicKey, x509RootKey)
}

func (ua *UpstreamAuthority) nextX509CASN() int64 {
	ua.x509CASN++
	return ua.x509CASN
}

func createCATemplate(cn string, sn int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(sn),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.PrivateKey) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	require.NoError(t, err, "unable to sign certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "unable to parse certificate")
	return cert
}

func certsDER(certs []*x509.Certificate) [][]byte {
	var out [][]byte
	for _, cert := range certs {
		out = append(out, cert.Raw)
	}
	return out
}
