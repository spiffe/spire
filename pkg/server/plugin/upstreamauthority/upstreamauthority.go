package upstreamauthority

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/proto/spire/common"
)

type UpstreamAuthority interface {
	catalog.PluginInfo

	// MintX509CA sends a CSR to the upstream authority for minting, using the
	// preferred TTL. The preferred TTL is advisory only. Upstream Authorities
	// may choose a different value.  The function returns the newly minted CA,
	// the most recent set of upstream X.509 authorities, and a stream for
	// streaming upstream X.509 authority updates. The returned stream MUST be
	// closed when the caller is no longer interested in updates. If the
	// upstream authority does not support streaming updates, the stream will
	// return io.EOF when called.
	MintX509CA(ctx context.Context, csr []byte, preferredTTL time.Duration) (x509CA []*x509.Certificate, upstreamX509Authorities []*x509certificate.X509Authority, stream UpstreamX509AuthorityStream, err error)

	// PublishJWTKey publishes the given JWT key with the upstream authority.
	// Support for this method is optional. Implementations that do not support
	// publishing JWT keys upstream return NotImplemented.
	// The function returns the latest set of upstream JWT authorities and a
	// stream for streaming upstream JWT authority updates. The returned stream
	// MUST be closed when the caller is no longer interested in updates. If
	// the upstream authority does not support streaming updates, the stream
	// will return io.EOF when called.
	PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) (jwtAuthorities []*common.PublicKey, stream UpstreamJWTAuthorityStream, err error)

	// SubscribeToLocalBundle can be used to sync the local trust bundle with
	// the upstream trust bundle.
	// Support for this method is optional but strongly recommended.
	// The function returns the latest set of upstream authorities and a
	// stream for streaming upstream authority updates. The returned stream
	// MUST be closed when the caller is no longer interested in updates. If
	// the upstream authority does not support streaming updates, the stream
	// will return io.EOF when called.
	SubscribeToLocalBundle(ctx context.Context) (x509CAs []*x509certificate.X509Authority, jwtAuthorities []*common.PublicKey, stream LocalBundleUpdateStream, err error)
}

type UpstreamX509AuthorityStream interface {
	// RecvUpstreamX509Authorities returns the latest set of upstream X.509
	// authorities. The call blocks until the update is received, the Close()
	// method is called, or the context originally passed into MintX509CA is
	// canceled. If the function returns an error, no more updates will be
	// available over the stream.
	RecvUpstreamX509Authorities() ([]*x509certificate.X509Authority, error)

	// Close() closes the stream. It MUST be called by callers of MintX509CA
	// when they are done with the stream.
	Close()
}

type UpstreamJWTAuthorityStream interface {
	// RecvUpstreamJWTAuthorities returns the latest set of upstream JWT
	// authorities. The call blocks until the update is received, the Close()
	// method is called, or the context originally passed into PublishJWTKey is
	// canceled. If the function returns an error, no more updates will be
	// available over the stream.
	RecvUpstreamJWTAuthorities() ([]*common.PublicKey, error)

	// Close() closes the stream. It MUST be called by callers of PublishJWTKey
	// when they are done with the stream.
	Close()
}

type LocalBundleUpdateStream interface {
	// RecvLocalBundleUpdate returns the latest local trust domain bundle
	// The call blocks until the update is received, the Close()
	// method is called, or the context originally passed into GetTrustBundle is
	// canceled. If the function returns an error, no more updates will be
	// available over the stream.
	RecvLocalBundleUpdate() ([]*x509certificate.X509Authority, []*common.PublicKey, error)

	// Close() closes the stream. It MUST be called by callers of GetTrustBundle
	// when they are done with the stream.
	Close()
}
