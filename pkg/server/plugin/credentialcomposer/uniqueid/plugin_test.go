package uniqueid_test

import (
	"context"
	"crypto/x509/pkix"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer/uniqueid"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
)

var (
	id1 = spiffeid.RequireFromString("spiffe://example.org/test1")
	id2 = spiffeid.RequireFromString("spiffe://example.org/test2")
	key = testkey.MustEC256()
	ctx = context.Background()
)

func TestPlugin(t *testing.T) {
	cc := new(credentialcomposer.V1)
	plugintest.Load(t, uniqueid.BuiltIn(), cc)

	t.Run("ComposeServerX509CA", func(t *testing.T) {
		t.Run("attributes unchanged", func(t *testing.T) {
			want := credentialcomposer.X509CAAttributes{}
			got, err := cc.ComposeServerX509CA(ctx, want)
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})
	})

	t.Run("ComposeServerX509SVID", func(t *testing.T) {
		t.Run("attributes unchanged", func(t *testing.T) {
			want := credentialcomposer.X509SVIDAttributes{}
			got, err := cc.ComposeServerX509SVID(ctx, want)
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})
	})

	t.Run("ComposeAgentX509SVID", func(t *testing.T) {
		t.Run("attributes unchanged", func(t *testing.T) {
			want := credentialcomposer.X509SVIDAttributes{}
			got, err := cc.ComposeAgentX509SVID(ctx, id1, key.Public(), want)
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})
	})

	t.Run("ComposeWorkloadX509SVID", func(t *testing.T) {
		t.Run("appended to subject without unique ID", func(t *testing.T) {
			want := credentialcomposer.X509SVIDAttributes{}

			got, err := cc.ComposeWorkloadX509SVID(ctx, id1, key.Public(), want)

			// The plugin should add the unique ID attribute
			want.Subject.ExtraNames = append(want.Subject.ExtraNames, x509svid.UniqueIDAttribute(id1))

			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})

		t.Run("replaced in subject with unique ID", func(t *testing.T) {
			want := credentialcomposer.X509SVIDAttributes{
				Subject: pkix.Name{
					ExtraNames: []pkix.AttributeTypeAndValue{
						x509svid.UniqueIDAttribute(id1),
					},
				},
			}

			got, err := cc.ComposeWorkloadX509SVID(ctx, id2, key.Public(), want)

			// The plugin should replace the unique ID attribute
			want.Subject.ExtraNames[0] = x509svid.UniqueIDAttribute(id2)

			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})
	})

	t.Run("ComposeWorkloadJWTSVID", func(t *testing.T) {
		t.Run("attributes unchanged", func(t *testing.T) {
			want := credentialcomposer.JWTSVIDAttributes{Claims: map[string]any{"sub": id1.String()}}
			got, err := cc.ComposeWorkloadJWTSVID(ctx, id1, want)
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})
	})
}
