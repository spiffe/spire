package awss3

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		configureRequest *configv1.ConfigureRequest
		newClientErr     error
		expectCode       codes.Code
		expectMsg        string
		config           *Config
		expectAWSConfig  *aws.Config
	}{
		{
			name: "success",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				Bucket:          "bucket",
				ObjectKey:       "object-key",
				Format:          "spiffe",
			},
		},
		{
			name: "no region",
			config: &Config{
				Bucket:    "bucket",
				ObjectKey: "object-key",
				Format:    "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the region",
		},

		{
			name: "no bucket",
			config: &Config{
				Region:    "region",
				ObjectKey: "object-key",
				Format:    "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bucket name",
		},
		{
			name: "no object key",
			config: &Config{
				Region: "region",
				Bucket: "bucket",
				Format: "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the object key",
		},
		{
			name: "no bundle format",
			config: &Config{
				Region:    "region",
				ObjectKey: "object-key",
				Bucket:    "bucket",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bundle format",
		},
		{
			name: "client error",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				Bucket:          "bucket",
				ObjectKey:       "object-key",
				Format:          "spiffe",
			},
			expectCode:   codes.Internal,
			expectMsg:    "failed to create client: client creation error",
			newClientErr: errors.New("client creation error"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(awsConfig aws.Config) (simpleStorageService, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{
					awsConfig: awsConfig,
				}, nil
			}
			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			// Check that the plugin has the expected configuration.
			tt.config.bundleFormat, err = bundleformat.FromString(tt.config.Format)
			require.NoError(t, err)
			require.Equal(t, tt.config, p.config)

			client, ok := p.s3Client.(*fakeClient)
			require.True(t, ok)

			// It's important to check that the configuration has been wired
			// up to the aws config, that needs to have the specified region
			// and credentials.
			require.Equal(t, tt.config.Region, client.awsConfig.Region)
			creds, err := client.awsConfig.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, tt.config.AccessKeyID, creds.AccessKeyID)
			require.Equal(t, tt.config.SecretAccessKey, creds.SecretAccessKey)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)

	for _, tt := range []struct {
		name string

		newClientErr error
		expectCode   codes.Code
		expectMsg    string
		config       *Config
		bundle       *types.Bundle
		putObjectErr error
	}{
		{
			name:   "success",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				Bucket:          "bucket",
				ObjectKey:       "object-key",
				Format:          "spiffe",
			},
		},
		{
			name:   "multiple times",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				Bucket:          "bucket",
				ObjectKey:       "object-key",
				Format:          "spiffe",
			},
		},
		{
			name:   "put object failure",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				Bucket:          "bucket",
				ObjectKey:       "object-key",
				Format:          "spiffe",
			},
			putObjectErr: errors.New("some error"),
			expectCode:   codes.Internal,
			expectMsg:    "failed to put object: some error",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name: "missing bundle",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				Bucket:          "bucket",
				ObjectKey:       "object-key",
				Format:          "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(awsConfig aws.Config) (simpleStorageService, error) {
				return &fakeClient{
					t:            t,
					expectBucket: aws.String(tt.config.Bucket),
					expectKey:    aws.String(tt.config.ObjectKey),
					putObjectErr: tt.putObjectErr,
				}, nil
			}
			p := newPlugin(newClient)

			if tt.config != nil {
				plugintest.Load(t, builtin(p), nil, options...)
				require.NoError(t, err)
			}

			resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestPublishMultiple(t *testing.T) {
	config := &Config{
		AccessKeyID:     "access-key-id",
		SecretAccessKey: "secret-access-key",
		Region:          "region",
		Bucket:          "bucket",
		ObjectKey:       "object-key",
		Format:          "spiffe",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	newClient := func(awsConfig aws.Config) (simpleStorageService, error) {
		return &fakeClient{
			t:            t,
			expectBucket: aws.String(config.Bucket),
			expectKey:    aws.String(config.ObjectKey),
		}, nil
	}
	p := newPlugin(newClient)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple put operations, and check that only a call to PutObject is
	// done when there is a modified bundle that was not successfully published
	// before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	client, ok := p.s3Client.(*fakeClient)
	require.True(t, ok)

	// Reset the putObjectCount counter.
	client.putObjectCount = 0
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.putObjectCount)

	// Call PublishBundle with the same bundle.
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the putObjectCount counter should be still 1.
	require.Equal(t, 1, client.putObjectCount)

	// Have a new bundle and call PublishBundle.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// PublishBundle was called with a different bundle, putObjectCount should
	// be incremented to be 2.
	require.Equal(t, 2, client.putObjectCount)

	// Simulate that calling to PutObject fails with an error.
	client.putObjectErr = errors.New("error calling PutObject")

	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	// Since there is no change in the bundle, PutObject should not be called
	// and there should be no error.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the putObjectCount counter should be still 2.
	require.Equal(t, 2, client.putObjectCount)

	// Have a new bundle and call PublishBundle. PutObject should be called this
	// time and return an error.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 3
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// Since the bundle could not be published, putObjectCount should be
	// still 2.
	require.Equal(t, 2, client.putObjectCount)

	// Clear the PutObject error and call PublishBundle.
	client.putObjectErr = nil
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})

	// No error should happen this time.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The putObjectCount counter should be incremented to 3, since the bundle
	// should have been published successfully.
	require.Equal(t, 3, client.putObjectCount)
}

type fakeClient struct {
	t *testing.T

	awsConfig      aws.Config
	putObjectErr   error
	expectBucket   *string
	expectKey      *string
	putObjectCount int
}

func (c *fakeClient) PutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if c.putObjectErr != nil {
		return nil, c.putObjectErr
	}

	require.Equal(c.t, c.expectBucket, params.Bucket, "bucket mismatch")
	require.Equal(c.t, c.expectKey, params.Key, "key mismatch")
	c.putObjectCount++
	return &s3.PutObjectOutput{}, nil
}

func getTestBundle(t *testing.T) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
}
