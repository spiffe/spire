package gcsbundle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"github.com/spiffe/spire/proto/spire/server/notifier"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
)

func TestRequiresIdentityProvider(t *testing.T) {
	_, err := catalog.LoadBuiltInPlugin(context.Background(), catalog.BuiltInPlugin{
		Plugin: BuiltIn(),
	})
	spiretest.RequireGRPCStatusContains(t, err, codes.Unknown, "IdentityProvider host service is required")
}

func TestConfigure(t *testing.T) {
	testCases := []struct {
		name   string
		config string
		code   codes.Code
		desc   string
	}{
		{
			name: "malformed",
			config: `
				MALFORMED
			`,
			code: codes.InvalidArgument,
			desc: "unable to decode configuration",
		},
		{
			name: "missing bucket",
			config: `
				object_path = "bundle.pem"
			`,
			code: codes.InvalidArgument,
			desc: "bucket must be set",
		},
		{
			name: "missing object path",
			config: `
				bucket = "the-bucket"
			`,
			code: codes.InvalidArgument,
			desc: "object_path must be set",
		},
		{
			name: "success without service account file",
			config: `
				bucket = "the-bucket"
				object_path = "bundle.pem"
			`,
			code: codes.OK,
		},
		{
			name: "success with service account file",
			config: `
				bucket = "the-bucket"
				object_path = "bundle.pem"
				service_account_file = "the-service-account-file"
			`,
			code: codes.OK,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			idp := fakeidentityprovider.New()

			raw := New()
			var plugin notifier.Plugin
			pluginDone := spiretest.LoadPlugin(t, builtIn(raw), &plugin,
				spiretest.HostService(hostservices.IdentityProviderHostServiceServer(idp)))
			defer pluginDone()

			resp, err := plugin.Configure(context.Background(), &spi.ConfigureRequest{Configuration: tt.config})
			if tt.code != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.desc)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestGetPluginInfo(t *testing.T) {
	resp, err := New().GetPluginInfo(context.Background(), &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, &spi.GetPluginInfoResponse{}, resp)
}

func TestNotify(t *testing.T) {
	testUpdateBundleObject(t, func(plugin notifier.Plugin) error {
		_, err := plugin.Notify(context.Background(), &notifier.NotifyRequest{
			Event: &notifier.NotifyRequest_BundleUpdated{
				BundleUpdated: &notifier.BundleUpdated{},
			},
		})
		return err
	})
}

func TestNotifyAndAdvise(t *testing.T) {
	testUpdateBundleObject(t, func(plugin notifier.Plugin) error {
		_, err := plugin.NotifyAndAdvise(context.Background(), &notifier.NotifyAndAdviseRequest{
			Event: &notifier.NotifyAndAdviseRequest_BundleLoaded{
				BundleLoaded: &notifier.BundleLoaded{},
			},
		})
		return err
	})
}

func testUpdateBundleObject(t *testing.T, notify func(plugin notifier.Plugin) error) {
	bundle1 := &common.Bundle{RootCas: []*common.Certificate{{DerBytes: []byte("1")}}}
	bundle2 := &common.Bundle{RootCas: []*common.Certificate{{DerBytes: []byte("2")}}}

	for _, tt := range []struct {
		name                  string
		bundles               []*common.Bundle
		skipConfigure         bool
		configureBucketClient func(client *fakeBucketClient) error
		code                  codes.Code
		desc                  string
		expectedBundle        *common.Bundle
	}{
		{
			name:          "not configured",
			skipConfigure: true,
			code:          codes.FailedPrecondition,
			desc:          "not configured",
		},
		{
			name: "failed to create bucket client",
			configureBucketClient: func(*fakeBucketClient) error {
				return errors.New("ohno")
			},
			code: codes.Unknown,
			desc: "unable to instantiate bucket client: ohno",
		},
		{
			name: "failed to get object generation",
			configureBucketClient: func(client *fakeBucketClient) error {
				client.SetGetObjectGenerationError(errors.New("ohno"))
				return nil
			},
			code: codes.Unknown,
			desc: "unable to get bundle object the-bucket/bundle.pem: ohno",
		},
		{
			name: "failed to fetch bundle from identity provider",
			code: codes.Unknown,
			desc: "unable to fetch bundle from SPIRE server: no bundle",
		},
		{
			name:    "failed to put object",
			bundles: []*common.Bundle{bundle1},
			configureBucketClient: func(client *fakeBucketClient) error {
				client.AppendPutObjectError(errors.New("ohno"))
				return nil
			},
			code: codes.Unknown,
			desc: "unable to update bundle object the-bucket/bundle.pem: ohno",
		},
		{
			name:           "success",
			bundles:        []*common.Bundle{bundle1},
			code:           codes.OK,
			expectedBundle: bundle1,
		},
		{
			name:    "success with conflict resolution",
			bundles: []*common.Bundle{bundle1, bundle2},
			configureBucketClient: func(client *fakeBucketClient) error {
				client.AppendPutObjectError(&googleapi.Error{
					Code: http.StatusPreconditionFailed,
					Errors: []googleapi.ErrorItem{
						{Reason: "conditionNotMet"},
					},
				})
				return nil
			},
			code:           codes.OK,
			expectedBundle: bundle2,
		},
		{
			name:    "failed with unrelated precondition failed error",
			bundles: []*common.Bundle{bundle1, bundle2},
			configureBucketClient: func(client *fakeBucketClient) error {
				client.AppendPutObjectError(&googleapi.Error{
					Code: http.StatusPreconditionFailed,
					Body: "ohno",
				})
				return nil
			},
			code: codes.Unknown,
			desc: "unable to update bundle object the-bucket/bundle.pem: googleapi: got HTTP response code 412 with body: ohno",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a raw instance so we can hook the bucket client creation,
			// possibly overriding with a test specific hook.
			client := newFakeBucketClient()
			raw := New()
			raw.hooks.newBucketClient = func(ctx context.Context, serviceAccountFile string) (bucketClient, error) {
				if serviceAccountFile != "the-service-account-file" {
					return nil, fmt.Errorf("unexpected service account file %q", serviceAccountFile)
				}
				if tt.configureBucketClient != nil {
					if err := tt.configureBucketClient(client); err != nil {
						return nil, err
					}
				}
				return client, nil
			}

			idp := fakeidentityprovider.New()
			for _, bundle := range tt.bundles {
				idp.AppendBundle(bundle)
			}

			// Load the instance as a plugin
			var plugin notifier.Plugin
			pluginDone := spiretest.LoadPlugin(t, builtIn(raw), &plugin,
				spiretest.HostService(hostservices.IdentityProviderHostServiceServer(idp)))
			defer pluginDone()

			if !tt.skipConfigure {
				_, err := plugin.Configure(context.Background(), &spi.ConfigureRequest{
					Configuration: `
				bucket = "the-bucket"
				object_path = "bundle.pem"
				service_account_file = "the-service-account-file"
			`,
				})
				require.NoError(t, err)
			}

			err := notify(plugin)
			if tt.code != codes.OK {
				spiretest.RequireGRPCStatus(t, err, tt.code, tt.desc)
				return
			}
			require.NoError(t, err)
			require.Equal(t, bundleData(tt.expectedBundle), client.GetBundleData())
		})
	}
}

type fakeBucketClient struct {
	mu                     sync.Mutex
	data                   []byte
	getObjectGenerationErr error
	putObjectErrs          []error
	closed                 bool
}

func newFakeBucketClient() *fakeBucketClient {
	return &fakeBucketClient{}
}

func (c *fakeBucketClient) GetObjectGeneration(ctx context.Context, bucket, object string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return 99, c.getObjectGenerationErr
}

func (c *fakeBucketClient) PutObject(ctx context.Context, bucket, object string, data []byte, generation int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if bucket != "the-bucket" {
		return fmt.Errorf("expected bucket %q; got %q", "the-bucket", bucket)
	}
	if object != "bundle.pem" {
		return fmt.Errorf("expected object %q; got %q", "bundle.pem", object)
	}
	if generation != 99 {
		return fmt.Errorf("expected generation 99; got %d", generation)
	}

	if len(c.putObjectErrs) > 0 {
		err := c.putObjectErrs[0]
		c.putObjectErrs = c.putObjectErrs[1:]
		return err
	}

	c.data = append([]byte(nil), data...)
	return nil
}

func (c *fakeBucketClient) SetGetObjectGenerationError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getObjectGenerationErr = err
}

func (c *fakeBucketClient) AppendPutObjectError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putObjectErrs = append(c.putObjectErrs, err)
}

func (c *fakeBucketClient) GetBundleData() []byte {
	c.mu.Lock()
	data := append([]byte(nil), c.data...)
	c.mu.Unlock()
	return data
}

func (c *fakeBucketClient) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeBucketClient) Closed() bool {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	return closed
}
