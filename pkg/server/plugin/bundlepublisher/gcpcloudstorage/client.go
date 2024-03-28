package gcpcloudstorage

import (
	"context"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

type gcsService interface {
	Bucket(name string) *storage.BucketHandle
	Close() error
}

func newGCSClient(ctx context.Context, opts ...option.ClientOption) (gcsService, error) {
	return storage.NewClient(ctx, opts...)
}

func newStorageWriter(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser {
	return o.NewWriter(ctx)
}
