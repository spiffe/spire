package minios3

import (
	"context"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
)

type minioService interface {
	PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64,
		opts minio.PutObjectOptions,
	) (info minio.UploadInfo, err error)
}

func newMinioClient(c Config) (minioService, error) {
	// Initialize minio client object.
	minioClient, err := minio.New(c.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(c.AccessKeyID, c.SecretAccessKey, ""),
		Secure: true,
	})
	if err != nil {
		return nil, err
	}
	return minioClient, nil
}
