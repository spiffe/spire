package grpcutil

import (
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GRPCDialerConfig struct {
	// Log is used to log errors when used in non-blocking mode.
	Log   logrus.FieldLogger
	Creds credentials.TransportCredentials
	Opts  []grpc.DialOption
}

type Dialer interface {
	Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error)
}

type grpcDialer struct {
	log   logrus.FieldLogger
	creds credentials.TransportCredentials
	opts  []grpc.DialOption
}

func NewGRPCDialer(c GRPCDialerConfig) Dialer {
	return &grpcDialer{
		log:   c.Log,
		creds: c.Creds,
		opts:  append([]grpc.DialOption{}, c.Opts...),
	}
}

// Dial dials the given address, using TLS credentials, and logs information about connection
// errors.
func (d *grpcDialer) Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error) {
	if d.creds == nil {
		return nil, errors.New("credentials are required")
	}

	dialer := func(address string, timeout time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		conn, err := (&net.Dialer{}).DialContext(ctx, addr.Network(), addr.String())
		if err != nil {
			d.log.Error(err)
			return nil, err
		}

		conn, _, err = d.creds.ClientHandshake(ctx, address, conn)
		if err != nil {
			d.log.Error(err)
			return nil, err
		}

		return conn, nil
	}

	opts := append(d.opts,
		grpc.FailOnNonTempDialError(true),
		grpc.WithDialer(dialer),
		grpc.WithInsecure(), // we want to handle TLS by ourselves
	)
	return grpc.DialContext(ctx, addr.String(), opts...)
}
