// The following source code has been taken, with minor modification, from the
// gRPC codebase. We'd rather use their dialer, which supports HTTP-CONNECT
// proxies, but need richer error logging on handshake failure.

/*
 *
 * Copyright 2017 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package grpcutil

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const grpcUA = "grpc-go/" + grpc.Version

func getProxyURL(ctx context.Context, address string) (*url.URL, error) {
	req := &http.Request{
		URL: &url.URL{
			Scheme: "https",
			Host:   address,
		},
	}
	url, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, err
	}
	if url == nil {
		return nil, nil
	}
	switch url.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %q", url.Scheme)
	}
	return url, nil
}

// To read a response from a net.Conn, http.ReadResponse() takes a bufio.Reader.
// It's possible that this reader reads more than what's need for the response and stores
// those bytes in the buffer.
// bufConn wraps the original net.Conn and the bufio.Reader to make sure we don't lose the
// bytes in the buffer.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func doHTTPConnectHandshake(ctx context.Context, conn net.Conn, addr string) (_ net.Conn, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: addr},
		Header: map[string][]string{"User-Agent": {grpcUA}},
	})

	req = req.WithContext(ctx)
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("failed to write the HTTP request: %v", err)
	}

	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		return nil, fmt.Errorf("reading server HTTP response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, fmt.Errorf("failed to do connect handshake, status code: %s", resp.Status)
		}
		return nil, fmt.Errorf("failed to do connect handshake, response: %q", dump)
	}

	return &bufConn{Conn: conn, r: r}, nil
}

// proxyDial dials to a proxy and does an HTTP CONNECT handshake if proxying is
// enabled. Otherwise, it just does a regular TCP dial. It is based on the
// newProxyDialer wrapper implementation from the gRPC codebase.
func proxyDial(ctx context.Context, log logrus.StdLogger, addr string) (conn net.Conn, err error) {
	proxyURL, err := getProxyURL(ctx, addr)
	if err != nil {
		log.Printf("Failed to obtain proxy url for address %s: %v", addr, err)
		return nil, err
	}

	if proxyURL == nil {
		// no proxy; dial the address directly
		return new(net.Dialer).DialContext(ctx, "tcp", addr)
	}

	// Dial the proxy
	log.Printf("Proxying via %s to reach %s", proxyURL.String(), addr)
	conn, err = new(net.Dialer).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}

	// if the proxy is over HTTPS, wrap the connection in a TLS connection
	// before doing the HTTP CONNECT handshake.
	if proxyURL.Scheme == "https" {
		conn = tls.Client(conn, &tls.Config{
			ServerName: proxyURL.Hostname(),
		})
	}

	// Do the HTTP-CONNECT handshake. If unsuccessful, conn is closed.
	return doHTTPConnectHandshake(ctx, conn, addr)
}
