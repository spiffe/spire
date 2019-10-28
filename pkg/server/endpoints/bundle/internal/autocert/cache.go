// Copyright (c) 2016 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package autocert

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ErrCacheMiss is returned when a certificate is not found in cache.
var ErrCacheMiss = errors.New("acme/autocert: certificate cache miss")

// Cache is used by Manager to store and retrieve previously obtained certificates
// and other account data as opaque blobs.
//
// Cache implementations should not rely on the key naming pattern. Keys can
// include any printable ASCII characters, except the following: \/:*?"<>|
type Cache interface {
	// Get returns a certificate data for the specified key.
	// If there's no such key, Get returns ErrCacheMiss.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores the data in the cache under the specified key.
	// Underlying implementations may use any data storage format,
	// as long as the reverse operation, Get, results in the original data.
	Put(ctx context.Context, key string, data []byte) error

	// Delete removes a certificate data from the cache under the specified key.
	// If there's no such key in the cache, Delete returns nil.
	Delete(ctx context.Context, key string) error
}

// DirCache implements Cache using a directory on the local filesystem.
// If the directory does not exist, it will be created with 0700 permissions.
type DirCache string

// Get reads a certificate data from the specified file name.
func (d DirCache) Get(ctx context.Context, name string) ([]byte, error) {
	name = filepath.Join(string(d), name)
	var (
		data []byte
		err  error
		done = make(chan struct{})
	)
	go func() {
		data, err = ioutil.ReadFile(name)
		close(done)
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}
	if os.IsNotExist(err) {
		return nil, ErrCacheMiss
	}
	return data, err
}

// Put writes the certificate data to the specified file name.
// The file will be created with 0600 permissions.
func (d DirCache) Put(ctx context.Context, name string, data []byte) error {
	if err := os.MkdirAll(string(d), 0700); err != nil {
		return err
	}

	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		var tmp string
		if tmp, err = d.writeTempFile(name, data); err != nil {
			return
		}
		defer os.Remove(tmp)
		select {
		case <-ctx.Done():
			// Don't overwrite the file if the context was canceled.
		default:
			newName := filepath.Join(string(d), name)
			err = os.Rename(tmp, newName)
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	return err
}

// Delete removes the specified file name.
func (d DirCache) Delete(ctx context.Context, name string) error {
	name = filepath.Join(string(d), name)
	var (
		err  error
		done = make(chan struct{})
	)
	go func() {
		err = os.Remove(name)
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// writeTempFile writes b to a temporary file, closes the file and returns its path.
func (d DirCache) writeTempFile(prefix string, b []byte) (name string, reterr error) {
	// TempFile uses 0600 permissions
	f, err := ioutil.TempFile(string(d), prefix)
	if err != nil {
		return "", err
	}
	defer func() {
		if reterr != nil {
			os.Remove(f.Name())
		}
	}()
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}
