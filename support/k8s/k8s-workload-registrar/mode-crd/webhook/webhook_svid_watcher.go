/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	certsFileMode      = os.FileMode(0644)
	keyFileMode        = os.FileMode(0600)
	certsFileName      = "tls.crt"
	keyFileName        = "tls.key"
	trustBundleTimeout = 3 * time.Minute
)

type SVIDWatcherConfig struct {
	AgentSocketPath string
	Ctx             context.Context
	Log             logrus.FieldLogger
	SpiffeID        *types.SPIFFEID
	WebhookCertDir  string
}

type SVIDWatcher struct {
	c SVIDWatcherConfig
}

func NewSVIDWatcher(config SVIDWatcherConfig) *SVIDWatcher {
	return &SVIDWatcher{
		c: config,
	}
}

// startWatcher sets up the process to download and rotate the webhook certificates
func (s *SVIDWatcher) Start() error {
	err := os.MkdirAll(s.c.WebhookCertDir, 0700)
	if err != nil {
		return err
	}

	client, err := workloadapi.New(s.c.Ctx, workloadapi.WithAddr("unix://"+s.c.AgentSocketPath))
	if err != nil {
		return fmt.Errorf("unable to create workload API client: %w", err)
	}

	w := &x509Watcher{
		s:      s,
		svidCh: make(chan *x509svid.SVID),
	}

	go func() {
		defer client.Close()
		err := client.WatchX509Context(s.c.Ctx, w)
		if err != nil && status.Code(err) != codes.Canceled {
			s.c.Log.Fatalf("Error watching X.509 context: %w", err)
		}
	}()

	// Wait for the initial trust bundle to arrive. We can't start the webhook without the certs in place.
	select {
	case svid := <-w.svidCh:
		s.c.Log.Info("Received initial trust bundle from SPIRE")
		if err := s.dumpBundles(svid); err != nil {
			return fmt.Errorf("error dumping bundles: %w", err)
		}
	case <-time.After(trustBundleTimeout):
		return fmt.Errorf("timed out waiting for trust bundle")
	}

	// Wait for updates to the trust bundle
	go func() {
		for {
			select {
			case svid := <-w.svidCh:
				if err := s.dumpBundles(svid); err != nil {
					s.c.Log.Fatalf("Error dumping bundles: %w", err)
				}
			case <-s.c.Ctx.Done():
				return
			}
		}
	}()

	return nil
}

// dumpBundles takes a X509SVIDResponse, representing a svid message from the Workload API
// and write the certs to disk
func (s *SVIDWatcher) dumpBundles(svid *x509svid.SVID) error {
	certsFile := path.Join(s.c.WebhookCertDir, certsFileName)
	keyFile := path.Join(s.c.WebhookCertDir, keyFileName)

	pemCerts, pemKey, err := svid.Marshal()
	if err != nil {
		return fmt.Errorf("unable to marshal X.509 SVID: %w", err)
	}

	if err := ioutil.WriteFile(certsFile, pemCerts, certsFileMode); err != nil {
		return fmt.Errorf("error writing certs file: %w", err)
	}

	if err := ioutil.WriteFile(keyFile, pemKey, keyFileMode); err != nil {
		return fmt.Errorf("error writing key file: %w", err)
	}

	return nil
}

// x509Watcher is a sample implementation of the workloadapi.X509ContextWatcher interface
type x509Watcher struct {
	s      *SVIDWatcher
	svidCh chan *x509svid.SVID
}

// OnX509ContextUpdate is run every time an SVID is updated
func (w *x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	var SVID *x509svid.SVID
	if w.s.c.SpiffeID == nil {
		SVID = c.DefaultSVID()
	} else {
		for _, svid := range c.SVIDs {
			if svid.ID.TrustDomain().String() == w.s.c.SpiffeID.GetTrustDomain() &&
				svid.ID.Path() == w.s.c.SpiffeID.GetPath() {
				SVID = svid
			}
		}
	}
	if SVID != nil {
		w.svidCh <- SVID
		w.s.c.Log.WithFields(logrus.Fields{
			"id": SVID.ID.String(),
		}).Info("SVID updated")
	} else {
		w.s.c.Log.Error("Unable to find SVID")
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (w *x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled && status.Code(err) != codes.PermissionDenied {
		w.s.c.Log.Debugf("OnX509ContextWatchError error: %v", err)
	}
}

func errorFromStatus(s *types.Status) error {
	if s == nil {
		return errors.New("result status is unexpectedly nil")
	}
	return status.Error(codes.Code(s.Code), s.Message)
}
