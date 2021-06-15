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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/stretchr/testify/require"
)

const (
	keyRSA       = "testdata/key-pkcs8-rsa.pem"
	certSingle   = "testdata/good-leaf-only.pem"
	keyECDSA     = "testdata/key-pkcs8-ecdsa.pem"
	certMultiple = "testdata/good-leaf-and-intermediate.pem"
)

func TestSvidWatcher(t *testing.T) {
	dir, err := ioutil.TempDir("", "svid-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewSVIDWatcher(SVIDWatcherConfig{
		Ctx:            ctx,
		Log:            plugin.NullLogger(),
		WebhookCertDir: dir,
	})

	w := x509Watcher{
		s:      watcher,
		svidCh: make(chan *x509svid.SVID, 1),
	}

	tests := []struct {
		name      string
		keyPath   string
		certsPath string
	}{
		{
			name:      "Single certificate and key",
			keyPath:   keyRSA,
			certsPath: certSingle,
		},
		{
			name:      "Multiple certificates and key",
			keyPath:   keyECDSA,
			certsPath: certMultiple,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			svid, err := x509svid.Load(test.certsPath, test.keyPath)
			require.NoError(t, err)

			w.OnX509ContextUpdate(&workloadapi.X509Context{
				SVIDs: []*x509svid.SVID{svid},
			})

			// Wait until response is processed
			select {
			case svid := <-w.svidCh:
				err := w.s.dumpBundles(svid)
				require.NoError(t, err)
			case <-ctx.Done():
				require.NoError(t, ctx.Err())
			case <-time.After(trustBundleTimeout):
				require.FailNow(t, "timed out waiting for trust bundle")
			}

			actualSvid, err := x509svid.Load(filepath.Join(dir, certsFileName), filepath.Join(dir, keyFileName))
			require.NoError(t, err)
			require.Equal(t, svid, actualSvid)
		})
	}
}
