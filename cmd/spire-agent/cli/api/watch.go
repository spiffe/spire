package api

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/util"
)

type WatchCLI struct {
	config *common.ConfigOS
}

func (WatchCLI) Synopsis() string {
	return "Attaches to the Workload API and prints updates as they're received"
}

func (w WatchCLI) Help() string {
	err := w.parseConfig([]string{"-h"})
	return err.Error()
}

func (w *WatchCLI) Run(args []string) int {
	err := w.parseConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	addr, err := w.config.GetAddr()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	clientOption, err := util.GetWorkloadAPIClientOption(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := workloadapi.WatchX509Context(ctx, newWatcher(), clientOption); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}

func (w *WatchCLI) parseConfig(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	c := &common.ConfigOS{}
	c.AddOSFlags(fs)

	w.config = c
	return fs.Parse(args)
}

type watcher struct {
	updateTime time.Time
}

func newWatcher() *watcher {
	return &watcher{
		updateTime: time.Now(),
	}
}

func (w *watcher) OnX509ContextUpdate(x509Context *workloadapi.X509Context) {
	svids := make([]*X509SVID, 0, len(x509Context.SVIDs))
	for _, svid := range x509Context.SVIDs {
		var bundle []*x509.Certificate
		federatedBundles := make(map[string][]*x509.Certificate)

		for _, candidateBundle := range x509Context.Bundles.Bundles() {
			if candidateBundle.TrustDomain() == svid.ID.TrustDomain() {
				bundle = candidateBundle.X509Authorities()
			} else {
				federatedBundles[candidateBundle.TrustDomain().String()] = candidateBundle.X509Authorities()
			}
		}

		svids = append(svids, &X509SVID{
			SPIFFEID:         svid.ID.String(),
			Certificates:     svid.Certificates,
			PrivateKey:       svid.PrivateKey,
			Bundle:           bundle,
			FederatedBundles: federatedBundles,
		})
	}
	printX509SVIDResponse(commoncli.DefaultEnv, svids, time.Since(w.updateTime))
	w.updateTime = time.Now()
}

func (w *watcher) OnX509ContextWatchError(err error) {
	fmt.Fprintln(os.Stderr, err)
}
