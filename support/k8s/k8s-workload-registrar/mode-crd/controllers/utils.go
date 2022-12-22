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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func NewManager(leaderElection bool, leaderElectionResourceLock string, metricsBindAddr, webhookCertDir string, webhookPort int) (ctrl.Manager, error) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = spiffeidv1beta1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		LeaderElection:             leaderElection,
		LeaderElectionID:           "spire-k8s-registrar-leader-election",
		LeaderElectionResourceLock: leaderElectionResourceLock,
		MetricsBindAddress:         metricsBindAddr,
		Scheme:                     scheme,
		WebhookServer: &webhook.Server{
			Port:          webhookPort,
			CertDir:       webhookCertDir,
			TLSMinVersion: "1.2",
		},
	})
	if err != nil {
		return nil, err
	}

	return mgr, nil
}

// setOwnerRef sets the owner object as owner of a new SPIFFE ID resource locally
func setOwnerRef(owner metav1.Object, spiffeID *spiffeidv1beta1.SpiffeID, scheme *runtime.Scheme) error {
	err := controllerutil.SetControllerReference(owner, spiffeID, scheme)
	if err != nil {
		return err
	}

	// Make owner reference non-blocking, so object can be deleted if registrar is down
	ownerRef := metav1.GetControllerOfNoCopy(spiffeID)
	if ownerRef == nil {
		return err
	}
	ownerRef.BlockOwnerDeletion = pointer.Bool(false)

	return nil
}

// deleteRegistrationEntry deletes an entry on the SPIRE Server
func deleteRegistrationEntry(ctx context.Context, r entryv1.EntryClient, entryID string) error {
	resp, err := r.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: []string{entryID}})
	if err != nil {
		return err
	}
	// These checks are purely defensive
	switch {
	case len(resp.Results) > 1:
		return errors.New("batch delete response has too many results")
	case len(resp.Results) < 1:
		return errors.New("batch delete response missing result")
	}

	err = errorFromStatus(resp.Results[0].Status)
	switch status.Code(err) {
	case codes.OK, codes.NotFound:
		return nil
	default:
		return err
	}
}

func makeID(trustDomain, pathFmt string, pathArgs ...interface{}) string {
	id := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   fmt.Sprintf(pathFmt, pathArgs...),
	}
	return id.String()
}

// Helper functions for string operations.
func equalStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}

	for i, v := range x {
		if v != y[i] {
			return false
		}
	}

	return true
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeStringIf(slice []string, s string) []string {
	i := 0 // output index
	for _, item := range slice {
		if item != s {
			// copy and increment index
			slice[i] = item
			i++
		}
	}

	return slice[:i]
}
