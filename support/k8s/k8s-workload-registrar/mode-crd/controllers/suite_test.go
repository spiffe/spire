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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	spiffeidv1beta1 "github.com/spiffe/spire/support/k8s/k8s-workload-registrar/mode-crd/api/spiffeid/v1beta1"
	"github.com/spiffe/spire/test/fakes/fakeentryclient"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	TrustDomain           = "example.org"
	Cluster               = "test-cluster"
	CheckSignatureEnabled = true
)

type CommonControllerTestSuite struct {
	cluster               string
	k8sClient             client.Client
	entryClient           *fakeentryclient.Client
	log                   logrus.FieldLogger
	r                     *SpiffeIDReconciler
	scheme                *runtime.Scheme
	trustDomain           string
	checkSignatureEnabled bool
}

func NewCommonControllerTestSuite(t *testing.T) CommonControllerTestSuite {
	err := spiffeidv1beta1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)

	log, _ := test.NewNullLogger()
	c := CommonControllerTestSuite{
		cluster:               Cluster,
		log:                   log,
		k8sClient:             fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		entryClient:           fakeentryclient.New(t, spiffeid.RequireTrustDomainFromString(TrustDomain), nil, nil),
		scheme:                scheme.Scheme,
		trustDomain:           TrustDomain,
		checkSignatureEnabled: CheckSignatureEnabled,
	}

	r := NewSpiffeIDReconciler(SpiffeIDReconcilerConfig{
		Client:                c.k8sClient,
		Cluster:               Cluster,
		Log:                   log,
		E:                     c.entryClient,
		TrustDomain:           TrustDomain,
		CheckSignatureEnabled: CheckSignatureEnabled,
	})

	c.r = r
	return c
}
