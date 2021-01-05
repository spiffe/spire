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
	TrustDomain = "example.org"
	Cluster     = "test-cluster"
)

type CommonControllerTestSuite struct {
	cluster     string
	ctx         context.Context
	k8sClient   client.Client
	entryClient *fakeentryclient.Client
	log         logrus.FieldLogger
	r           *SpiffeIDReconciler
	scheme      *runtime.Scheme
	trustDomain string
}

func NewCommonControllerTestSuite(t *testing.T) CommonControllerTestSuite {
	err := spiffeidv1beta1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)

	log, _ := test.NewNullLogger()
	c := CommonControllerTestSuite{
		cluster:     Cluster,
		ctx:         context.Background(),
		log:         log,
		k8sClient:   fake.NewFakeClientWithScheme(scheme.Scheme),
		entryClient: fakeentryclient.New(t, spiffeid.RequireTrustDomainFromString(TrustDomain), nil, nil),
		scheme:      scheme.Scheme,
		trustDomain: TrustDomain,
	}

	r := NewSpiffeIDReconciler(SpiffeIDReconcilerConfig{
		Client:      c.k8sClient,
		Cluster:     Cluster,
		Ctx:         c.ctx,
		Log:         log,
		E:           c.entryClient,
		TrustDomain: TrustDomain,
	})

	c.r = r
	return c
}
