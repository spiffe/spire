package federation

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFederationNoDomains(t *testing.T) {
	// build a fake pod
	pod := &corev1.Pod{ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{"foo": "bar"}}}

	// get annotations
	domains := GetFederationDomains(pod)

	if len(domains) != 0 {
		t.Fatal("Wrong amount of trust domains")
	}
}

func TestFederationSingleDomain(t *testing.T) {
	// build a fake pod
	pod := &corev1.Pod{ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{FederationAnnotation: "example.com"}}}

	// get annotations
	domains := GetFederationDomains(pod)

	// verify we have a matching domain
	if len(domains) != 1 {
		t.Fatal("Wrong amount of trust domains")
	}
}

func TestFederationMultiDomain(t *testing.T) {
	// build a fake pod
	pod := &corev1.Pod{ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{FederationAnnotation: "example.com,example.org"}}}

	// get annotations
	domains := GetFederationDomains(pod)

	// verify we have a matching domain
	if len(domains) != 2 {
		t.Fatal("Wrong amount of trust domains")
	}
}
