package federation

import (
	"strings"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const FederationAnnotation = "spiffe.io/federatesWith"

func GetFederationDomains(obj v1.Object) []string {
	if val, ok := obj.GetAnnotations()[FederationAnnotation]; ok {
		return strings.Split(val, ",")
	}
	return []string{}
}
