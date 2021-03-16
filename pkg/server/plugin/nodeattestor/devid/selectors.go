package devid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	spc "github.com/spiffe/spire/proto/spire/common"
)

var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}

func selectorsFromCertificate(selectorType, prefix string, cert *x509.Certificate) []*spc.Selector {
	snValue := fmt.Sprintf("%s:serialnumber:%x", prefix, cert.SerialNumber.Bytes())

	selectors := []*spc.Selector{
		{
			Type:  selectorType,
			Value: snValue,
		},
	}

	subjectSelectors := selectorsFromAttributes(
		selectorType,
		fmt.Sprintf("%s:subject", prefix),
		cert.Subject.Names,
	)

	issuerSelectors := selectorsFromAttributes(
		selectorType,
		fmt.Sprintf("%s:issuer", prefix),
		cert.Issuer.Names,
	)

	selectors = append(selectors, subjectSelectors...)
	selectors = append(selectors, issuerSelectors...)

	return selectors
}

func selectorsFromAttributes(selectorType, prefix string, attributes []pkix.AttributeTypeAndValue) []*spc.Selector {
	selectors := make([]*spc.Selector, 0, len(attributes))
	for _, tv := range attributes {
		valueString := fmt.Sprint(tv.Value)
		oidString := tv.Type.String()
		typeName, ok := attributeTypeNames[oidString]
		if ok {
			selectors = append(selectors, &spc.Selector{
				Type:  selectorType,
				Value: fmt.Sprintf("%s:%s:%s", prefix, typeName, valueString),
			})
		}

		selectors = append(selectors, &spc.Selector{
			Type:  selectorType,
			Value: fmt.Sprintf("%s:oid:%s:%s", prefix, oidString, valueString),
		})
	}

	return selectors
}
