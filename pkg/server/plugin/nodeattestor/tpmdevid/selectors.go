package tpmdevid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

var attributeTypeNames = map[string]string{
	"2.5.4.3":  "cn",           // Common name
	"2.5.4.5":  "serialnumber", // Serial number
	"2.5.4.6":  "c",            // Country
	"2.5.4.8":  "st",           // State
	"2.5.4.10": "o",            // Organization
	"2.5.4.11": "ou",           // Organizational unit
}

func selectorsFromCertificate(prefix string, cert *x509.Certificate) []string {
	snValue := fmt.Sprintf("%s:serialnumber:%x", prefix, cert.SerialNumber.Bytes())
	selectors := []string{snValue}

	subjectSelectors := selectorsFromAttributes(
		fmt.Sprintf("%s:subject", prefix),
		cert.Subject.Names,
	)

	issuerSelectors := selectorsFromAttributes(
		fmt.Sprintf("%s:issuer", prefix),
		cert.Issuer.Names,
	)

	selectors = append(selectors, subjectSelectors...)
	selectors = append(selectors, issuerSelectors...)

	return selectors
}

func selectorsFromAttributes(prefix string, attributes []pkix.AttributeTypeAndValue) []string {
	selectors := make([]string, 0, len(attributes))
	for _, tv := range attributes {
		valueString := fmt.Sprint(tv.Value)
		oidString := tv.Type.String()
		typeName, ok := attributeTypeNames[oidString]
		if ok {
			selectors = append(selectors,
				fmt.Sprintf("%s:%s:%s", prefix, typeName, valueString))
		}
	}

	return selectors
}
