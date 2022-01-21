package sigstore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	rekor "github.com/sigstore/rekor/pkg/generated/client"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type Sigstore interface {
	FetchSignaturePayload(imageName string, rekorURL string) ([]oci.Signature, error)
	ExtractselectorOfSignedImage(signatures []oci.Signature) string
}

type Sigstoreimpl struct {
	verifyFunction func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
}

func New() Sigstore {
	return &Sigstoreimpl{
		verifyFunction: cosign.VerifyImageSignatures,
	}
}

// FetchSignaturePayload retrieves the signature payload from the specified image
func (sigstore Sigstoreimpl) FetchSignaturePayload(imageName string, rekorURL string) ([]oci.Signature, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		message := fmt.Sprint("Error parsing image reference: ", err.Error())
		return nil, errors.New(message)
	}
	co := &cosign.CheckOpts{}
	if rekorURL != "" {
		rekorURI, err := url.Parse(rekorURL)
		if err != nil {
			message := fmt.Sprint("Error parsing rekor URI: ", err.Error())
			return nil, errors.New(message)
		}
		if rekorURI.Scheme != "" && rekorURI.Scheme != "https" {
			return nil, errors.New("Invalid rekor URL Scheme: " + rekorURI.Scheme)
		}
		if rekorURI.Host == "" {
			return nil, errors.New("Invalid rekor URL Host: " + rekorURI.Host)
		}
		co.RekorClient = rekor.NewHTTPClientWithConfig(nil, rekor.DefaultTransportConfig().WithBasePath(rekorURI.Path).WithHost(rekorURI.Host))
	} else {
		co.RekorClient = rekor.NewHTTPClientWithConfig(nil, rekor.DefaultTransportConfig())
	}
	if co.RekorClient == nil {
		return nil, errors.New("Error creating rekor client")
	}
	co.RootCerts = fulcio.GetRoots()

	ctx := context.Background()
	sigs, ok, err := sigstore.verifyFunction(ctx, ref, co)
	if err != nil {
		message := fmt.Sprint("Error verifying signature: ", err.Error())
		return nil, errors.New(message)
	}
	if !ok {
		message := "Bundle not verified for " + imageName
		return nil, errors.New(message)
	}

	return sigs, nil
}

func (Sigstoreimpl) ExtractselectorOfSignedImage(signatures []oci.Signature) string {
	var selector string
	// Payload can be empty if the attestor fails to retrieve it
	// In a non-strict mode this method should be reached and return
	// an empty selector
	if signatures != nil {
		// verify which subject
		selector = getImageSubject(signatures)
	}

	// return subject as selector
	return selector
}

type Subject struct {
	Subject string `json:"Subject"`
}

type Optional struct {
	Optional Subject `json:"optional"`
}

func getOnlySubject(payload string) string {
	var selector []Optional
	err := json.Unmarshal([]byte(payload), &selector)

	if err != nil {
		log.Println("Error decoding the payload:", err.Error())
		return ""
	}

	re := regexp.MustCompile(`[{}]`) // brackets regex

	if len(selector) > 0 { // if there is a subject
		subject := fmt.Sprintf("%s", selector[0])  // get the first subject
		subject = re.ReplaceAllString(subject, "") // remove the brackets

		return subject
	}

	return ""
}

func getImageSubject(verified []oci.Signature) string {
	var outputKeys []payload.SimpleContainerImage
	for _, vs := range verified {
		ss := payload.SimpleContainerImage{}
		pl, err := vs.Payload()
		if err != nil {
			log.Println("Error accessing the payload:", err.Error())
			return ""
		}
		err = json.Unmarshal(pl, &ss)
		if err != nil {
			log.Println("Error decoding the payload:", err.Error())
			return ""
		}
		cert, err := vs.Cert()
		if err != nil {
			log.Println("Error accessing the certificate:", err.Error())
			return ""
		}
		if cert != nil {
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["Subject"] = certSubject(cert)
		}

		outputKeys = append(outputKeys, ss)
	}
	b, _ := json.Marshal(outputKeys)

	subject := getOnlySubject(string(b))

	return subject
}

func certSubject(c *x509.Certificate) string {
	switch {
	case c == nil:
		return ""
	case c.EmailAddresses != nil:
		return c.EmailAddresses[0]
	case c.URIs != nil:
		// removing leading '//' from c.URIs[0].String()
		re := regexp.MustCompile(`^\/*(?P<email>.*)`)
		return re.ReplaceAllString(c.URIs[0].String(), "$email")
	}
	return ""
}
