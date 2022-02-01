package sigstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	rekor "github.com/sigstore/rekor/pkg/generated/client"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	corev1 "k8s.io/api/core/v1"
)

type Sigstore interface {
	FetchImageSignatures(imageName string, rekorURL string) ([]oci.Signature, error)
	SelectorValuesFromSignature(oci.Signature) []string
	ExtractSelectorsFromSignatures(signatures []oci.Signature) []string
	ShouldSkipImage(status corev1.ContainerStatus) (bool, error)
	AddSkippedImage(imageID string)
	ClearSkipList()
	AddAllowedSubject(subject string)
	EnableAllowSubjectList(bool)
	ClearAllowedSubjects()
}

type Sigstoreimpl struct {
	verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
	skippedImages              map[string]bool
	allowListEnabled           bool
	subjectAllowList           map[string]bool
}

func New() Sigstore {
	return &Sigstoreimpl{
		verifyFunction:             cosign.VerifyImageSignatures,
		fetchImageManifestFunction: remote.Get,
		skippedImages:              nil,
		allowListEnabled:           false,
		subjectAllowList:           nil,
	}
}

// FetchImageSignatures retrieves signatures for specified image via cosign, using the specified rekor server.
// Returns a list of verified signatures, and an error if any.
func (sigstore *Sigstoreimpl) FetchImageSignatures(imageName string, rekorURL string) ([]oci.Signature, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		message := fmt.Sprint("Error parsing image reference: ", err.Error())
		return nil, errors.New(message)
	}

	_, err = sigstore.ValidateImage(ref)
	if err != nil {
		message := fmt.Sprint("Could not validate image reference digest: ", err.Error())
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

// ExtractSelectorsFromSignatures extracts selectors from a list of image signatures.
// returns a list of selector strings.
func (sigstore *Sigstoreimpl) ExtractSelectorsFromSignatures(signatures []oci.Signature) []string {
	// Payload can be empty if the attestor fails to retrieve it
	if signatures == nil {
		return nil
	}
	var selectors []string
	for _, sig := range signatures {
		// verify which subject
		sigSelectors := sigstore.SelectorValuesFromSignature(sig)
		if sigSelectors != nil {
			selectors = append(selectors, sigSelectors...)
		}
	}
	return selectors
}

func getSignatureSubject(signature oci.Signature) string {
	if signature == nil {
		return ""
	}
	ss := payload.SimpleContainerImage{}
	pl, err := signature.Payload()
	if err != nil {
		log.Println("Error accessing the payload:", err.Error())
		return ""
	}
	err = json.Unmarshal(pl, &ss)
	if err != nil {
		log.Println("Error decoding the payload:", err.Error())
		return ""
	}
	cert, err := signature.Cert()
	if err != nil {
		log.Println("Error accessing the certificate:", err.Error())
		return ""
	}

	subject := ""
	if ss.Optional != nil {
		subjString := ss.Optional["subject"]
		if _, ok := subjString.(string); ok {
			subject = subjString.(string)
		}
	}
	if cert != nil {
		subject = certSubject(cert)
	}

	return subject
}

// The following structs are used to go through the payload json objects
type BundleSignature struct {
	Content   string            `json:"content"`
	Format    string            `json:"format"`
	PublicKey map[string]string `json:"publicKey"`
}

type BundleSpec struct {
	Data      map[string]map[string]string `json:"data"`
	Signature BundleSignature              `json:"signature"`
}

type BundleBody struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Spec       BundleSpec `json:"spec"`
}

func getBundleSignatureContent(bundle *oci.Bundle) (string, error) {
	if bundle == nil {
		return "", errors.New("Bundle is nil")
	}
	body64, ok := bundle.Payload.Body.(string)
	if !ok {
		return "", errors.New("Payload body is not a string")
	}
	body, err := base64.StdEncoding.DecodeString(body64)
	if err != nil {
		return "", err
	}
	var bundlebody BundleBody
	err = json.Unmarshal(body, &bundlebody)

	if err != nil {
		return "", err
	}

	if bundlebody.Spec.Signature.Content == "" {
		return "", errors.New("Bundle payload body has no signature content")
	}

	return bundlebody.Spec.Signature.Content, nil
}

// SelectorValuesFromSignature extracts selectors from a signature.
// returns a list of selectors.
func (sigstore *Sigstoreimpl) SelectorValuesFromSignature(signature oci.Signature) []string {
	subject := getSignatureSubject(signature)

	if subject == "" {
		return nil
	}

	suppress := false
	if sigstore.allowListEnabled {
		if _, ok := sigstore.subjectAllowList[subject]; !ok {
			suppress = true
		}
	}

	var selectors []string
	if !suppress {
		selectors = []string{
			fmt.Sprintf("image-signature-subject:%s", subject),
		}
		bundle, _ := signature.Bundle()
		sigContent, err := getBundleSignatureContent(bundle)
		if err != nil {
			log.Println("Error getting signature content: ", err.Error())
		} else {
			selectors = append(selectors, fmt.Sprintf("image-signature-content:%s", sigContent))
		}
	}

	return selectors
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

// ShouldSkipImage checks the skip list for the image ID in the container status.
// If the image ID is found in the skip list, it returns true.
// If the image ID is not found in the skip list, it returns false.
func (sigstore *Sigstoreimpl) ShouldSkipImage(status corev1.ContainerStatus) (bool, error) {
	if sigstore.skippedImages == nil {
		return false, nil
	}
	if status.ImageID == "" {
		return false, errors.New("Container status does not contain an image ID")
	}
	if _, ok := sigstore.skippedImages[status.ImageID]; ok {
		return true, nil
	}
	return false, nil
}

// AddSkippedImage adds the image ID and selectors to the skip list.
func (sigstore *Sigstoreimpl) AddSkippedImage(imageID string) {
	if sigstore.skippedImages == nil {
		sigstore.skippedImages = make(map[string]bool)
	}
	sigstore.skippedImages[imageID] = true
}

// ClearSkipList clears the skip list.
func (sigstore *Sigstoreimpl) ClearSkipList() {
	for k := range sigstore.skippedImages {
		delete(sigstore.skippedImages, k)
	}
	sigstore.skippedImages = nil
}

// Validates if the image manifest hash matches the digest in the image reference
func (sigstore *Sigstoreimpl) ValidateImage(ref name.Reference) (bool, error) {
	desc, err := sigstore.fetchImageManifestFunction(ref)
	if err != nil {
		return false, err
	}
	if desc.Manifest == nil {
		return false, errors.New("Manifest is nil")
	}
	hash, _, err := v1.SHA256(bytes.NewReader(desc.Manifest))
	if err != nil {
		return false, err
	}

	return validateRefDigest(ref, hash.String())
}

func validateRefDigest(ref name.Reference, digest string) (bool, error) {
	if dgst, ok := ref.(name.Digest); ok {
		if dgst.DigestStr() == digest {
			return true, nil
		}
		return false, fmt.Errorf("Digest %s does not match %s", digest, dgst.DigestStr())
	}
	return false, fmt.Errorf("Reference %s is not a digest", ref.String())
}

func (sigstore *Sigstoreimpl) AddAllowedSubject(subject string) {
	if sigstore.subjectAllowList == nil {
		sigstore.subjectAllowList = make(map[string]bool)
	}
	sigstore.subjectAllowList[subject] = true
}

func (sigstore *Sigstoreimpl) ClearAllowedSubjects() {
	for k := range sigstore.subjectAllowList {
		delete(sigstore.subjectAllowList, k)
	}
	sigstore.subjectAllowList = nil
}

func (sigstore *Sigstoreimpl) EnableAllowSubjectList(flag bool) {
	sigstore.allowListEnabled = flag
}
