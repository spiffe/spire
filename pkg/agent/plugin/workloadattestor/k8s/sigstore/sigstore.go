package sigstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	corev1 "k8s.io/api/core/v1"
)

const (
	// Signature Verification Selector
	signatureVerifiedSelector = "sigstore-validation:passed"
)

type Sigstore interface {
	AttestContainerSignatures(ctx context.Context, status *corev1.ContainerStatus) ([]string, error)
	FetchImageSignatures(ctx context.Context, imageName string) ([]oci.Signature, error)
	SelectorValuesFromSignature(oci.Signature, string) SelectorsFromSignatures
	ExtractSelectorsFromSignatures(signatures []oci.Signature, containerID string) []SelectorsFromSignatures
	ShouldSkipImage(imageID string) (bool, error)
	AddSkippedImage(imageID string)
	ClearSkipList()
	AddAllowedSubject(subject string)
	EnableAllowSubjectList(bool)
	ClearAllowedSubjects()
	SetRekorURL(rekorURL string) error
	SetLogger(logger hclog.Logger)
}

type sigstoreImpl struct {
	verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
	skippedImages              map[string]bool
	allowListEnabled           bool
	subjectAllowList           map[string]bool
	rekorURL                   url.URL
	checkOptsFunction          func(url.URL) *cosign.CheckOpts
	logger                     hclog.Logger
	sigstorecache              Cache
}

func New(cache Cache, logger hclog.Logger) Sigstore {
	return &sigstoreImpl{
		verifyFunction:             cosign.VerifyImageSignatures,
		fetchImageManifestFunction: remote.Get,
		checkOptsFunction:          DefaultCheckOpts,

		rekorURL: url.URL{
			Scheme: rekor.DefaultSchemes[0],
			Host:   rekor.DefaultHost,
			Path:   rekor.DefaultBasePath,
		},
		logger:        logger,
		sigstorecache: cache,
	}
}

func DefaultCheckOpts(rekorURL url.URL) *cosign.CheckOpts {
	co := &cosign.CheckOpts{}

	// Set the rekor client
	co.RekorClient = rekor.NewHTTPClientWithConfig(nil, rekor.DefaultTransportConfig().WithBasePath(rekorURL.Path).WithHost(rekorURL.Host))

	co.RootCerts = fulcio.GetRoots()

	return co
}

func (s *sigstoreImpl) SetLogger(logger hclog.Logger) {
	s.logger = logger
}

// FetchImageSignatures retrieves signatures for specified image via cosign, using the specified rekor server.
// Returns a list of verified signatures, and an error if any.
func (s *sigstoreImpl) FetchImageSignatures(ctx context.Context, imageName string) ([]oci.Signature, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		message := fmt.Errorf("error parsing image reference: %w", err)
		return nil, message
	}

	if _, err := s.ValidateImage(ref); err != nil {
		message := fmt.Errorf("could not validate image reference digest: %w", err)
		return nil, message
	}

	co := s.checkOptsFunction(s.rekorURL)
	sigs, ok, err := s.verifyFunction(ctx, ref, co)
	if err != nil {
		message := fmt.Errorf("error verifying signature: %w", err)
		return nil, message
	}
	if !ok {
		return nil, fmt.Errorf("bundle not verified for %q", imageName)
	}

	return sigs, nil
}

// ExtractSelectorsFromSignatures extracts selectors from a list of image signatures.
// returns a list of selector strings.
func (s *sigstoreImpl) ExtractSelectorsFromSignatures(signatures []oci.Signature, containerID string) []SelectorsFromSignatures {
	// Payload can be empty if the attestor fails to retrieve it
	if signatures == nil {
		return nil
	}
	var selectors []SelectorsFromSignatures
	for _, sig := range signatures {
		// verify which subject
		sigSelectors := s.SelectorValuesFromSignature(sig, containerID)
		if sigSelectors.Verified {
			selectors = append(selectors, sigSelectors)
		}
	}
	return selectors
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

type SelectorsFromSignatures struct {
	Subject        string
	Content        string
	LogID          string
	IntegratedTime string
	Verified       bool
}

// SelectorValuesFromSignature extracts selectors from a signature.
// returns a list of selectors.
func (s *sigstoreImpl) SelectorValuesFromSignature(signature oci.Signature, containerID string) SelectorsFromSignatures {
	var selectorsFromSignatures SelectorsFromSignatures
	subject, err := getSignatureSubject(signature)

	if err != nil {
		s.logger.Error("error getting signature subject: ", err)
		return selectorsFromSignatures
	}

	if subject == "" {
		s.logger.Error("error getting signature subject: empty subject")
		return selectorsFromSignatures
	}

	if s.allowListEnabled {
		if _, ok := s.subjectAllowList[subject]; !ok {
			return selectorsFromSignatures
		}
	}

	selectorsFromSignatures.Subject = subject
	selectorsFromSignatures.Verified = true

	bundle, err := signature.Bundle()
	if err != nil {
		s.logger.Error("error getting signature bundle: ", err.Error())
	} else {
		sigContent, err := getBundleSignatureContent(bundle)
		if err != nil {
			s.logger.Error("error getting signature content: ", err)
		} else {
			selectorsFromSignatures.Content = sigContent
		}
		if bundle.Payload.LogID != "" {
			selectorsFromSignatures.LogID = bundle.Payload.LogID
		}
		if bundle.Payload.IntegratedTime != 0 {
			selectorsFromSignatures.IntegratedTime = strconv.FormatInt(bundle.Payload.IntegratedTime, 10)
		}
	}
	return selectorsFromSignatures
}

// ShouldSkipImage checks the skip list for the image ID in the container status.
// If the image ID is found in the skip list, it returns true.
// If the image ID is not found in the skip list, it returns false.
func (s *sigstoreImpl) ShouldSkipImage(imageID string) (bool, error) {
	if s.skippedImages == nil {
		return false, nil
	}
	if imageID == "" {
		return false, errors.New("image ID is empty")
	}
	_, ok := s.skippedImages[imageID]
	return ok, nil
}

// AddSkippedImage adds the image ID and selectors to the skip list.
func (s *sigstoreImpl) AddSkippedImage(imageID string) {
	if s.skippedImages == nil {
		s.skippedImages = make(map[string]bool)
	}
	s.skippedImages[imageID] = true
}

// ClearSkipList clears the skip list.
func (s *sigstoreImpl) ClearSkipList() {
	s.skippedImages = nil
}

// ValidateImage validates if the image manifest hash matches the digest in the image reference
func (s *sigstoreImpl) ValidateImage(ref name.Reference) (bool, error) {
	desc, err := s.fetchImageManifestFunction(ref)
	if err != nil {
		return false, err
	}
	if len(desc.Manifest) == 0 {
		return false, errors.New("manifest is empty")
	}
	hash, _, err := v1.SHA256(bytes.NewReader(desc.Manifest))
	if err != nil {
		return false, err
	}

	return validateRefDigest(ref, hash.String())
}

func (s *sigstoreImpl) AddAllowedSubject(subject string) {
	if s.subjectAllowList == nil {
		s.subjectAllowList = make(map[string]bool)
	}
	s.subjectAllowList[subject] = true
}

func (s *sigstoreImpl) ClearAllowedSubjects() {
	s.subjectAllowList = nil
}

func (s *sigstoreImpl) EnableAllowSubjectList(flag bool) {
	s.allowListEnabled = flag
}

func (s *sigstoreImpl) AttestContainerSignatures(ctx context.Context, status *corev1.ContainerStatus) ([]string, error) {
	skip, _ := s.ShouldSkipImage(status.ImageID)
	if skip {
		return []string{signatureVerifiedSelector}, nil
	}

	imageID := status.ImageID

	cachedSignature := s.sigstorecache.GetSignature(imageID)
	if cachedSignature != nil {
		s.logger.Debug("Found cached signature", "imageId", imageID)
	} else {
		signatures, err := s.FetchImageSignatures(ctx, imageID)
		if err != nil {
			return nil, err
		}

		selectors := s.ExtractSelectorsFromSignatures(signatures, status.ContainerID)

		cachedSignature = &Item{
			Key:   imageID,
			Value: selectors,
		}

		s.logger.Debug("Caching signature", "imageID", imageID)
		s.sigstorecache.PutSignature(*cachedSignature)
	}

	var selectorsString []string
	if len(cachedSignature.Value) > 0 {
		for _, selector := range cachedSignature.Value {
			toString := selectorsToString(selector, status.ContainerID)
			selectorsString = append(selectorsString, toString...)
		}
		selectorsString = append(selectorsString, signatureVerifiedSelector)
	}

	return selectorsString, nil
}

func (s *sigstoreImpl) SetRekorURL(rekorURL string) error {
	if rekorURL == "" {
		return errors.New("rekor URL is empty")
	}
	rekorURI, err := url.Parse(rekorURL)
	if err != nil {
		return fmt.Errorf("failed to parsing rekor URI: %w", err)
	}
	if rekorURI.Scheme != "" && rekorURI.Scheme != "https" {
		return fmt.Errorf("invalid rekor URL Scheme: %s", rekorURI.Scheme)
	}
	if rekorURI.Host == "" {
		return fmt.Errorf("invalid rekor URL Host: %s", rekorURI.Host)
	}
	s.rekorURL = *rekorURI
	return nil
}

func getSignatureSubject(signature oci.Signature) (string, error) {
	if signature == nil {
		return "", errors.New("signature is nil")
	}
	ss := payload.SimpleContainerImage{}
	pl, err := signature.Payload()
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(pl, &ss)
	if err != nil {
		return "", err
	}
	cert, err := signature.Cert()
	if err != nil {
		return "", fmt.Errorf("failed to access signature certificate: %w", err)
	}

	subject := ""
	if len(ss.Optional) > 0 {
		subjString, ok := ss.Optional["subject"]
		if ok {
			subj, ok := subjString.(string)
			if ok {
				subject = subj
			}
		}
	}
	if cert != nil {
		subject = certSubject(cert)
	}

	return subject, nil
}

func getBundleSignatureContent(bundle *oci.Bundle) (string, error) {
	if bundle == nil {
		return "", errors.New("bundle is nil")
	}
	body64, ok := bundle.Payload.Body.(string)
	if !ok {
		return "", errors.New("payload body is not a string")
	}
	body, err := base64.StdEncoding.DecodeString(body64)
	if err != nil {
		return "", err
	}
	var bundleBody BundleBody
	if err := json.Unmarshal(body, &bundleBody); err != nil {
		return "", fmt.Errorf("failed to parse bundle body: %w", err)
	}

	if bundleBody.Spec.Signature.Content == "" {
		return "", errors.New("bundle payload body has no signature content")
	}

	return bundleBody.Spec.Signature.Content, nil
}

func selectorsToString(selectors SelectorsFromSignatures, containerID string) []string {
	var selectorsString []string
	if selectors.Subject != "" {
		selectorsString = append(selectorsString, fmt.Sprintf("%s:image-signature-subject:%s", containerID, selectors.Subject))
	}
	if selectors.Content != "" {
		selectorsString = append(selectorsString, fmt.Sprintf("%s:image-signature-content:%s", containerID, selectors.Content))
	}
	if selectors.LogID != "" {
		selectorsString = append(selectorsString, fmt.Sprintf("%s:image-signature-logid:%s", containerID, selectors.LogID))
	}
	if selectors.IntegratedTime != "" {
		selectorsString = append(selectorsString, fmt.Sprintf("%s:image-signature-integrated-time:%s", containerID, selectors.IntegratedTime))
	}
	return selectorsString
}

func certSubject(c *x509.Certificate) string {
	switch {
	case c == nil:
		return ""
	case len(c.EmailAddresses) > 0:
		return c.EmailAddresses[0]
	case len(c.URIs) > 0:
		// removing leading '//' from c.URIs[0].String()
		return strings.TrimPrefix(c.URIs[0].String(), "//")
	default:
		return ""
	}
}

func validateRefDigest(ref name.Reference, digest string) (bool, error) {
	if dgst, ok := ref.(name.Digest); ok {
		if dgst.DigestStr() == digest {
			return true, nil
		}
		return false, fmt.Errorf("digest %s does not match %s", digest, dgst.DigestStr())
	}
	return false, fmt.Errorf("reference %s is not a digest", ref.String())
}
