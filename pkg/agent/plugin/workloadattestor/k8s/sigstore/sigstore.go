//go:build !windows
// +build !windows

package sigstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	sig "github.com/sigstore/cosign/pkg/signature"
	rekor "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/spiffe/spire/pkg/common/telemetry"
	corev1 "k8s.io/api/core/v1"
)

const (
	// Signature Verification Selector
	signatureVerifiedSelector = "sigstore-validation:passed"
)

var (
	// OIDC token issuer Object Identifier
	oidcIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

type Sigstore interface {
	AttestContainerSignatures(ctx context.Context, status *corev1.ContainerStatus) ([]string, error)
	FetchImageSignatures(ctx context.Context, imageName string) ([]oci.Signature, error)
	SelectorValuesFromSignature(oci.Signature) (*SelectorsFromSignatures, error)
	ExtractSelectorsFromSignatures(signatures []oci.Signature, containerID string) []SelectorsFromSignatures
	ShouldSkipImage(imageID string) (bool, error)
	AddSkippedImages(imageID []string)
	ClearSkipList()
	AddAllowedSubject(issuer string, subject string)
	ClearAllowedSubjects()
	SetRekorURL(rekorURL string) error
	SetLogger(logger hclog.Logger)
	SetEnforceSCT(enforceSCT bool)
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

// Data extracted from signature
type SelectorsFromSignatures struct {
	Subject        string
	Content        string
	LogID          string
	IntegratedTime string
}

func New(cache Cache, logger hclog.Logger) Sigstore {
	return &sigstoreImpl{
		functionHooks: sigstoreFunctionHooks{
			// verifyFunction does all the images signatures checks, returning the verified signatures. If there were no valid signatures, it returns an error.
			verifyFunction:             cosign.VerifyImageSignatures,
			fetchImageManifestFunction: remote.Get,
			checkOptsFunction:          defaultCheckOptsFunction,
		},

		logger:        logger,
		sigstorecache: cache,
	}
}

type sigstoreImpl struct {
	functionHooks    sigstoreFunctionHooks
	skippedImages    map[string]struct{}
	subjectAllowList map[string]map[string]struct{}
	rekorURL         url.URL
	logger           hclog.Logger
	sigstorecache    Cache
	enforceSCT       bool
}

type sigstoreFunctionHooks struct {
	verifyFunction             verifyFunctionType
	fetchImageManifestFunction fetchImageManifestFunctionType
	checkOptsFunction          checkOptsFunctionType
}

func (s *sigstoreImpl) SetEnforceSCT(enforceSCT bool) {
	s.enforceSCT = enforceSCT
}

func (s *sigstoreImpl) SetLogger(logger hclog.Logger) {
	s.logger = logger
}

// FetchImageSignatures retrieves signatures for specified image via cosign, using the specified rekor server.
// Returns a list of verified signatures, and an error if any.
func (s *sigstoreImpl) FetchImageSignatures(ctx context.Context, imageName string) ([]oci.Signature, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference: %w", err)
	}

	if err := s.ValidateImage(ref); err != nil {
		return nil, fmt.Errorf("could not validate image reference digest: %w", err)
	}

	co, err := s.functionHooks.checkOptsFunction(s.rekorURL, s.enforceSCT)
	if err != nil {
		return nil, fmt.Errorf("could not create cosign check options: %w", err)
	}
	sigs, ok, err := s.functionHooks.verifyFunction(ctx, ref, co)
	switch {
	case err != nil:
		return nil, fmt.Errorf("error verifying signature: %w", err)
	case !ok:
		return nil, fmt.Errorf("bundle not verified for %q", imageName)
	default:
		return sigs, nil
	}
}

// ExtractSelectorsFromSignatures extracts selectors from a list of image signatures.
// returns a list of selector strings.
func (s *sigstoreImpl) ExtractSelectorsFromSignatures(signatures []oci.Signature, containerID string) []SelectorsFromSignatures {
	if len(signatures) == 0 {
		s.logger.Error("no signatures found for container", telemetry.ContainerID, containerID)
		return nil
	}
	var selectors []SelectorsFromSignatures
	for _, sig := range signatures {
		// verify which subject
		sigSelectors, err := s.SelectorValuesFromSignature(sig)
		if err != nil {
			s.logger.Error("error extracting selectors from signature", "error", err, telemetry.ContainerID, containerID)

			continue
		}
		selectors = append(selectors, *sigSelectors)
	}
	return selectors
}

// SelectorValuesFromSignature extracts selectors from a signature.
// returns a list of selectors.
func (s *sigstoreImpl) SelectorValuesFromSignature(signature oci.Signature) (*SelectorsFromSignatures, error) {
	subject, err := getSignatureSubject(signature)
	if err != nil {
		return nil, fmt.Errorf("error getting signature subject: %w", err)
	}
	if subject == "" {
		return nil, errors.New("error getting signature subject: empty subject")
	}

	issuer, err := getSignatureProvider(signature)
	if err != nil {
		return nil, fmt.Errorf("error getting signature provider: %w", err)
	}
	if issuer == "" {
		return nil, fmt.Errorf("error getting signature provider: %w", errors.New("empty issuer"))
	}

	if issuerSubjects, ok := s.subjectAllowList[issuer]; !ok {
		return nil, fmt.Errorf("signature issuer %q not in allow-list", issuer)
	} else if _, ok := issuerSubjects[subject]; !ok {
		return nil, fmt.Errorf("subject %q not allowed for issuer %q", subject, issuer)
	}

	bundle, err := signature.Bundle()
	switch {
	case err != nil:
		return nil, fmt.Errorf("error getting signature bundle: %w", err)
	case bundle.Payload.LogID == "":
		return nil, errors.New("error getting signature log ID: empty log ID")
	case bundle.Payload.IntegratedTime == 0:
		return nil, errors.New("error getting signature integrated time: integrated time is 0")
	}
	sigContent, err := getBundleSignatureContent(bundle)
	if err != nil {
		return nil, fmt.Errorf("error getting signature content: %w", err)
	}

	return &SelectorsFromSignatures{
		Subject:        subject,
		Content:        sigContent,
		LogID:          bundle.Payload.LogID,
		IntegratedTime: strconv.FormatInt(bundle.Payload.IntegratedTime, 10),
	}, nil
}

// ShouldSkipImage checks the skip list for the image ID in the container status.
// If the image ID is found in the skip list, it returns true.
// If the image ID is not found in the skip list, it returns false.
func (s *sigstoreImpl) ShouldSkipImage(imageID string) (bool, error) {
	if imageID == "" {
		return false, errors.New("image ID is empty")
	}
	if len(s.skippedImages) == 0 {
		return false, nil
	}
	_, ok := s.skippedImages[imageID]
	return ok, nil
}

// AddSkippedImage adds the image ID and selectors to the skip list.
func (s *sigstoreImpl) AddSkippedImages(imageIDList []string) {
	if s.skippedImages == nil {
		s.skippedImages = make(map[string]struct{})
	}
	for _, imageID := range imageIDList {
		s.skippedImages[imageID] = struct{}{}
	}
}

// ClearSkipList clears the skip list.
func (s *sigstoreImpl) ClearSkipList() {
	s.skippedImages = nil
}

// ValidateImage validates if the image manifest hash matches the digest in the image reference
func (s *sigstoreImpl) ValidateImage(ref name.Reference) error {
	dgst, ok := ref.(name.Digest)
	if !ok {
		return fmt.Errorf("reference %T is not a digest", ref)
	}
	desc, err := s.functionHooks.fetchImageManifestFunction(dgst)
	if err != nil {
		return err
	}
	if len(desc.Manifest) == 0 {
		return errors.New("manifest is empty")
	}
	hash, _, err := v1.SHA256(bytes.NewReader(desc.Manifest))
	if err != nil {
		return err
	}

	return validateRefDigest(dgst, hash.String())
}

func (s *sigstoreImpl) AddAllowedSubject(issuer string, subject string) {
	if s.subjectAllowList == nil {
		s.subjectAllowList = make(map[string]map[string]struct{})
	}
	if _, ok := s.subjectAllowList[issuer]; !ok {
		s.subjectAllowList[issuer] = make(map[string]struct{})
	}
	s.subjectAllowList[issuer][subject] = struct{}{}
}

func (s *sigstoreImpl) ClearAllowedSubjects() {
	s.subjectAllowList = nil
}

func (s *sigstoreImpl) AttestContainerSignatures(ctx context.Context, status *corev1.ContainerStatus) ([]string, error) {
	skip, err := s.ShouldSkipImage(status.ImageID)
	if err != nil {
		return nil, fmt.Errorf("failed attesting container signature: %w", err)
	}
	if skip {
		return []string{signatureVerifiedSelector}, nil
	}

	imageID := status.ImageID

	cachedSignature := s.sigstorecache.GetSignature(imageID)
	if cachedSignature != nil {
		s.logger.Debug("Found cached signature", "image_id", imageID)
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

		s.logger.Debug("Caching signature", "image_id", imageID)
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
		return fmt.Errorf("failed parsing rekor URI: %w", err)
	}
	if rekorURI.Host == "" {
		return fmt.Errorf("host is required on rekor URL")
	}
	if rekorURI.Scheme != "https" {
		return fmt.Errorf("invalid rekor URL Scheme %q", rekorURI.Scheme)
	}
	s.rekorURL = *rekorURI
	return nil
}

func defaultCheckOptsFunction(rekorURL url.URL, enforceSCT bool) (*cosign.CheckOpts, error) {
	switch {
	case rekorURL.Host == "":
		return nil, errors.New("rekor URL host is empty")
	case rekorURL.Scheme == "":
		return nil, errors.New("rekor URL scheme is empty")
	case rekorURL.Path == "":
		return nil, errors.New("rekor URL path is empty")
	}

	rootCerts, err := fulcio.GetRoots()
	if err != nil {
		return nil, fmt.Errorf("failed to get fulcio root certificates: %w", err)
	}

	cfg := rekor.DefaultTransportConfig().WithBasePath(rekorURL.Path).WithHost(rekorURL.Host)
	co := &cosign.CheckOpts{
		// Set the rekor client
		RekorClient: rekor.NewHTTPClientWithConfig(nil, cfg),
		RootCerts:   rootCerts,
		EnforceSCT:  enforceSCT,
	}
	co.IntermediateCerts, err = fulcio.GetIntermediates()

	return co, err
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
	if pl == nil {
		return "", errors.New("signature payload is nil")
	}
	if err := json.Unmarshal(pl, &ss); err != nil {
		return "", err
	}
	cert, err := signature.Cert()
	if err != nil {
		return "", fmt.Errorf("failed to access signature certificate: %w", err)
	}

	if cert != nil {
		return sig.CertSubject(cert), nil
	}
	if len(ss.Optional) > 0 {
		if subjString, ok := ss.Optional["subject"]; ok {
			if subj, ok := subjString.(string); ok {
				return subj, nil
			}
		}
	}

	return "", errors.New("no subject found in signature")
}

func getSignatureProvider(signature oci.Signature) (string, error) {
	if signature == nil {
		return "", errors.New("signature is nil")
	}
	cert, err := signature.Cert()
	if err != nil {
		return "", fmt.Errorf("failed to access signature certificate: %w", err)
	}
	if cert == nil {
		return "", errors.New("no certificate found in signature")
	}
	return certOIDCProvider(cert)
}

func certOIDCProvider(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidcIssuerOID) {
			return string(ext.Value), nil
		}
	}

	return "", errors.New("no OIDC issuer found in certificate extensions")
}

func getBundleSignatureContent(bundle *bundle.RekorBundle) (string, error) {
	if bundle == nil {
		return "", errors.New("bundle is nil")
	}
	body64, ok := bundle.Payload.Body.(string)
	if !ok {
		return "", fmt.Errorf("expected payload body to be a string but got %T instead", bundle.Payload.Body)
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

func validateRefDigest(dgst name.Digest, digest string) error {
	if dgst.DigestStr() == digest {
		return nil
	}
	return fmt.Errorf("digest %s does not match %s", digest, dgst.DigestStr())
}

type verifyFunctionType func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)

type fetchImageManifestFunctionType func(name.Reference, ...remote.Option) (*remote.Descriptor, error)

type checkOptsFunctionType func(url.URL, bool) (*cosign.CheckOpts, error)
