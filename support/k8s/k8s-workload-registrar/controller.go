package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	admv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ControllerConfig struct {
	Log           logrus.FieldLogger
	R             registration.RegistrationClient
	TrustDomain   string
	Cluster       string
	PodLabel      string
	PodAnnotation string
}

type Controller struct {
	c ControllerConfig
}

func NewController(config ControllerConfig) *Controller {
	return &Controller{
		c: config,
	}
}

func (c *Controller) Initialize(ctx context.Context) error {
	// ensure there is a node registration entry for PSAT nodes in the cluster.
	return c.createEntry(ctx, &common.RegistrationEntry{
		ParentId: idutil.ServerID(c.c.TrustDomain),
		SpiffeId: c.nodeID(),
		Selectors: []*common.Selector{
			{Type: "k8s_psat", Value: fmt.Sprintf("cluster:%s", c.c.Cluster)},
		},
	})
}

func (c *Controller) ReviewAdmission(ctx context.Context, req *admv1beta1.AdmissionRequest) (*admv1beta1.AdmissionResponse, error) {
	c.c.Log.WithFields(logrus.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"version":   req.Kind.Version,
		"operation": req.Operation,
	}).Debug("ReviewAdmission called")

	if err := c.reviewAdmission(ctx, req); err != nil {
		return nil, err
	}

	return &admv1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}, nil
}

// reviewAdmission handles CREATE and DELETE requests for pods in
// non-kubernetes namespaces. Ideally the ValidatingAdmissionWebhook
// configuration has filters in place to restrict the admission requests.
func (c *Controller) reviewAdmission(ctx context.Context, req *admv1beta1.AdmissionRequest) error {
	switch req.Namespace {
	case metav1.NamespacePublic, metav1.NamespaceSystem:
		return nil
	}

	if req.Kind != (metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}) {
		c.c.Log.WithFields(logrus.Fields{
			"version": req.Kind.Version,
			"kind":    req.Kind.Kind,
		}).Warn("Admission request received for unhandled object; check filters")
		return nil
	}

	switch req.Operation {
	case admv1beta1.Create:
		pod := new(corev1.Pod)
		if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
			return errs.New("unable to unmarshal %s/%s object: %v", req.Kind.Version, req.Kind.Kind, err)
		}
		return c.createPodEntry(ctx, pod)
	case admv1beta1.Delete:
		return c.deletePodEntry(ctx, req.Namespace, req.Name)
	default:
		c.c.Log.WithFields(logrus.Fields{
			"operation": req.Operation,
		}).Warn("Admission request received for unhandled pod operation; check filters")
	}

	return nil
}

// podSpiffeID returns the desired spiffe ID for the pod, or nil if it should be ignored
func (c *Controller) podSpiffeID(pod *corev1.Pod) string {
	if c.c.PodLabel != "" {
		// the controller has been configured with a pod label. if the pod
		// has that label, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if labelValue, ok := pod.Labels[c.c.PodLabel]; ok {
			return c.makeID("%s", labelValue)
		}
		return ""
	}

	if c.c.PodAnnotation != "" {
		// the controller has been configured with a pod annotation. if the pod
		// has that annotation, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if annotationValue, ok := pod.Annotations[c.c.PodAnnotation]; ok {
			return c.makeID("%s", annotationValue)
		}
		return ""
	}

	// the controller has not been configured with a pod label or a pod annotation.
	// create an entry based on the service account.
	return c.makeID("ns/%s/sa/%s", pod.Namespace, pod.Spec.ServiceAccountName)
}

func (c *Controller) createPodEntry(ctx context.Context, pod *corev1.Pod) error {
	spiffeID := c.podSpiffeID(pod)
	// If we have no spiffe ID for the pod, do nothing
	if spiffeID == "" {
		return nil
	}

	return c.createEntry(ctx, &common.RegistrationEntry{
		ParentId: c.nodeID(),
		SpiffeId: spiffeID,
		Selectors: []*common.Selector{
			namespaceSelector(pod.Namespace),
			podNameSelector(pod.Name),
		},
	})
}

func (c *Controller) deletePodEntry(ctx context.Context, namespace, name string) error {
	log := c.c.Log.WithFields(logrus.Fields{
		"ns":  namespace,
		"pod": name,
	})

	entries, err := c.c.R.ListBySelectors(ctx, &common.Selectors{
		Entries: []*common.Selector{
			namespaceSelector(namespace),
			podNameSelector(name),
		},
	})
	if err != nil {
		return errs.New("unable to list by pod entries: %v", err)
	}

	log.Info("Deleting pod entries")
	if len(entries.Entries) > 1 {
		log.WithField("count", len(entries.Entries)).Warn("Multiple pod entries found to delete")
	}

	var errGroup errs.Group
	for _, entry := range entries.Entries {
		_, err := c.c.R.DeleteEntry(ctx, &registration.RegistrationEntryID{
			Id: entry.EntryId,
		})
		if err != nil {
			log.WithError(err).Error("Failed deleting pod entry")
			errGroup.Add(errs.New("unable to delete entry %q: %v", entry.EntryId, err))
		}
	}
	return errGroup.Err()
}

func (c *Controller) nodeID() string {
	return c.makeID("k8s-workload-registrar/%s/node", c.c.Cluster)
}

func (c *Controller) makeID(pathFmt string, pathArgs ...interface{}) string {
	id := url.URL{
		Scheme: "spiffe",
		Host:   c.c.TrustDomain,
		Path:   path.Clean(fmt.Sprintf(pathFmt, pathArgs...)),
	}
	return id.String()
}

func (c *Controller) createEntry(ctx context.Context, entry *common.RegistrationEntry) error {
	// ensure there is a node registration entry for PSAT nodes in the cluster.
	log := c.c.Log.WithFields(logrus.Fields{
		"parent_id": entry.ParentId,
		"spiffe_id": entry.SpiffeId,
		"selectors": selectorsField(entry.Selectors),
	})
	_, err := c.c.R.CreateEntry(ctx, entry)
	switch status.Code(err) {
	case codes.OK, codes.AlreadyExists:
		log.Info("Created pod entry")
		return nil
	default:
		log.WithError(err).Error("Failed to create pod entry")
		return errs.Wrap(err)
	}
}

func namespaceSelector(namespace string) *common.Selector {
	return &common.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("ns:%s", namespace),
	}
}

func podNameSelector(podName string) *common.Selector {
	return &common.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("pod-name:%s", podName),
	}
}

func selectorsField(selectors []*common.Selector) string {
	var buf bytes.Buffer
	for i, selector := range selectors {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(selector.Type)
		buf.WriteString(":")
		buf.WriteString(selector.Value)
	}
	return buf.String()
}
