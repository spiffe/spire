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

type WebhookConfig struct {
	Log         logrus.FieldLogger
	R           registration.RegistrationClient
	TrustDomain string
	Cluster     string
	PodLabel    string
}

type Webhook struct {
	c WebhookConfig
}

func NewWebhook(config WebhookConfig) *Webhook {
	return &Webhook{
		c: config,
	}
}

func (w *Webhook) Initialize(ctx context.Context) error {
	// ensure there is a node registration entry for PSAT nodes in the cluster.
	return w.createEntry(ctx, &common.RegistrationEntry{
		ParentId: idutil.ServerID(w.c.TrustDomain),
		SpiffeId: w.nodeID(),
		Selectors: []*common.Selector{
			{Type: "k8s_psat", Value: fmt.Sprintf("cluster:%s", w.c.Cluster)},
		},
	})
}

func (w *Webhook) ReviewAdmission(ctx context.Context, req *admv1beta1.AdmissionRequest) (*admv1beta1.AdmissionResponse, error) {
	w.c.Log.WithFields(logrus.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"version":   req.Kind.Version,
		"operation": req.Operation,
	}).Debug("ReviewAdmission called")

	if err := w.reviewAdmission(ctx, req); err != nil {
		return nil, err
	}

	return &admv1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}, nil
}

// reviewAdmission handles CREATE and DELETE requests for pods in
// non-kubernetes namespaces. Ideally the ValidatingAdmissionWebhook
// configuration has filters in place that prevent the webhook from being
// called for requests other than these but just in case, we filter here as
// well.
func (w *Webhook) reviewAdmission(ctx context.Context, req *admv1beta1.AdmissionRequest) error {
	switch req.Namespace {
	case metav1.NamespacePublic, metav1.NamespaceSystem:
		return nil
	}

	if req.Kind != (metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}) {
		return nil
	}

	switch req.Operation {
	case admv1beta1.Create:
		pod := new(corev1.Pod)
		if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
			return errs.New("unable to unmarshal %s/%s object: %v", req.Kind.Version, req.Kind.Kind, err)
		}
		return w.createPodEntry(ctx, pod)
	case admv1beta1.Delete:
		return w.deletePodEntry(ctx, req.Namespace, req.Name)
	}

	return nil
}

func (w *Webhook) createPodEntry(ctx context.Context, pod *corev1.Pod) error {
	if w.c.PodLabel != "" {
		// the webhook has been been configured with a pod label. if the pod
		// has that label, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if labelValue, ok := pod.Labels[w.c.PodLabel]; ok {
			return w.createPodEntryByLabel(ctx, pod, w.c.PodLabel, labelValue)
		}
		return nil
	}

	// the webhook has not been configured with a pod label. create an entry
	// based on the service account.
	return w.createPodEntryByServiceAccount(ctx, pod)
}

func (w *Webhook) createPodEntryByLabel(ctx context.Context, pod *corev1.Pod, labelKey, labelValue string) error {
	return w.createEntry(ctx, &common.RegistrationEntry{
		ParentId: w.nodeID(),
		SpiffeId: w.makeID("%s", labelValue),
		Selectors: []*common.Selector{
			namespaceSelector(pod.Namespace),
			podNameSelector(pod.Name),
		},
	})
}

func (w *Webhook) createPodEntryByServiceAccount(ctx context.Context, pod *corev1.Pod) error {
	return w.createEntry(ctx, &common.RegistrationEntry{
		ParentId: w.nodeID(),
		SpiffeId: w.makeID("ns/%s/sa/%s", pod.Namespace, pod.Spec.ServiceAccountName),
		Selectors: []*common.Selector{
			namespaceSelector(pod.Namespace),
			podNameSelector(pod.Name),
		},
	})
}

func (w *Webhook) deletePodEntry(ctx context.Context, namespace, name string) error {
	log := w.c.Log.WithFields(logrus.Fields{
		"ns":  namespace,
		"pod": name,
	})

	entries, err := w.c.R.ListBySelectors(ctx, &common.Selectors{
		Entries: []*common.Selector{
			namespaceSelector(namespace),
			podNameSelector(name),
		},
	})
	if err != nil {
		return errs.New("unable to list by pod entries: %v", err)
	}

	log.WithField("count", len(entries.Entries)).Debug("Deleting entries")

	var errGroup errs.Group
	for _, entry := range entries.Entries {
		_, err := w.c.R.DeleteEntry(ctx, &registration.RegistrationEntryID{
			Id: entry.EntryId,
		})
		if err != nil {
			log.WithField("err", err.Error()).Debug("Failed deleting pod entry")
			errGroup.Add(errs.New("unable to delete entry %q: %v", entry.EntryId, err))
		}
	}
	return errGroup.Err()
}

func (w *Webhook) nodeID() string {
	return w.makeID("node")
}

func (w *Webhook) makeID(pathFmt string, pathArgs ...interface{}) string {
	id := url.URL{
		Scheme: "spiffe",
		Host:   w.c.TrustDomain,
		Path:   path.Clean(fmt.Sprintf(pathFmt, pathArgs...)),
	}
	return id.String()
}

func (w *Webhook) createEntry(ctx context.Context, entry *common.RegistrationEntry) error {
	// ensure there is a node registration entry for PSAT nodes in the cluster.
	log := w.c.Log.WithFields(logrus.Fields{
		"parent_id": entry.ParentId,
		"spiffe_id": entry.SpiffeId,
		"selectors": selectorsField(entry.Selectors),
	})
	_, err := w.c.R.CreateEntry(ctx, entry)
	switch status.Code(err) {
	case codes.OK, codes.AlreadyExists:
		log.Debug("Created entry")
		return nil
	default:
		log.WithField("err", err).Debug("Failed to create entry")
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
