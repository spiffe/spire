package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	admv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

type AdmissionController interface {
	ReviewAdmission(context.Context, admv1.AdmissionReview) (*admv1.AdmissionResponse, error)
}

type WebhookHandler struct {
	log        logrus.FieldLogger
	controller AdmissionController
}

func NewWebhookHandler(log logrus.FieldLogger, controller AdmissionController) *WebhookHandler {
	_ = admv1.AddToScheme(runtimeScheme)
	_ = admv1beta1.AddToScheme(runtimeScheme)
	return &WebhookHandler{
		log:        log,
		controller: controller,
	}
}

// admitv1beta1Func handles a v1beta1 admission
type admitv1beta1Func func(context.Context, admv1beta1.AdmissionReview) (*admv1beta1.AdmissionResponse, error)

// admitv1beta1Func handles a v1 admission
type admitv1Func func(context.Context, admv1.AdmissionReview) (*admv1.AdmissionResponse, error)

// admitHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admitHandler struct {
	v1beta1 admitv1beta1Func
	v1      admitv1Func
}

func newDelegateToV1AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{
		v1beta1: delegateV1beta1AdmitToV1(f),
		v1:      f,
	}
}

func delegateV1beta1AdmitToV1(f admitv1Func) admitv1beta1Func {
	return func(context context.Context, review admv1beta1.AdmissionReview) (*admv1beta1.AdmissionResponse, error) {
		in := admv1.AdmissionReview{Request: convertAdmissionRequestToV1(review.Request)}
		out, err := f(context, in)
		if err != nil {
			return nil, err
		}
		return convertAdmissionResponseToV1beta1(out), nil
	}
}

func convertAdmissionRequestToV1(r *admv1beta1.AdmissionRequest) *admv1.AdmissionRequest {
	return &admv1.AdmissionRequest{
		Kind:               r.Kind,
		Namespace:          r.Namespace,
		Name:               r.Name,
		Object:             r.Object,
		Resource:           r.Resource,
		Operation:          admv1.Operation(r.Operation),
		UID:                r.UID,
		DryRun:             r.DryRun,
		OldObject:          r.OldObject,
		Options:            r.Options,
		RequestKind:        r.RequestKind,
		RequestResource:    r.RequestResource,
		RequestSubResource: r.RequestSubResource,
		SubResource:        r.SubResource,
		UserInfo:           r.UserInfo,
	}
}

func convertAdmissionResponseToV1beta1(r *admv1.AdmissionResponse) *admv1beta1.AdmissionResponse {
	var pt *admv1beta1.PatchType
	if r.PatchType != nil {
		t := admv1beta1.PatchType(*r.PatchType)
		pt = &t
	}
	return &admv1beta1.AdmissionResponse{
		UID:              r.UID,
		Allowed:          r.Allowed,
		AuditAnnotations: r.AuditAnnotations,
		Patch:            r.Patch,
		PatchType:        pt,
		Result:           r.Result,
	}
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/validate" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if req.Method != http.MethodPost {
		http.Error(w, "Expected POST", http.StatusMethodNotAllowed)
		return
	}

	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		http.Error(w, "Expected JSON content", http.StatusBadRequest)
		return
	}

	var body []byte
	if data, err := ioutil.ReadAll(req.Body); err == nil {
		body = data
	}

	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Malformed JSON body: %v", err)
		h.log.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	log := h.log.WithFields(logrus.Fields{
		"version": gvk.Version,
		"kind":    gvk.Kind,
	})
	admit := newDelegateToV1AdmitHandler(h.controller.ReviewAdmission)
	ctx := req.Context()

	var responseObj runtime.Object
	switch *gvk {
	case admv1beta1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admv1beta1.AdmissionReview)
		if !ok {
			msg := fmt.Sprintf("Expected v1beta1.AdmissionReview but got: %T", obj)
			log.Error(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		responseAdmissionReview := &admv1beta1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		resp, err := admit.v1beta1(ctx, *requestedAdmissionReview)
		if err != nil {
			msg := fmt.Sprintf("Internal error occurred: %v", err)
			log.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		responseAdmissionReview.Response = resp
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	case admv1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admv1.AdmissionReview)
		if !ok {
			msg := fmt.Sprintf("Expected v1.AdmissionReview but got: %T", obj)
			log.Error(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		responseAdmissionReview := &admv1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		resp, err := admit.v1(ctx, *requestedAdmissionReview)
		if err != nil {
			msg := fmt.Sprintf("Internal error occurred: %v", err)
			log.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		responseAdmissionReview.Response = resp
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		log.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	log.Debugf("Sending response: %v", responseObj)

	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		log.Error(err)
	}
}
