package main

import (
	"context"
	"encoding/json"
	"net/http"

	admv1beta1 "k8s.io/api/admission/v1beta1"
)

type AdmissionController interface {
	ReviewAdmission(context.Context, *admv1beta1.AdmissionRequest) (*admv1beta1.AdmissionResponse, error)
}

type WebhookHandler struct {
	controller AdmissionController
}

func NewWebhookHandler(controller AdmissionController) *WebhookHandler {
	return &WebhookHandler{
		controller: controller,
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

	var in admv1beta1.AdmissionReview
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, "Malformed JSON body", http.StatusBadRequest)
		return
	}

	if in.Request == nil {
		http.Error(w, "AdmissionReview is missing request", http.StatusBadRequest)
		return
	}

	out, err := h.controller.ReviewAdmission(req.Context(), in.Request)
	if err != nil {
		http.Error(w, "Request could not be processed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(admv1beta1.AdmissionReview{
		Response: out,
	})
}
