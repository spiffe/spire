package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1beta1 "k8s.io/api/admission/v1beta1"
)

func TestHandler(t *testing.T) {
	controller := newFakeController()
	handler := NewWebhookHandler(controller)

	testCases := []struct {
		name       string
		method     string
		path       string
		reqHeader  http.Header
		reqBody    string
		status     int
		respHeader http.Header
		respBody   string
	}{
		{
			name:     "wrong path",
			method:   "POST",
			path:     "/whatever",
			status:   http.StatusNotFound,
			respBody: "Not found\n",
		},
		{
			name:     "not a POST",
			method:   "GET",
			path:     "/validate",
			status:   http.StatusMethodNotAllowed,
			respBody: "Expected POST\n",
		},
		{
			name:     "no JSON content type header",
			method:   "POST",
			path:     "/validate",
			status:   http.StatusBadRequest,
			respBody: "Expected JSON content\n",
		},
		{
			name:   "malformed JSON content",
			status: http.StatusBadRequest,
			method: "POST",
			path:   "/validate",
			reqHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			respBody: "Malformed JSON body\n",
		},
		{
			name:   "missing request",
			status: http.StatusBadRequest,
			method: "POST",
			path:   "/validate",
			reqHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			reqBody:  "{}",
			respBody: "AdmissionReview is missing request\n",
		},
		{
			name:   "success",
			status: http.StatusOK,
			method: "POST",
			path:   "/validate",
			reqHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			reqBody: "{\"request\": {\"uid\":\"UID\"}}",
			respHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			respBody: "{\"response\":{\"uid\":\"UID\",\"allowed\":true}}\n",
		},
		{
			name:   "failure",
			status: http.StatusInternalServerError,
			method: "POST",
			path:   "/validate",
			reqHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			reqBody:  "{\"request\": {\"uid\":\"FAILME\"}}",
			respBody: "Request could not be processed\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			u := url.URL{
				Scheme: "http",
				Host:   "localhost",
				Path:   testCase.path,
			}
			req, err := http.NewRequest(testCase.method, u.String(), strings.NewReader(testCase.reqBody))
			req.Header = testCase.reqHeader
			require.NoError(t, err)

			respBody := new(bytes.Buffer)
			w := httptest.NewRecorder()
			w.Body = respBody
			handler.ServeHTTP(w, req)

			resp := w.Result()
			assert.Equal(t, testCase.status, resp.StatusCode)
			if testCase.respHeader != nil {
				assert.Equal(t, testCase.respHeader, resp.Header)
			}
			assert.Equal(t, testCase.respBody, respBody.String())
		})
	}
}

type fakeController struct{}

func newFakeController() *fakeController {
	return &fakeController{}
}

func (*fakeController) ReviewAdmission(ctx context.Context, req *admv1beta1.AdmissionRequest) (*admv1beta1.AdmissionResponse, error) {
	if req.UID == "FAILME" {
		return nil, errors.New("OHNO!")
	}
	return &admv1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}, nil
}
