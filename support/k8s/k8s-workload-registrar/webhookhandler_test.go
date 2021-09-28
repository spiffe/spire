package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
)

func TestHandler(t *testing.T) {
	log, _ := test.NewNullLogger()
	controller := newFakeController()
	handler := NewWebhookHandler(log, controller)

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
			respBody: "Malformed JSON body: Object 'Kind' is missing in ''\n",
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
			respBody: "Malformed JSON body: Object 'Kind' is missing in '{}'\n",
		},
		{
			name:   "success",
			status: http.StatusOK,
			method: "POST",
			path:   "/validate",
			reqHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			reqBody: `{ "apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": { "uid": "0df28fbd-5f5f-11e8-bc74-36e6bb280816" } }`,
			respHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			respBody: "{\"kind\":\"AdmissionReview\",\"apiVersion\":\"admission.k8s.io/v1\",\"response\":{\"uid\":\"0df28fbd-5f5f-11e8-bc74-36e6bb280816\",\"allowed\":true}}",
		},
		{
			name:   "failure",
			status: http.StatusBadRequest,
			method: "POST",
			path:   "/validate",
			reqHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			reqBody:  "{\"request\": {\"uid\":\"FAILME\"}}",
			respBody: "Malformed JSON body: Object 'Kind' is missing in '{\"request\": {\"uid\":\"FAILME\"}}'\n",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			u := url.URL{
				Scheme: "http",
				Host:   "localhost",
				Path:   testCase.path,
			}
			req, err := http.NewRequest(testCase.method, u.String(), strings.NewReader(testCase.reqBody))
			req.Header = testCase.reqHeader
			require.NoError(t, err)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, testCase.status, resp.StatusCode)
			if testCase.respHeader != nil {
				assert.Equal(t, testCase.respHeader, resp.Header)
			}
			assert.Equal(t, testCase.respBody, w.Body.String())
		})
	}
}

type fakeController struct{}

func newFakeController() *fakeController {
	return &fakeController{}
}

func (*fakeController) ReviewAdmission(ctx context.Context, ar admv1.AdmissionReview) (*admv1.AdmissionResponse, error) {
	if ar.Request.UID == "FAILME" {
		return nil, errors.New("ohno")
	}
	return &admv1.AdmissionResponse{
		UID:     ar.Request.UID,
		Allowed: true,
	}, nil
}
