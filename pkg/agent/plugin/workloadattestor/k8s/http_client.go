package k8s

import "net/http"

type httpClient interface {
	Get(url string) (resp *http.Response, err error)
}
