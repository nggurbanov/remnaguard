package testutil

import (
	"net/http"
	"net/http/httptest"
)

func NewUpstream(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}
