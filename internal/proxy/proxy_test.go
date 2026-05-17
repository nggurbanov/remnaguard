package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestWriteResponseDropsProtectedResponseHeaders(t *testing.T) {
	cfg := config.Defaults()
	p := &Proxy{cfg: cfg}
	res := &Response{
		StatusCode: http.StatusFound,
		Header: http.Header{
			"Content-Type":       []string{"application/json"},
			"Location":           []string{"https://upstream.internal/login"},
			"Set-Cookie":         []string{"sid=secret"},
			"Authorization":      []string{"Bearer secret"},
			"Proxy-Authenticate": []string{"Basic realm=upstream"},
			"X-Debug-Token":      []string{"debug-secret"},
		},
		Body: []byte(`{"ok":true}`),
	}

	rec := httptest.NewRecorder()
	p.WriteResponse(rec, res, false)

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected safe content type to pass through, got %q", got)
	}
	for _, name := range []string{"Location", "Set-Cookie", "Authorization", "Proxy-Authenticate", "X-Debug-Token"} {
		if got := rec.Header().Get(name); got != "" {
			t.Fatalf("expected %s to be stripped, got %q", name, got)
		}
	}
}
