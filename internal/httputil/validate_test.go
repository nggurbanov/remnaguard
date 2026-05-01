package httputil

import (
	"net/http"
	"testing"
)

func TestValidateRawRequestRejectsEncodedSlash(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/api/users%2fadmin", nil)
	req.RequestURI = "/api/users%2fadmin"
	if _, _, err := ValidateRawRequest(req, 2048, 4096); err == nil {
		t.Fatal("expected encoded slash to be rejected")
	}
}

func TestValidateRawRequestAcceptsCanonicalAPIPath(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/api/users/123?select=id", nil)
	req.RequestURI = "/api/users/123?select=id"
	path, query, err := ValidateRawRequest(req, 2048, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/users/123" || query != "select=id" {
		t.Fatalf("unexpected target: %q %q", path, query)
	}
}

func TestValidateQueryRejectsUnknownAndDuplicate(t *testing.T) {
	if err := ValidateQuery("includeHwid=true", []string{"includeHwid"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuery("includeHwid=true&includeHwid=false", []string{"includeHwid"}); err == nil {
		t.Fatal("expected duplicate query rejection")
	}
	if err := ValidateQuery("admin=true", []string{"includeHwid"}); err == nil {
		t.Fatal("expected unknown query rejection")
	}
}

func TestStripHopByHopRemovesConnectionNominatedHeaders(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "keep-alive, X-Custom-Hop")
	h.Set("X-Custom-Hop", "secret")
	h.Set("X-Forwarded-Port", "443")
	h.Set("Authorization", "Bearer keep")
	StripHopByHop(h)
	if h.Get("Connection") != "" || h.Get("X-Custom-Hop") != "" || h.Get("X-Forwarded-Port") != "" {
		t.Fatalf("hop-by-hop/forwarded headers not stripped: %#v", h)
	}
	if h.Get("Authorization") == "" {
		t.Fatal("end-to-end header was stripped")
	}
}
