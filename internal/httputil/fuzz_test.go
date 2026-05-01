package httputil

import (
	"net/http"
	"testing"
)

func FuzzValidateRawRequest(f *testing.F) {
	f.Add("/api/users/00000000-0000-0000-0000-000000000000")
	f.Add("/api/users%2fadmin")
	f.Add("/api/../admin")
	f.Fuzz(func(t *testing.T, target string) {
		req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "example.test"
		req.RequestURI = target
		_, _, _ = ValidateRawRequest(req, 2048, 4096)
	})
}
