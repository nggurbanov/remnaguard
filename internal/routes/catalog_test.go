package routes

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestCatalogDeniesUnknownByNoMatch(t *testing.T) {
	if _, ok := Match(Catalog("2.7.4"), http.MethodDelete, "/api/nodes"); ok {
		t.Fatal("unexpected route match")
	}
}

func TestPublicSubscriptionRoute(t *testing.T) {
	route, ok := Match(Catalog("2.7.4"), http.MethodGet, "/api/sub/abcdef/sing-box")
	if !ok {
		t.Fatal("route not found")
	}
	if route.Support != PublicSubscription {
		t.Fatalf("unexpected support: %s", route.Support)
	}
}

func TestCatalogMetadataIsStrictClean(t *testing.T) {
	res := validateCatalog(Catalog("2.7.4"))
	if len(res.Invalid) > 0 || len(res.Duplicates) > 0 {
		t.Fatalf("invalid catalog metadata: invalid=%v duplicates=%v", res.Invalid, res.Duplicates)
	}
}

func TestOpenAPIStrictAgainstLocalFixture(t *testing.T) {
	spec := "testdata/remnawave-2.7.4-openapi-min.json"
	res, err := CheckOpenAPIStrict(spec, Catalog("2.7.4"))
	if err != nil {
		t.Fatalf("strict OpenAPI check failed: %v; unknown=%d removed=%d invalid=%d ambiguous=%d duplicates=%d", err, len(res.Unknown), len(res.Removed), len(res.Invalid), len(res.Ambiguous), len(res.Duplicates))
	}
	if res.Coverage != 100 {
		t.Fatalf("coverage = %.2f, want 100", res.Coverage)
	}
}

func TestOpenAPIStrictAgainstPinnedOperationFixture(t *testing.T) {
	spec := writeMinimalOpenAPISpec(t, remnawave274Operations)
	res, err := CheckOpenAPIStrict(spec, Catalog("2.7.4"))
	if err != nil {
		t.Fatalf("strict OpenAPI check failed: %v; unknown=%d removed=%d invalid=%d ambiguous=%d duplicates=%d", err, len(res.Unknown), len(res.Removed), len(res.Invalid), len(res.Ambiguous), len(res.Duplicates))
	}
	if len(res.Covered) != 185 || res.Coverage != 100 {
		t.Fatalf("covered=%d coverage=%.2f, want 185 and 100", len(res.Covered), res.Coverage)
	}
}

func TestActualRemnawave274Routes(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/system/stats/bandwidth"},
		{http.MethodGet, "/api/hwid/devices/00000000-0000-0000-0000-000000000000"},
		{http.MethodPatch, "/api/users"},
		{http.MethodPost, "/api/users/00000000-0000-0000-0000-000000000000/actions/reset-traffic"},
	} {
		if _, ok := Match(Catalog("2.7.4"), tc.method, tc.path); !ok {
			t.Fatalf("route not found: %s %s", tc.method, tc.path)
		}
	}
}

func writeMinimalOpenAPISpec(t *testing.T, operations string) string {
	t.Helper()
	methods := map[string]map[string]bool{}
	for _, line := range strings.Split(operations, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		method, path, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("invalid operation line %q", line)
		}
		if methods[path] == nil {
			methods[path] = map[string]bool{}
		}
		methods[path][strings.ToLower(method)] = true
	}
	var b strings.Builder
	b.WriteString(`{"openapi":"3.0.0","paths":{`)
	firstPath := true
	for path, ms := range methods {
		if !firstPath {
			b.WriteByte(',')
		}
		firstPath = false
		fmt.Fprintf(&b, "%q:{", path)
		firstMethod := true
		for method := range ms {
			if !firstMethod {
				b.WriteByte(',')
			}
			firstMethod = false
			fmt.Fprintf(&b, "%q:{}", method)
		}
		b.WriteByte('}')
	}
	b.WriteString(`}}`)
	file := t.TempDir() + "/openapi.json"
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}
