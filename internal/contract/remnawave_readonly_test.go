package contract

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyRemnawaveContract(t *testing.T) {
	if os.Getenv("REMNAGUARD_CONTRACT_TESTS") != "1" {
		t.Skip("set REMNAGUARD_CONTRACT_TESTS=1 to run external Remnawave contract tests")
	}
	baseURL := strings.TrimRight(os.Getenv("REMNAGUARD_CONTRACT_BASE_URL"), "/")
	bearer := os.Getenv("REMNAGUARD_CONTRACT_BEARER")
	if baseURL == "" || bearer == "" {
		t.Fatal("REMNAGUARD_CONTRACT_BASE_URL and REMNAGUARD_CONTRACT_BEARER are required")
	}
	if os.Getenv("REMNAGUARD_CONTRACT_ALLOW_PROD") != "1" && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		t.Fatal("refusing non-local contract target unless REMNAGUARD_CONTRACT_ALLOW_PROD=1 is set")
	}

	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for _, path := range readOnlySmokePaths() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept-Encoding", "identity")
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 500 {
			t.Fatalf("GET %s returned unexpected status %d", path, res.StatusCode)
		}
	}
}

func readOnlySmokePaths() []string {
	return []string{
		"/api/system/health",
		"/api/system/metadata",
		"/api/system/stats",
		"/api/system/stats/bandwidth",
		"/api/remnawave-settings",
		"/api/users",
		"/api/nodes",
		"/api/hosts",
		"/api/config-profiles",
		"/api/internal-squads",
		"/api/external-squads",
		"/api/subscription-settings",
		"/api/subscription-page-configs",
		"/api/subscription-templates",
		"/api/tokens",
		"/api/hwid/devices",
	}
}
