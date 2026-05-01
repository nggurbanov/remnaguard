package contract

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/nggurbanov/remnaguard/internal/auth"
	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/server"
)

func TestReadOnlyRemnaGuardProxyContract(t *testing.T) {
	if os.Getenv("REMNAGUARD_CONTRACT_TESTS") != "1" {
		t.Skip("set REMNAGUARD_CONTRACT_TESTS=1 to run external RemnaGuard contract tests")
	}
	baseURL := strings.TrimRight(os.Getenv("REMNAGUARD_CONTRACT_BASE_URL"), "/")
	if baseURL == "" || os.Getenv("REMNAGUARD_CONTRACT_BEARER") == "" {
		t.Fatal("REMNAGUARD_CONTRACT_BASE_URL and REMNAGUARD_CONTRACT_BEARER are required")
	}
	if os.Getenv("REMNAGUARD_CONTRACT_ALLOW_PROD") != "1" && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		t.Fatal("refusing non-local contract target unless REMNAGUARD_CONTRACT_ALLOW_PROD=1 is set")
	}

	const pepper = "contract-pepper"
	const secret = "contract-secret"
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", pepper)

	cfg := config.Defaults()
	cfg.Upstream.BaseURL = baseURL
	cfg.Upstream.BearerEnv = "REMNAGUARD_CONTRACT_BEARER"
	cfg.Compatibility.AssumeVersion = "2.7.4"
	cfg.Audit.Stdout = false
	cfg.Tokens = []config.TokenPolicy{{
		ID:     "contract-privileged-readonly",
		Scopes: []string{"remnawave:*"},
		Credentials: []config.Credential{{
			ID:         "contract-cred",
			HMACSHA256: auth.Digest(secret, []byte(pepper)),
		}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	rt, err := server.NewRuntime(cfg, "contract", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range readOnlySmokePaths() {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RequestURI = path
		req.Header.Set("Authorization", "Bearer rg_contract-cred."+secret)
		rec := httptest.NewRecorder()
		rt.TestHandler().ServeHTTP(rec, req)
		if rec.Code < 200 || rec.Code >= 500 {
			t.Fatalf("unexpected RemnaGuard proxy status %d for GET %s: %s", rec.Code, path, rec.Body.String())
		}
	}
}
