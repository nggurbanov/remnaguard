package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nggurbanov/remnaguard/internal/auth"
	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/server"
)

func TestLocalStagingDestructiveContract(t *testing.T) {
	if os.Getenv("REMNAGUARD_DESTRUCTIVE_CONTRACT_TESTS") != "1" {
		t.Skip("set REMNAGUARD_DESTRUCTIVE_CONTRACT_TESTS=1 for local staging destructive contracts")
	}
	baseURL := strings.TrimRight(os.Getenv("REMNAGUARD_STAGING_BASE_URL"), "/")
	bearer := os.Getenv("REMNAGUARD_STAGING_BEARER")
	if bearer == "" && os.Getenv("REMNAGUARD_STAGING_BEARER_FILE") != "" {
		b, err := os.ReadFile(os.Getenv("REMNAGUARD_STAGING_BEARER_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		bearer = strings.TrimSpace(string(b))
	}
	if baseURL == "" || bearer == "" {
		t.Fatal("REMNAGUARD_STAGING_BASE_URL and REMNAGUARD_STAGING_BEARER or REMNAGUARD_STAGING_BEARER_FILE are required")
	}
	if !strings.HasPrefix(baseURL, "http://127.0.0.1:") && !strings.HasPrefix(baseURL, "http://localhost:") {
		t.Fatalf("destructive contract tests require local staging target, got %s", baseURL)
	}
	upstreamURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	stagingProxy := httptest.NewServer(stagingForwardedProxy(upstreamURL))
	defer stagingProxy.Close()

	const pepper = "destructive-pepper"
	const secret = "destructive-secret"
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", pepper)
	cfg := config.Defaults()
	cfg.Upstream.BaseURL = stagingProxy.URL
	cfg.Upstream.Bearer = bearer
	cfg.Upstream.AllowInsecureHTTP = true
	cfg.Compatibility.AssumeVersion = "2.7.4"
	cfg.Audit.Stdout = false
	cfg.WriteSafety.EnableRestrictedWrites = true
	cfg.WriteSafety.SingleWriter = true
	cfg.Tokens = []config.TokenPolicy{{
		ID:          "destructive-restricted",
		Scopes:      []string{"users:read", "users:create", "users:update", "users:action", "hwid:read", "hwid:write"},
		Constraints: config.Constraints{UsernamePrefix: "rg-contract-", MaxTrafficLimitBytes: 10 * 1024 * 1024, ForbidUnlimitedTraffic: true},
		Credentials: []config.Credential{{
			ID:         "destructive-cred",
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
	handler := rt.TestHandler()

	username := fmt.Sprintf("rg-contract-%d", time.Now().UnixNano())
	create := map[string]any{
		"username":             username,
		"expireAt":             time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"trafficLimitBytes":    1048576,
		"trafficLimitStrategy": "NO_RESET",
		"description":          "remnaguard local destructive contract",
	}
	createRes := rgRequest(t, handler, http.MethodPost, "/api/users", create)
	if createRes.Code < 200 || createRes.Code >= 300 {
		t.Fatalf("create user failed: %d %s", createRes.Code, createRes.Body.String())
	}
	uuid := jsonPathString(t, createRes.Body.Bytes(), "response", "uuid")
	if uuid == "" {
		uuid = jsonPathString(t, createRes.Body.Bytes(), "uuid")
	}
	if uuid == "" {
		t.Fatalf("create response did not include uuid: %s", createRes.Body.String())
	}
	defer rgRequest(t, handler, http.MethodDelete, "/api/users/"+uuid, nil)

	readRes := rgRequest(t, handler, http.MethodGet, "/api/users/by-username/"+username, nil)
	if readRes.Code < 200 || readRes.Code >= 300 {
		t.Fatalf("read by username failed: %d %s", readRes.Code, readRes.Body.String())
	}

	update := map[string]any{"uuid": uuid, "description": "remnaguard contract updated", "trafficLimitBytes": 2097152}
	updateRes := rgRequest(t, handler, http.MethodPatch, "/api/users", update)
	if updateRes.Code < 200 || updateRes.Code >= 300 {
		t.Fatalf("update user failed: %d %s", updateRes.Code, updateRes.Body.String())
	}

	actionRes := rgRequest(t, handler, http.MethodPost, "/api/users/"+uuid+"/actions/reset-traffic", nil)
	if actionRes.Code < 200 || actionRes.Code >= 300 {
		t.Fatalf("reset traffic failed: %d %s", actionRes.Code, actionRes.Body.String())
	}

	hwidBody := map[string]any{"userUuid": uuid, "hwid": "rg-contract-hwid", "platform": "test", "deviceModel": "contract"}
	hwidCreate := rgRequest(t, handler, http.MethodPost, "/api/hwid/devices", hwidBody)
	if hwidCreate.Code < 200 || hwidCreate.Code >= 300 {
		t.Fatalf("hwid create failed: %d %s", hwidCreate.Code, hwidCreate.Body.String())
	}
	hwidList := rgRequest(t, handler, http.MethodGet, "/api/hwid/devices/"+uuid, nil)
	if hwidList.Code < 200 || hwidList.Code >= 300 {
		t.Fatalf("hwid list failed: %d %s", hwidList.Code, hwidList.Body.String())
	}
	hwidDelete := rgRequest(t, handler, http.MethodPost, "/api/hwid/devices/delete", map[string]any{"userUuid": uuid, "hwid": "rg-contract-hwid"})
	if hwidDelete.Code < 200 || hwidDelete.Code >= 300 {
		t.Fatalf("hwid delete failed: %d %s", hwidDelete.Code, hwidDelete.Body.String())
	}
}

func stagingForwardedProxy(target *url.URL) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", target.Host)
			pr.Out.Header.Set("X-Forwarded-For", "127.0.0.1")
		},
	}
	return rp
}

func rgRequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RequestURI = path
	req.Header.Set("Authorization", "Bearer rg_destructive-cred.destructive-secret")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func jsonPathString(t *testing.T, body []byte, path ...string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	cur := v
	for _, part := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[part]
	}
	s, _ := cur.(string)
	return s
}
