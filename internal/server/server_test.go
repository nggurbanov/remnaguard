package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nggurbanov/remnaguard/internal/auth"
	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestSingletonUserReadResponseOwnershipGate(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer root" {
			t.Fatalf("unexpected upstream auth %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"uuid":"00000000-0000-0000-0000-000000000000","username":"foreign-user"}}`))
	}))
	defer upstream.Close()

	rt, err := NewRuntime(testConfig(upstream.URL, "secret"), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/users/00000000-0000-0000-0000-000000000000", nil)
	req.RequestURI = "/api/users/00000000-0000-0000-0000-000000000000"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPrivilegedRepresentativeRoutesProxy(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer root" {
			t.Fatalf("unexpected upstream auth %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"body":` + stringOrNull(body) + `}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = []string{"remnawave:*"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method string
		target string
		body   []byte
	}{
		{http.MethodGet, "/api/config-profiles?page=1", nil},
		{http.MethodGet, "/api/nodes", nil},
		{http.MethodPatch, "/api/remnawave-settings", []byte(`{"anyDocumentedField":true}`)},
		{http.MethodPost, "/api/system/tools/happ/encrypt", []byte(`{"payload":"x"}`)},
		{http.MethodPut, "/api/metadata/user/00000000-0000-0000-0000-000000000000", []byte(`{"k":"v"}`)},
	} {
		req := httptest.NewRequest(tc.method, tc.target, bytes.NewReader(tc.body))
		req.RequestURI = tc.target
		if tc.body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer rg_cred.secret")
		rec := httptest.NewRecorder()
		rt.apiHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s got %d: %s", tc.method, tc.target, rec.Code, rec.Body.String())
		}
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 upstream calls, got %d", len(seen))
	}
}

func TestRestrictedCannotCallPrivilegedRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("restricted privileged request must not reach upstream")
	}))
	defer upstream.Close()
	rt, err := NewRuntime(testConfig(upstream.URL, "secret"), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.RequestURI = "/api/nodes"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestReloadRerunsVersionDetection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/system/metadata" {
			_, _ = w.Write([]byte(`{"version":"2.7.4"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Compatibility.AssumeVersion = ""
	cfg.Upstream.VersionPath = "/api/system/metadata"
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.state.Load().versionOK.Load() {
		t.Fatal("version guard should start closed before detection")
	}
	if err := rt.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !rt.state.Load().versionOK.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !rt.state.Load().versionOK.Load() {
		t.Fatal("reload did not rerun version detection")
	}
}

func TestRequestUsesSingleRuntimeStateAcrossReload(t *testing.T) {
	releaseOld := make(chan struct{})
	oldUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-releaseOld
		w.Header().Set("X-Upstream", "old")
		_, _ = w.Write([]byte("old"))
	}))
	defer oldUpstream.Close()
	newUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream", "new")
		_, _ = w.Write([]byte("new"))
	}))
	defer newUpstream.Close()

	cfg := testConfig(oldUpstream.URL, "secret")
	cfg.Tokens[0].Scopes = []string{"remnawave:*"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.RequestURI = "/api/nodes"
		req.Header.Set("Authorization", "Bearer rg_cred.secret")
		rec := httptest.NewRecorder()
		rt.apiHandler().ServeHTTP(rec, req)
		done <- rec
	}()
	time.Sleep(20 * time.Millisecond)
	next := testConfig(newUpstream.URL, "secret")
	next.Tokens[0].Scopes = []string{"remnawave:*"}
	if err := rt.Reload(next); err != nil {
		t.Fatal(err)
	}
	close(releaseOld)
	rec := <-done
	if rec.Header().Get("X-Upstream") != "old" || rec.Body.String() != "old" {
		t.Fatalf("request mixed runtime state: header=%q body=%q", rec.Header().Get("X-Upstream"), rec.Body.String())
	}
}

func TestReloadSwapsConcurrencyLimits(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Limits.GlobalConcurrency = 2
	cfg.Tokens[0].Scopes = []string{"remnawave:*"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	next := testConfig(upstream.URL, "secret")
	next.Limits.GlobalConcurrency = 1
	next.Tokens[0].Scopes = []string{"remnawave:*"}
	if err := rt.Reload(next); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.RequestURI = "/api/nodes"
		req.Header.Set("Authorization", "Bearer rg_cred.secret")
		rec := httptest.NewRecorder()
		close(started)
		rt.apiHandler().ServeHTTP(rec, req)
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.RequestURI = "/api/nodes"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	close(release)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected reloaded global concurrency limit, got %d", rec.Code)
	}
}

func TestOldVersionDetectionCannotCloseReloadedState(t *testing.T) {
	releaseOld := make(chan struct{})
	oldUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-releaseOld
		_, _ = w.Write([]byte(`{"version":"0.0.0"}`))
	}))
	defer oldUpstream.Close()

	cfg := testConfig(oldUpstream.URL, "secret")
	cfg.Compatibility.AssumeVersion = ""
	cfg.Upstream.VersionPath = "/api/system/metadata"
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	oldState := rt.state.Load()
	go rt.detectVersion(context.Background(), oldState)

	next := testConfig(oldUpstream.URL, "secret")
	next.Compatibility.AssumeVersion = "2.7.4"
	if err := rt.Reload(next); err != nil {
		t.Fatal(err)
	}
	close(releaseOld)
	time.Sleep(50 * time.Millisecond)
	if !rt.state.Load().versionOK.Load() {
		t.Fatal("old version detection changed current readiness")
	}
}

func TestPrivilegedBodyLimitAppliesToUnknownSizeBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("oversized privileged body must not reach upstream")
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Limits.MaxBodyBytes = 8
	cfg.Tokens[0].Scopes = []string{"remnawave:*"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/system/testers/srr-matcher", io.NopCloser(bytes.NewBufferString("0123456789abcdef")))
	req.RequestURI = "/api/system/testers/srr-matcher"
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on oversized streamed body, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublicSubscriptionBodyLimitAppliesBeforeProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("oversized public subscription body must not reach upstream")
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.PublicSubs.Enabled = true
	cfg.Limits.MaxBodyBytes = 8
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/sub/abcdef/sing-box", io.NopCloser(bytes.NewBufferString("0123456789abcdef")))
	req.RequestURI = "/api/sub/abcdef/sing-box"
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNewRuntimeFailsOnInvalidTLSConfig(t *testing.T) {
	cfg := testConfig("https://example.test", "secret")
	cfg.Upstream.CustomCAFile = t.TempDir() + "/missing-ca.pem"
	if _, err := NewRuntime(cfg, "test", ""); err == nil {
		t.Fatal("expected invalid custom CA to fail closed")
	}
}

func TestUpstreamResponseLimitReturnsGatewayError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0123456789abcdef"))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Limits.UpstreamBodyBytes = 8
	cfg.Tokens[0].Scopes = []string{"remnawave:*"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.RequestURI = "/api/nodes"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway for oversized upstream response, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRestrictedWriteCacheBodyIsLimited(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("oversized restricted write must not reach upstream")
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Limits.MaxBodyBytes = 8
	cfg.WriteSafety.EnableRestrictedWrites = true
	cfg.WriteSafety.SingleWriter = true
	cfg.Tokens[0].Scopes = []string{"users:create"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/users", io.NopCloser(bytes.NewBufferString(`{"username":"restricted-a"}`)))
	req.RequestURI = "/api/users"
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized restricted write, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublicSubscriptionStripsUnsafeHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("public subscription leaked authorization")
		}
		if r.Header.Get("X-Unsafe") != "" {
			t.Fatalf("public subscription forwarded unsafe header")
		}
		w.Header().Set("Set-Cookie", "secret=1")
		w.Header().Set("Subscription-Userinfo", "upload=0; download=0")
		_, _ = w.Write([]byte("sub"))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.PublicSubs.Enabled = true
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/sub/abcdef/sing-box", nil)
	req.RequestURI = "/api/sub/abcdef/sing-box"
	req.Header.Set("Authorization", "Bearer should-not-forward")
	req.Header.Set("X-Unsafe", "1")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("unsafe response header was forwarded")
	}
	if rec.Header().Get("Subscription-Userinfo") == "" {
		t.Fatal("safe subscription header missing")
	}
}

func TestAllForwardedHeadersAreStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
				t.Fatalf("forwarded header reached upstream: %s", name)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = []string{"remnawave:*"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.RequestURI = "/api/nodes"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	req.Header.Set("X-Forwarded-Port", "443")
	req.Header.Set("X-Forwarded-Prefix", "/prefix")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRestrictedUserCreateValidatesSquadsAndPostWriteOwnership(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"uuid":"u","username":"tenant-a","activeInternalSquads":[{"uuid":"internal-a"}],"externalSquadUuid":"external-a"}}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.WriteSafety.EnableRestrictedWrites = true
	cfg.WriteSafety.SingleWriter = true
	cfg.Tokens[0].Scopes = []string{"users:create"}
	cfg.Tokens[0].Constraints = config.Constraints{
		UsernamePrefix:        "tenant-",
		AllowedInternalSquads: []string{"internal-a"},
		AllowedExternalSquads: []string{"external-a"},
	}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"username":"tenant-a","activeInternalSquads":["internal-a"],"externalSquadUuid":"external-a"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.RequestURI = "/api/users"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected allowed create, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upstreamCalls)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"username":"tenant-b","activeInternalSquads":["internal-b"]}`))
	req.RequestURI = "/api/users"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected foreign squad denial, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 1 {
		t.Fatalf("denied create reached upstream")
	}
}

func TestRestrictedWriteDeniedWithoutExactScope(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("missing-scope write must not reach upstream")
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL, "secret")
	cfg.WriteSafety.EnableRestrictedWrites = true
	cfg.WriteSafety.SingleWriter = true
	cfg.Tokens[0].Scopes = []string{"users:read"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"username":"restricted-a"}`))
	req.RequestURI = "/api/users"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenSpecificAllowedRequestFields(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("denied request field must not reach upstream")
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL, "secret")
	cfg.WriteSafety.EnableRestrictedWrites = true
	cfg.WriteSafety.SingleWriter = true
	cfg.Tokens[0].Scopes = []string{"users:create"}
	cfg.Tokens[0].Constraints.AllowedRequestFields = map[string][]string{"user.create": {"username"}}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"username":"restricted-a","email":"a@example.com"}`))
	req.RequestURI = "/api/users"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected request field denial, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserListResponseIsFiltered(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"users":[{"uuid":"u1","username":"restricted-a"},{"uuid":"u2","username":"foreign-b"}],"total":2}}`))
	}))
	defer upstream.Close()
	rt, err := NewRuntime(testConfig(upstream.URL, "secret"), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/users?page=1", nil)
	req.RequestURI = "/api/users?page=1"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "restricted-a") || strings.Contains(rec.Body.String(), "foreign-b") {
		t.Fatalf("unexpected filtered body: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("expected redacted total, got %s", rec.Body.String())
	}
}

func TestSquadListResponseIsFiltered(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":[{"uuid":"internal-a","name":"A"},{"uuid":"internal-b","name":"B"}],"count":2}`))
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = append(cfg.Tokens[0].Scopes, "squads:read")
	cfg.Tokens[0].Constraints.AllowedInternalSquads = []string{"internal-a"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/internal-squads", nil)
	req.RequestURI = "/api/internal-squads"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "internal-a") || strings.Contains(rec.Body.String(), "internal-b") {
		t.Fatalf("unexpected filtered body: %s", rec.Body.String())
	}
}

func testConfig(upstreamURL, secret string) *config.Config {
	_ = os.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	cfg := config.Defaults()
	cfg.Upstream.BaseURL = upstreamURL
	cfg.Upstream.Bearer = "root"
	cfg.Upstream.AllowInsecureHTTP = true
	cfg.Compatibility.AssumeVersion = "2.7.4"
	cfg.Audit.Stdout = false
	cfg.Tokens = []config.TokenPolicy{{
		ID:          "restricted",
		Scopes:      []string{"users:read", "hwid:read"},
		Constraints: config.Constraints{UsernamePrefix: "restricted-"},
		Credentials: []config.Credential{{ID: "cred", HMACSHA256: auth.Digest(secret, []byte("pepper"))}},
	}}
	return cfg
}

func stringOrNull(body []byte) string {
	if len(body) == 0 {
		return "null"
	}
	return string(body)
}
