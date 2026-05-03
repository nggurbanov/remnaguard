package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
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

func TestEmptyUserReadResponsePassesThrough(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":[]}`))
	}))
	defer upstream.Close()

	rt, err := NewRuntime(testConfig(upstream.URL, "secret"), "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/users/by-telegram-id/1000000900000000", nil)
	req.RequestURI = "/api/users/by-telegram-id/1000000900000000"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected empty user response to pass through, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"response":[]`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
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
		_, _ = w.Write([]byte(`{"response":{"uuid":"u","username":"tenant-a","activeInternalSquads":[{"uuid":"11111111-1111-4111-8111-111111111111"}],"externalSquadUuid":"external-a"}}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.WriteSafety.EnableRestrictedWrites = true
	cfg.WriteSafety.SingleWriter = true
	cfg.Tokens[0].Scopes = []string{"users:create"}
	cfg.Tokens[0].Constraints = config.Constraints{
		UsernamePrefix:        "tenant-",
		AllowedInternalSquads: []string{"11111111-1111-4111-8111-111111111111"},
		AllowedExternalSquads: []string{"external-a"},
	}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"username":"tenant-a","activeInternalSquads":["11111111-1111-4111-8111-111111111111"],"externalSquadUuid":"external-a"}`
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

	req = httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"username":"tenant-b","activeInternalSquads":["22222222-2222-4222-8222-222222222222"]}`))
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
		_, _ = w.Write([]byte(`{"response":{"total":2,"internalSquads":[{"uuid":"11111111-1111-4111-8111-111111111111","name":"A","rawInbound":{"privateKey":"secret"}},{"uuid":"22222222-2222-4222-8222-222222222222","name":"B","rawInbound":{"privateKey":"secret"}}]}}`))
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = append(cfg.Tokens[0].Scopes, "squads:read")
	cfg.Tokens[0].Constraints.AllowedInternalSquads = []string{"11111111-1111-4111-8111-111111111111"}
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
	if !strings.Contains(rec.Body.String(), "11111111-1111-4111-8111-111111111111") || strings.Contains(rec.Body.String(), "22222222-2222-4222-8222-222222222222") {
		t.Fatalf("unexpected filtered body: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "rawInbound") || strings.Contains(rec.Body.String(), "privateKey") {
		t.Fatalf("sensitive squad fields were not redacted: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("expected redacted total, got %s", rec.Body.String())
	}
}

func TestSquadDetailResponseIsRedacted(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"uuid":"11111111-1111-4111-8111-111111111111","name":"A","viewPosition":1,"inbounds":[{"tag":"node"}],"rawInbound":{"privateKey":"secret"}}}`))
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = append(cfg.Tokens[0].Scopes, "squads:read")
	cfg.Tokens[0].Constraints.AllowedInternalSquads = []string{"11111111-1111-4111-8111-111111111111"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/internal-squads/11111111-1111-4111-8111-111111111111", nil)
	req.RequestURI = "/api/internal-squads/11111111-1111-4111-8111-111111111111"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "11111111-1111-4111-8111-111111111111") || !strings.Contains(rec.Body.String(), `"name":"A"`) {
		t.Fatalf("unexpected redacted body: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "inbounds") || strings.Contains(rec.Body.String(), "privateKey") {
		t.Fatalf("sensitive squad detail fields were not redacted: %s", rec.Body.String())
	}
}

func TestAuthenticatedSubscriptionRouteWorksWhenPublicDisabled(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer root" {
			t.Fatalf("unexpected upstream auth %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() != "/api/sub/abcdef/info" {
			t.Fatalf("unexpected upstream uri %q", r.URL.RequestURI())
		}
		_, _ = w.Write([]byte(`{"response":{"username":"restricted-a"}}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.PublicSubs.Enabled = false
	cfg.Tokens[0].Scopes = []string{"subscriptions:read"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/sub/abcdef/info", nil)
	req.RequestURI = "/api/sub/abcdef/info"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubscriptionRouteWithoutAuthStillRequiresPublicMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("unauthenticated disabled public subscription must not reach upstream")
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.PublicSubs.Enabled = false
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/sub/abcdef/info", nil)
	req.RequestURI = "/api/sub/abcdef/info"
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubscriptionPageConfigListIsFiltered(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	allowed := "11111111-1111-4111-8111-111111111111"
	foreign := "22222222-2222-4222-8222-222222222222"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/api/subscription-page-configs/" {
			t.Fatalf("unexpected upstream uri %q", r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"configs":[{"uuid":"` + allowed + `","name":"Bat"},{"uuid":"` + foreign + `","name":"Redivo"}],"total":2}}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = []string{"subscription-pages:read"}
	cfg.Tokens[0].Constraints.AllowedSubscriptionPageConfigs = []string{allowed}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/subscription-page-configs/", nil)
	req.RequestURI = "/api/subscription-page-configs/"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), allowed) || strings.Contains(rec.Body.String(), foreign) {
		t.Fatalf("unexpected filtered body: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("expected redacted total, got %s", rec.Body.String())
	}
}

func TestSubscriptionPageConfigDetailIsDeniedOutsideAllowlist(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	allowed := "11111111-1111-4111-8111-111111111111"
	foreign := "22222222-2222-4222-8222-222222222222"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"uuid":"` + foreign + `","name":"Redivo"}}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = []string{"subscription-pages:read"}
	cfg.Tokens[0].Constraints.AllowedSubscriptionPageConfigs = []string{allowed}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/subscription-page-configs/"+foreign, nil)
	req.RequestURI = "/api/subscription-page-configs/" + foreign
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubscriptionSubpageConfigProxiesReadOnlyResponse(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"theme":"bat"}}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL, "secret")
	cfg.Tokens[0].Scopes = []string{"subscriptions:read"}
	cfg.Tokens[0].Constraints.AllowedSubscriptionPageConfigs = []string{"11111111-1111-4111-8111-111111111111"}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/subscriptions/subpage-config/abcdef", nil)
	req.RequestURI = "/api/subscriptions/subpage-config/abcdef"
	req.Header.Set("Authorization", "Bearer rg_cred.secret")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPanelAuthFacadeStatusAndAuthorizeDoNotProxy(t *testing.T) {
	rt, upstreamCalls := newPanelFacadeRuntimeCountingUpstream(t)

	statusReq := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	statusReq.RequestURI = "/api/auth/status"
	statusRec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status got %d: %s", statusRec.Code, statusRec.Body.String())
	}
	assertJSONMatchesFixture(t, statusRec.Body.Bytes(), "status_telegram_only.json")

	authorizeReq := httptest.NewRequest(http.MethodPost, "/api/auth/oauth2/authorize", strings.NewReader(`{"provider":"telegram"}`))
	authorizeReq.RequestURI = "/api/auth/oauth2/authorize"
	authorizeReq.Header.Set("Content-Type", "application/json")
	authorizeRec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(authorizeRec, authorizeReq)
	if authorizeRec.Code != http.StatusOK {
		t.Fatalf("authorize got %d: %s", authorizeRec.Code, authorizeRec.Body.String())
	}
	assertJSONMatchesFixture(t, authorizeRec.Body.Bytes(), "oauth2_authorize_telegram.response.json")
	if *upstreamCalls != 0 {
		t.Fatalf("panel auth facade status/authorize reached upstream %d time(s)", *upstreamCalls)
	}
}

func TestPanelAuthFacadeUnsupportedAuthMethodsReturnDisabledJSONAndDoNotProxy(t *testing.T) {
	rt, upstreamCalls := newPanelFacadeRuntimeCountingUpstream(t)
	tests := []struct {
		name    string
		method  string
		target  string
		body    string
		fixture string
	}{
		{name: "password login", method: http.MethodPost, target: "/api/auth/login", body: `{"username":"alice","password":"password"}`, fixture: "unsupported_login.response.json"},
		{name: "register", method: http.MethodPost, target: "/api/auth/register", body: `{"username":"alice","password":"password"}`, fixture: "unsupported_register.response.json"},
		{name: "passkey options", method: http.MethodGet, target: "/api/auth/passkey/authentication/options", fixture: "unsupported_passkey_options.response.json"},
		{name: "passkey verify", method: http.MethodPost, target: "/api/auth/passkey/authentication/verify", body: `{"response":{"id":"passkey"}}`, fixture: "unsupported_passkey_verify.response.json"},
		{name: "github authorize", method: http.MethodPost, target: "/api/auth/oauth2/authorize", body: `{"provider":"github"}`, fixture: "unsupported_oauth2_github_authorize.response.json"},
		{name: "github callback", method: http.MethodPost, target: "/api/auth/oauth2/callback", body: `{"provider":"github","code":"code","state":"state"}`, fixture: "unsupported_oauth2_github_callback.response.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			req.RequestURI = tc.target
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			rt.apiHandler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("got %d want 403: %s", rec.Code, rec.Body.String())
			}
			assertJSONMatchesFixture(t, rec.Body.Bytes(), tc.fixture)
			assertJSONKeyAbsent(t, rec.Body.Bytes(), "accessToken")
			if *upstreamCalls != 0 {
				t.Fatalf("unsupported auth method reached upstream %d time(s)", *upstreamCalls)
			}
		})
	}
}

func TestPanelAuthFacadeTelegramCallbackIssuesPanelSession(t *testing.T) {
	rt := newPanelFacadeRuntime(t)
	var auditOut bytes.Buffer
	rt.Audit().SetOutputForTest(&auditOut)
	code := signedTelegramCode(time.Now())
	req := httptest.NewRequest(http.MethodPost, "/api/auth/oauth2/callback", strings.NewReader(`{"provider":"telegram","code":`+strconvQuote(code)+`,"state":"telegram-oauth-state"}`))
	req.RequestURI = "/api/auth/oauth2/callback"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Response struct {
			AccessToken string `json:"accessToken"`
		} `json:"response"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	root := decodeObject(t, rec.Body.Bytes())
	assertExactKeys(t, root, "response")
	response := decodeObject(t, root["response"])
	assertExactKeys(t, response, "accessToken")
	if body.Response.AccessToken == "" || strings.HasPrefix(body.Response.AccessToken, "rg_") {
		t.Fatalf("unexpected panel token %q", body.Response.AccessToken)
	}
	if _, err := auth.ParseBearer("Bearer " + body.Response.AccessToken); err == nil {
		t.Fatal("panel access token parsed as raw RemnaGuard credential")
	}
	claims, err := auth.ValidatePanelSession(rt.state.Load().cfg.PanelFacade, body.Response.AccessToken, time.Now())
	if err != nil {
		t.Fatalf("callback returned invalid panel session: %v", err)
	}
	if claims.TelegramActorID != "123456789" {
		t.Fatalf("callback returned token for actor %q", claims.TelegramActorID)
	}
	for _, secret := range []string{"root", "secret", "panel-session-secret", telegramTestBotToken} {
		if strings.Contains(body.Response.AccessToken, secret) {
			t.Fatalf("panel token exposes secret material %q in %q", secret, body.Response.AccessToken)
		}
	}
	events := decodeAuditEvents(t, auditOut.String())
	last := events[len(events)-1]
	assertAuditValue(t, last, "event", "panel_auth_callback")
	assertAuditValue(t, last, "actor_type", "telegram")
	assertAuditValue(t, last, "actor_id", "123456789")
	assertAuditValue(t, last, "display_name", "Alice")
	assertAuditValue(t, last, "mapped_credential_id", "cred")
	assertAuditValue(t, last, "credential_id", "cred")
	assertNoSecretMaterial(t, auditOut.String(), body.Response.AccessToken)
}

func TestPanelAuthFacadeAuthorizeURLBrowserHandoffReachesCallbackContract(t *testing.T) {
	rt := newPanelFacadeRuntime(t)
	authorizeReq := httptest.NewRequest(http.MethodPost, "/api/auth/oauth2/authorize", strings.NewReader(`{"provider":"telegram"}`))
	authorizeReq.RequestURI = "/api/auth/oauth2/authorize"
	authorizeReq.Header.Set("Content-Type", "application/json")
	authorizeRec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(authorizeRec, authorizeReq)
	if authorizeRec.Code != http.StatusOK {
		t.Fatalf("authorize got %d: %s", authorizeRec.Code, authorizeRec.Body.String())
	}
	var authorizeBody struct {
		Response struct {
			AuthorizationURL string `json:"authorizationUrl"`
		} `json:"response"`
	}
	if err := json.Unmarshal(authorizeRec.Body.Bytes(), &authorizeBody); err != nil {
		t.Fatal(err)
	}
	returnedURL, err := url.Parse(authorizeBody.Response.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorizationUrl: %v", err)
	}
	query := returnedURL.Query()
	payload, err := url.ParseQuery(signedTelegramCode(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	for key, values := range payload {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	returnedURL.RawQuery = query.Encode()

	handoffReq := httptest.NewRequest(http.MethodGet, returnedURL.String(), nil)
	handoffReq.RequestURI = returnedURL.RequestURI()
	handoffRec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(handoffRec, handoffReq)
	if handoffRec.Code != http.StatusSeeOther {
		t.Fatalf("handoff got %d: %s", handoffRec.Code, handoffRec.Body.String())
	}
	location := handoffRec.Header().Get("Location")
	frontendCallback, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse handoff location %q: %v", location, err)
	}
	if frontendCallback.Path != "/oauth2/callback/telegram" {
		t.Fatalf("handoff redirected to %q", location)
	}
	code := frontendCallback.Query().Get("code")
	state := frontendCallback.Query().Get("state")
	if code == "" || state != panelOAuth2TelegramState {
		t.Fatalf("handoff location missing callback contract values: %q", location)
	}

	callbackRec := postPanelCallbackWithState(t, rt, code, state)
	if callbackRec.Code != http.StatusOK {
		t.Fatalf("callback got %d: %s", callbackRec.Code, callbackRec.Body.String())
	}
	var callbackBody struct {
		Response struct {
			AccessToken string `json:"accessToken"`
		} `json:"response"`
	}
	if err := json.Unmarshal(callbackRec.Body.Bytes(), &callbackBody); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(callbackBody.Response.AccessToken, "panel_") {
		t.Fatalf("callback returned non-panel token %q", callbackBody.Response.AccessToken)
	}
	claims, err := auth.ValidatePanelSession(rt.state.Load().cfg.PanelFacade, callbackBody.Response.AccessToken, time.Now())
	if err != nil {
		t.Fatalf("callback returned invalid panel session: %v", err)
	}
	if claims.TelegramActorID != "123456789" {
		t.Fatalf("callback returned token for actor %q", claims.TelegramActorID)
	}
	assertNoSecretMaterial(t, authorizeRec.Body.String()+handoffRec.Body.String()+location+callbackRec.Body.String())
}

func TestPanelAuthFacadeUnmappedCallbackAuditIncludesActorWithoutSecrets(t *testing.T) {
	rt := newPanelFacadeRuntime(t)
	var auditOut bytes.Buffer
	rt.Audit().SetOutputForTest(&auditOut)
	code := signedTelegramCodeForActor("987654321", time.Now())
	rec := postPanelCallback(t, rt, code)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403: %s", rec.Code, rec.Body.String())
	}
	events := decodeAuditEvents(t, auditOut.String())
	last := events[len(events)-1]
	assertAuditValue(t, last, "event", "request_denied")
	assertAuditValue(t, last, "actor_type", "telegram")
	assertAuditValue(t, last, "actor_id", "987654321")
	assertAuditValue(t, last, "auth_event_type", "callback")
	if strings.Contains(rec.Body.String(), "987654321") {
		t.Fatalf("response leaked actor id: %s", rec.Body.String())
	}
	assertNoSecretMaterial(t, rec.Body.String()+auditOut.String(), code)
}

func TestPanelSessionAllowedRouteUsesExistingProxyPipeline(t *testing.T) {
	upstreamCalls := 0
	var panelToken string
	rt := newPanelFacadeProxyRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.URL.RequestURI() != "/api/users/by-telegram-id/1000000900000000" {
			t.Fatalf("unexpected upstream uri %q", r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer root" {
			t.Fatalf("unexpected upstream auth %q", r.Header.Get("Authorization"))
		}
		if strings.Contains(r.Header.Get("Authorization"), panelToken) {
			t.Fatal("panel session token reached upstream authorization")
		}
		for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "Proxy-Authorization", "X-Connected-Secret"} {
			if r.Header.Get(header) != "" {
				t.Fatalf("protected header %s reached upstream", header)
			}
		}
		assertUpstreamHeadersExclude(t, r, panelToken, "123456789", "rg_cred.secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":[]}`))
	})
	panelToken = issueTestPanelSession(t, rt)

	req := httptest.NewRequest(http.MethodGet, "/api/users/by-telegram-id/1000000900000000", nil)
	req.RequestURI = "/api/users/by-telegram-id/1000000900000000"
	req.Header.Set("Authorization", "Bearer "+panelToken)
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Proxy-Authorization", "Bearer should-not-forward")
	req.Header.Set("Connection", "X-Connected-Secret")
	req.Header.Set("X-Connected-Secret", "should-not-forward")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected panel session request to proxy, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upstreamCalls)
	}
}

func TestPanelSessionMissingRequiredScopeDoesNotCallUpstream(t *testing.T) {
	upstreamCalls := 0
	rt := newPanelFacadeProxyRuntime(t, func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	})
	var auditOut bytes.Buffer
	rt.Audit().SetOutputForTest(&auditOut)
	panelToken := issueTestPanelSession(t, rt)

	req := httptest.NewRequest(http.MethodGet, "/api/internal-squads", nil)
	req.RequestURI = "/api/internal-squads"
	req.Header.Set("Authorization", "Bearer "+panelToken)
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected missing scope denial, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("denied panel session request reached upstream %d time(s)", upstreamCalls)
	}
	events := decodeAuditEvents(t, auditOut.String())
	last := events[len(events)-1]
	assertAuditValue(t, last, "event", "request_denied")
	assertAuditValue(t, last, "actor_id", "123456789")
	assertAuditValue(t, last, "mapped_credential_id", "cred")
	assertAuditValue(t, last, "credential_id", "cred")
	assertAuditValue(t, last, "route", "squad.internal.list")
	assertAuditValue(t, last, "method", http.MethodGet)
	assertAuditValue(t, last, "path", "/api/internal-squads")
	assertAuditValue(t, last, "reason", "missing_scope")
	assertNoSecretMaterial(t, rec.Body.String()+auditOut.String(), panelToken)
}

func TestPanelSessionExpiredTokenDoesNotCallUpstream(t *testing.T) {
	upstreamCalls := 0
	rt := newPanelFacadeProxyRuntime(t, func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	})
	panelToken, err := auth.IssuePanelSession(rt.state.Load().cfg.PanelFacade, "123456789", time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users/by-telegram-id/1000000900000000", nil)
	req.RequestURI = "/api/users/by-telegram-id/1000000900000000"
	req.Header.Set("Authorization", "Bearer "+panelToken)
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected expired panel token denial, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("expired panel token reached upstream %d time(s)", upstreamCalls)
	}
	assertNoSecretMaterial(t, rec.Body.String(), panelToken)
}

func TestPanelFacadeErrorsRedactInvalidTokenUnmappedActorAndUnknownRoute(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		path  string
		want  int
	}{
		{name: "invalid token", token: "panel_invalid_secret_value", path: "/api/users/by-telegram-id/1000000900000000", want: http.StatusUnauthorized},
		{name: "unmapped actor", token: "", path: "/api/users/by-telegram-id/1000000900000000", want: http.StatusForbidden},
		{name: "unknown route", token: "", path: "/api/not-cataloged", want: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newPanelFacadeProxyRuntime(t, func(http.ResponseWriter, *http.Request) {
				t.Fatal("redaction denial must not reach upstream")
			})
			var auditOut bytes.Buffer
			rt.Audit().SetOutputForTest(&auditOut)
			token := tc.token
			if token == "" {
				actorID := "987654321"
				if tc.name == "unknown route" {
					actorID = "123456789"
				}
				var err error
				token, err = auth.IssuePanelSession(rt.state.Load().cfg.PanelFacade, actorID, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.RequestURI = tc.path
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			rt.apiHandler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			combined := rec.Body.String() + auditOut.String()
			if strings.Contains(combined, token) || strings.Contains(combined, "panel_invalid_secret_value") {
				t.Fatalf("raw token leaked in response/audit: %s", combined)
			}
			assertNoSecretMaterial(t, combined, token)
		})
	}
}

func TestPanelSessionUnknownRouteDoesNotCallUpstream(t *testing.T) {
	upstreamCalls := 0
	rt := newPanelFacadeProxyRuntime(t, func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	})
	panelToken := issueTestPanelSession(t, rt)

	req := httptest.NewRequest(http.MethodGet, "/api/not-cataloged", nil)
	req.RequestURI = "/api/not-cataloged"
	req.Header.Set("Authorization", "Bearer "+panelToken)
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected unknown route denial, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("unknown route reached upstream %d time(s)", upstreamCalls)
	}
}

func TestPanelFacadeStillAcceptsRawRemnaGuardToken(t *testing.T) {
	upstreamCalls := 0
	rawToken := "rg_cred.secret"
	rt := newPanelFacadeProxyRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Header.Get("Authorization") != "Bearer root" {
			t.Fatalf("unexpected upstream auth %q", r.Header.Get("Authorization"))
		}
		assertUpstreamHeadersExclude(t, r, rawToken)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":[]}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users/by-telegram-id/1000000900000000", nil)
	req.RequestURI = "/api/users/by-telegram-id/1000000900000000"
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected raw token request to still proxy, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upstreamCalls)
	}
}

func TestPanelAuthFacadeTelegramCallbackDenials(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
		want int
	}{
		{name: "invalid hash", code: signedTelegramCode(time.Now()) + "00", want: http.StatusUnauthorized},
		{name: "expired auth date", code: signedTelegramCode(time.Now().Add(-10 * time.Minute)), want: http.StatusUnauthorized},
		{name: "unmapped actor", code: signedTelegramCodeForActor("987654321", time.Now()), want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newPanelFacadeRuntime(t)
			rec := postPanelCallback(t, rt, tc.code)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusForbidden && strings.Contains(rec.Body.String(), "987654321") {
				t.Fatalf("denial leaked actor id: %s", rec.Body.String())
			}
		})
	}
}

func TestPanelAuthFacadeCallbackRejectsMissingOrWrongState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
	}{
		{name: "missing state", state: ""},
		{name: "wrong state", state: "wrong-state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newPanelFacadeRuntime(t)
			rec := postPanelCallbackWithState(t, rt, signedTelegramCode(time.Now()), tc.state)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("got %d want 403: %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "accessToken") || (tc.state != "" && strings.Contains(rec.Body.String(), tc.state)) {
				t.Fatalf("state denial leaked sensitive detail or token shape: %s", rec.Body.String())
			}
		})
	}
}

func TestPanelAuthFacadeCallbackRejectsDisabledMappedCredential(t *testing.T) {
	rt := newPanelFacadeRuntime(t)
	rt.state.Load().cfg.Tokens[0].Credentials[0].Disabled = true
	rec := postPanelCallback(t, rt, signedTelegramCode(time.Now()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "123456789") || strings.Contains(rec.Body.String(), "cred") {
		t.Fatalf("denial leaked mapping detail: %s", rec.Body.String())
	}
}

func TestVerifyTelegramLoginPayloadDeterministicVector(t *testing.T) {
	payload := "auth_date=1700000000&first_name=Alice&id=123456789&last_name=Example&photo_url=https%3A%2F%2Fexample.com%2Favatar.jpg&username=alice_example&hash=b18416b843a8b4d148c835be0bf0ec842859233027024c5ffb25c6b6b1f37b11"
	fields, err := verifyTelegramLoginPayload(payload, telegramTestBotToken, 5*time.Minute, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if fields["id"] != "123456789" || fields["username"] != "alice_example" {
		t.Fatalf("unexpected fields: %#v", fields)
	}
	duplicate := payload + "&username=mallory"
	if _, err := verifyTelegramLoginPayload(duplicate, telegramTestBotToken, 5*time.Minute, time.Unix(1700000000, 0)); err == nil {
		t.Fatal("expected duplicate signed field denial")
	}
}

const telegramTestBotToken = "000000:TEST_TOKEN_DO_NOT_USE_TEST_TOKEN"

func newPanelFacadeRuntime(t *testing.T) *Runtime {
	t.Helper()
	rt, _ := newPanelFacadeRuntimeCountingUpstream(t)
	return rt
}

func newPanelFacadeRuntimeCountingUpstream(t *testing.T) (*Runtime, *int) {
	t.Helper()
	t.Setenv("PANEL_SESSION_SECRET", "panel-session-secret")
	t.Setenv("TELEGRAM_BOT_TOKEN", telegramTestBotToken)
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
		t.Fatal("panel auth facade request must not reach upstream")
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(upstream.URL, "secret")
	cfg.PanelFacade.Enabled = true
	cfg.PanelFacade.Session.Issuer = "remnaguard-test"
	cfg.PanelFacade.Session.Audience = "remnawave-panel"
	cfg.PanelFacade.Session.TokenTTL = time.Hour
	cfg.PanelFacade.Session.SecretEnv = "PANEL_SESSION_SECRET"
	cfg.PanelFacade.Telegram.BotTokenEnv = "TELEGRAM_BOT_TOKEN"
	cfg.PanelFacade.Telegram.AuthMaxAge = 5 * time.Minute
	cfg.PanelFacade.Actors.Telegram = map[string]config.PanelFacadeTelegramActor{"123456789": {CredentialID: "cred", DisplayName: "Alice"}}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return rt, &upstreamCalls
}

func newPanelFacadeProxyRuntime(t *testing.T, upstreamHandler http.HandlerFunc) *Runtime {
	t.Helper()
	t.Setenv("PANEL_SESSION_SECRET", "panel-session-secret")
	t.Setenv("TELEGRAM_BOT_TOKEN", telegramTestBotToken)
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)
	cfg := testConfig(upstream.URL, "secret")
	cfg.PanelFacade.Enabled = true
	cfg.PanelFacade.Session.Issuer = "remnaguard-test"
	cfg.PanelFacade.Session.Audience = "remnawave-panel"
	cfg.PanelFacade.Session.TokenTTL = time.Hour
	cfg.PanelFacade.Session.SecretEnv = "PANEL_SESSION_SECRET"
	cfg.PanelFacade.Telegram.BotTokenEnv = "TELEGRAM_BOT_TOKEN"
	cfg.PanelFacade.Telegram.AuthMaxAge = 5 * time.Minute
	cfg.PanelFacade.Actors.Telegram = map[string]config.PanelFacadeTelegramActor{"123456789": {CredentialID: "cred", DisplayName: "Alice"}}
	rt, err := NewRuntime(cfg, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func issueTestPanelSession(t *testing.T, rt *Runtime) string {
	t.Helper()
	token, err := auth.IssuePanelSession(rt.state.Load().cfg.PanelFacade, "123456789", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func postPanelCallback(t *testing.T, rt *Runtime, code string) *httptest.ResponseRecorder {
	t.Helper()
	return postPanelCallbackWithState(t, rt, code, "telegram-oauth-state")
}

func postPanelCallbackWithState(t *testing.T, rt *Runtime, code, state string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"provider":"telegram","code":` + strconvQuote(code)
	if state != "" {
		body += `,"state":` + strconvQuote(state)
	}
	body += `}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/oauth2/callback", strings.NewReader(body))
	req.RequestURI = "/api/auth/oauth2/callback"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.apiHandler().ServeHTTP(rec, req)
	return rec
}

func signedTelegramCode(now time.Time) string {
	return signedTelegramCodeForActor("123456789", now)
}

func signedTelegramCodeForActor(actorID string, now time.Time) string {
	values := url.Values{}
	values.Set("auth_date", strconvFormatInt(now.Unix()))
	values.Set("first_name", "Alice")
	values.Set("id", actorID)
	values.Set("last_name", "Example")
	values.Set("photo_url", "https://example.com/avatar.jpg")
	values.Set("username", "alice_example")
	fields := []string{"auth_date=" + values.Get("auth_date"), "first_name=Alice", "id=" + actorID, "last_name=Example", "photo_url=https://example.com/avatar.jpg", "username=alice_example"}
	secret := sha256Sum([]byte(telegramTestBotToken))
	hash := hmacHex(secret, strings.Join(fields, "\n"))
	values.Set("hash", hash)
	return values.Encode()
}

func assertJSONMatchesFixture(t *testing.T, got []byte, fixture string) {
	t.Helper()
	wantRaw, err := os.ReadFile(authCompatFixtureDir + "/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var wantValue any
	if err := json.Unmarshal(wantRaw, &wantValue); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("response mismatch\ngot:  %s\nwant fixture: %s", string(got), fixture)
	}
}

func assertJSONKeyAbsent(t *testing.T, data []byte, key string) {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if jsonContainsKey(value, key) {
		t.Fatalf("response contains forbidden key %q: %s", key, string(data))
	}
}

func jsonContainsKey(value any, key string) bool {
	switch typed := value.(type) {
	case map[string]any:
		if _, ok := typed[key]; ok {
			return true
		}
		for _, child := range typed {
			if jsonContainsKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if jsonContainsKey(child, key) {
				return true
			}
		}
	}
	return false
}

func decodeAuditEvents(t *testing.T, raw string) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode audit event %q: %v", line, err)
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	return events
}

func assertAuditValue(t *testing.T, event map[string]any, key string, want any) {
	t.Helper()
	got, ok := event[key]
	if !ok {
		t.Fatalf("audit event missing %q: %#v", key, event)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audit %s got %v want %v in %#v", key, got, want, event)
	}
}

func assertNoSecretMaterial(t *testing.T, text string, dynamicSecrets ...string) {
	t.Helper()
	secrets := []string{"root", "secret", "panel-session-secret", telegramTestBotToken, "Bearer panel_invalid_secret_value", "rg_cred.secret"}
	secrets = append(secrets, dynamicSecrets...)
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("secret material %q leaked in %q", secret, text)
		}
	}
}

func assertUpstreamHeadersExclude(t *testing.T, r *http.Request, forbidden ...string) {
	t.Helper()
	for name, values := range r.Header {
		for _, value := range values {
			for _, secret := range forbidden {
				if secret != "" && strings.Contains(value, secret) {
					t.Fatalf("upstream header %s leaked %q in %q", name, secret, value)
				}
			}
		}
	}
}

func strconvQuote(s string) string    { b, _ := json.Marshal(s); return string(b) }
func strconvFormatInt(i int64) string { return fmt.Sprintf("%d", i) }
func sha256Sum(b []byte) []byte       { sum := sha256.Sum256(b); return sum[:] }
func hmacHex(key []byte, msg string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
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
