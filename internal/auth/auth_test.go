package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestParseBearer(t *testing.T) {
	got, err := ParseBearer("Bearer rg_cred123.secret")
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialID != "cred123" || got.Secret != "secret" {
		t.Fatalf("unexpected token parse: %#v", got)
	}
}

func TestVerify(t *testing.T) {
	pepper := []byte("pepper-pepper-pepper-pepper-pepper-32")
	cred := config.Credential{ID: "cred", HMACSHA256: Digest("secret", pepper)}
	if !Verify("secret", pepper, cred) {
		t.Fatal("expected secret to verify")
	}
	if Verify("other", pepper, cred) {
		t.Fatal("expected wrong secret to fail")
	}
}

func TestPanelSessionIssueValidateAndRawBearerSeparation(t *testing.T) {
	panel := testPanelFacade(t)
	now := time.Unix(1700000000, 0)
	token, err := IssuePanelSession(panel, "123456789", now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(token, "rg_") {
		t.Fatalf("panel token must not use raw credential prefix: %q", token)
	}
	if !strings.HasPrefix(token, "panel_") {
		t.Fatalf("panel token should use panel prefix: %q", token)
	}
	if _, err := ParseBearer("Bearer " + token); err == nil {
		t.Fatal("panel session token must not parse as a raw RemnaGuard credential")
	}
	pepper := []byte("pepper-pepper-pepper-pepper-pepper-32")
	rawCred := config.Credential{ID: "cred", HMACSHA256: Digest("secret", pepper)}
	if Verify(token, pepper, rawCred) {
		t.Fatal("panel session token must not verify as a raw RemnaGuard credential secret")
	}
	claims, err := ValidatePanelSession(panel, token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "remnaguard-panel" || claims.Audience != "remnawave-browser" || claims.TelegramActorID != "123456789" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestPanelSessionRejectsDisabledFacade(t *testing.T) {
	panel := testPanelFacade(t)
	now := time.Unix(1700000000, 0)
	token, err := IssuePanelSession(panel, "123456789", now)
	if err != nil {
		t.Fatal(err)
	}
	panel.Enabled = false
	if _, err := ValidatePanelSession(panel, token, now); err == nil {
		t.Fatal("expected disabled panel facade to reject session token")
	}
}

func TestPanelSessionRejectsWrongIssuerAndAudience(t *testing.T) {
	panel := testPanelFacade(t)
	now := time.Unix(1700000000, 0)
	token, err := IssuePanelSession(panel, "123456789", now)
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuer := panel
	wrongIssuer.Session.Issuer = "other-issuer"
	if _, err := ValidatePanelSession(wrongIssuer, token, now); err == nil {
		t.Fatal("expected wrong issuer to reject session token")
	}
	wrongAudience := panel
	wrongAudience.Session.Audience = "other-audience"
	if _, err := ValidatePanelSession(wrongAudience, token, now); err == nil {
		t.Fatal("expected wrong audience to reject session token")
	}
}

func TestPanelSessionRejectsExpiredToken(t *testing.T) {
	panel := testPanelFacade(t)
	now := time.Unix(1700000000, 0)
	token, err := IssuePanelSession(panel, "123456789", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePanelSession(panel, token, now.Add(panel.Session.TokenTTL)); err == nil {
		t.Fatal("expected expired panel token to be rejected")
	}
}

func TestPanelSessionRejectsMalformedAndBadSignature(t *testing.T) {
	panel := testPanelFacade(t)
	now := time.Unix(1700000000, 0)
	token, err := IssuePanelSession(panel, "123456789", now)
	if err != nil {
		t.Fatal(err)
	}
	malformed := []string{"", "Bearer " + token, "panel_", "panel_not-base64.signature", token + ".extra"}
	for _, candidate := range malformed {
		if _, err := ValidatePanelSession(panel, candidate, now); err == nil {
			t.Fatalf("expected malformed panel token %q to be rejected", candidate)
		}
	}
	badSignature := token[:len(token)-1] + "A"
	if badSignature == token {
		badSignature = token[:len(token)-1] + "B"
	}
	if _, err := ValidatePanelSession(panel, badSignature, now); err == nil {
		t.Fatal("expected bad signature to be rejected")
	}
}

func TestPanelSessionRejectsEmptyActorID(t *testing.T) {
	panel := testPanelFacade(t)
	if _, err := IssuePanelSession(panel, " ", time.Unix(1700000000, 0)); err == nil {
		t.Fatal("expected empty actor id to be rejected during issue")
	}
	claims := PanelSessionClaims{Issuer: panel.Session.Issuer, Audience: panel.Session.Audience, ExpiresAt: 1700000900, IssuedAt: 1700000000}
	token := signTestPanelSession(t, panel, claims)
	if _, err := ValidatePanelSession(panel, token, time.Unix(1700000001, 0)); err == nil {
		t.Fatal("expected empty actor id claim to be rejected during validation")
	}
}

func TestPanelSessionPayloadContainsOnlySafeSessionClaims(t *testing.T) {
	panel := testPanelFacade(t)
	token, err := IssuePanelSession(panel, "123456789", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload := decodePanelPayload(t, token)
	if got := payload["telegram_actor_id"]; got != "123456789" {
		t.Fatalf("expected actor identity in token payload, got %#v", got)
	}
	for _, forbiddenKey := range []string{"credential_id", "mapped_credential_id", "scopes", "upstream_bearer", "root_bearer", "raw_token", "session_secret", "telegram_bot_token"} {
		if _, ok := payload[forbiddenKey]; ok {
			t.Fatalf("forbidden claim %q present in panel payload %#v", forbiddenKey, payload)
		}
	}
	encodedPayload := strings.SplitN(strings.TrimPrefix(token, "panel_"), ".", 2)[0]
	decodedPayload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbiddenMaterial := range []string{"panel-cred", "users:read", "root-secret", "rg_", "telegram-secret", "panel-session-secret-panel-session-32", "pepper-secret-pepper-secret-32bytes"} {
		if strings.Contains(string(decodedPayload), forbiddenMaterial) {
			t.Fatalf("forbidden material %q present in panel payload %s", forbiddenMaterial, decodedPayload)
		}
	}
}

func TestPanelSessionUsesConfiguredSecretEnvNotTokenPepper(t *testing.T) {
	t.Setenv("PANEL_SESSION_SECRET", "panel-session-secret-panel-session-32")
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper-secret-pepper-secret-32bytes")
	panel := testPanelFacadeWithSecretEnv("PANEL_SESSION_SECRET")
	now := time.Unix(1700000000, 0)
	token, err := IssuePanelSession(panel, "123456789", now)
	if err != nil {
		t.Fatal(err)
	}
	pepperPanel := panel
	pepperPanel.Session.SecretEnv = "REMNAGUARD_TOKEN_PEPPER"
	if _, err := ValidatePanelSession(pepperPanel, token, now); err == nil {
		t.Fatal("expected token signed with panel secret env to reject token pepper env")
	}
}

func TestPanelSessionRejectsFutureIssuedAndOverlongTTL(t *testing.T) {
	panel := testPanelFacade(t)
	now := time.Unix(1700000000, 0)
	futureClaims := PanelSessionClaims{Issuer: panel.Session.Issuer, Audience: panel.Session.Audience, IssuedAt: now.Add(2 * time.Minute).Unix(), ExpiresAt: now.Add(panel.Session.TokenTTL).Unix(), TelegramActorID: "123456789"}
	futureToken := signTestPanelSession(t, panel, futureClaims)
	if _, err := ValidatePanelSession(panel, futureToken, now); err == nil {
		t.Fatal("expected future-issued panel token to be rejected")
	}
	overlongClaims := PanelSessionClaims{Issuer: panel.Session.Issuer, Audience: panel.Session.Audience, IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * panel.Session.TokenTTL).Unix(), TelegramActorID: "123456789"}
	overlongToken := signTestPanelSession(t, panel, overlongClaims)
	if _, err := ValidatePanelSession(panel, overlongToken, now); err == nil {
		t.Fatal("expected overlong panel token lifetime to be rejected")
	}
}

func testPanelFacade(t *testing.T) config.PanelFacadeConfig {
	t.Helper()
	t.Setenv("PANEL_SESSION_SECRET", "panel-session-secret-panel-session-32")
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper-secret-pepper-secret-32bytes")
	return testPanelFacadeWithSecretEnv("PANEL_SESSION_SECRET")
}

func testPanelFacadeWithSecretEnv(secretEnv string) config.PanelFacadeConfig {
	return config.PanelFacadeConfig{
		Enabled: true,
		Session: config.PanelFacadeSessionConfig{
			Issuer:    "remnaguard-panel",
			Audience:  "remnawave-browser",
			TokenTTL:  15 * time.Minute,
			SecretEnv: secretEnv,
		},
	}
}

func decodePanelPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.SplitN(strings.TrimPrefix(token, "panel_"), ".", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected panel token shape: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func signTestPanelSession(t *testing.T, panel config.PanelFacadeConfig, claims PanelSessionClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	return "panel_" + encodedPayload + "." + signPanelSession(encodedPayload, []byte("panel-session-secret-panel-session-32"))
}
