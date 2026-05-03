package server

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const authCompatFixtureDir = "testdata/auth_compat"

func TestRemnawaveAuthCompatibilityStatusFixture(t *testing.T) {
	root := readFixtureObject(t, "status_telegram_only.json")
	assertExactKeys(t, root, "response")

	response := decodeObject(t, root["response"])
	assertExactKeys(t, response, "isLoginAllowed", "isRegisterAllowed", "authentication", "branding")
	assertBool(t, response["isLoginAllowed"], true)
	assertBool(t, response["isRegisterAllowed"], false)

	authentication := decodeObject(t, response["authentication"])
	assertExactKeys(t, authentication, "passkey", "oauth2", "password")

	passkey := decodeObject(t, authentication["passkey"])
	assertExactKeys(t, passkey, "enabled")
	assertBool(t, passkey["enabled"], false)

	password := decodeObject(t, authentication["password"])
	assertExactKeys(t, password, "enabled")
	assertBool(t, password["enabled"], false)

	oauth2 := decodeObject(t, authentication["oauth2"])
	assertExactKeys(t, oauth2, "providers")
	providers := decodeObject(t, oauth2["providers"])
	assertExactKeys(t, providers, "telegram", "github", "pocketid", "yandex", "keycloak", "generic")
	expectedProviders := map[string]bool{
		"telegram": true,
		"github":   false,
		"pocketid": false,
		"yandex":   false,
		"keycloak": false,
		"generic":  false,
	}
	for provider, enabled := range expectedProviders {
		assertBool(t, providers[provider], enabled)
	}

	branding := decodeObject(t, response["branding"])
	assertExactKeys(t, branding, "title", "logoUrl")
	assertString(t, branding["title"], "RemnaGuard Restricted Panel")
	if string(branding["logoUrl"]) != "null" {
		t.Fatalf("logoUrl should be null, got %s", string(branding["logoUrl"]))
	}
}

func TestRemnawaveAuthCompatibilityOAuth2Fixtures(t *testing.T) {
	authorizeRequest := readFixtureObject(t, "oauth2_authorize_telegram.request.json")
	assertExactKeys(t, authorizeRequest, "provider")
	assertString(t, authorizeRequest["provider"], "telegram")

	authorizeResponse := readFixtureObject(t, "oauth2_authorize_telegram.response.json")
	assertExactKeys(t, authorizeResponse, "response")
	authorizePayload := decodeObject(t, authorizeResponse["response"])
	assertExactKeys(t, authorizePayload, "authorizationUrl")
	authorizationURL := decodeString(t, authorizePayload["authorizationUrl"])
	if !strings.HasPrefix(authorizationURL, "https://oauth.telegram.org/auth?") {
		t.Fatalf("authorizationUrl should target Telegram OAuth, got %q", authorizationURL)
	}
	parsedAuthorizeURL, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorizationUrl: %v", err)
	}
	if got := parsedAuthorizeURL.Query().Get("response_type"); got != "code" {
		t.Fatalf("authorizationUrl response_type got %q want code", got)
	}
	if got := parsedAuthorizeURL.Query().Get("redirect_uri"); got != "https://restricted.example.com/oauth2/callback/telegram" {
		t.Fatalf("authorizationUrl redirect_uri got %q", got)
	}
	if got := parsedAuthorizeURL.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("authorizationUrl code_challenge_method got %q want S256", got)
	}
	if nonce := parsedAuthorizeURL.Query().Get("nonce"); nonce == "" {
		t.Fatal("authorizationUrl nonce is required")
	}
	if state := parsedAuthorizeURL.Query().Get("state"); state == "" || state == "telegram-oauth-state" {
		t.Fatalf("authorizationUrl state is unsafe: %q", state)
	}

	callbackRequest := readFixtureObject(t, "oauth2_callback_telegram.request.json")
	assertExactKeys(t, callbackRequest, "provider", "code", "state")
	assertString(t, callbackRequest["provider"], "telegram")
	assertString(t, callbackRequest["code"], "telegram-oauth-code")
	assertString(t, callbackRequest["state"], "test-random-oauth-state")

	callbackResponse := readFixtureObject(t, "oauth2_callback_telegram.response.json")
	assertExactKeys(t, callbackResponse, "response")
	callbackPayload := decodeObject(t, callbackResponse["response"])
	assertExactKeys(t, callbackPayload, "accessToken")
	accessToken := decodeString(t, callbackPayload["accessToken"])
	assertBrowserTokenIsPanelOnly(t, accessToken)
}

func TestRemnawaveAuthCompatibilityUnsupportedFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		path    string
	}{
		{name: "password login", fixture: "unsupported_login.response.json", path: "/api/auth/login"},
		{name: "register", fixture: "unsupported_register.response.json", path: "/api/auth/register"},
		{name: "passkey options", fixture: "unsupported_passkey_options.response.json", path: "/api/auth/passkey/authentication/options"},
		{name: "passkey verify", fixture: "unsupported_passkey_verify.response.json", path: "/api/auth/passkey/authentication/verify"},
		{name: "github authorize", fixture: "unsupported_oauth2_github_authorize.response.json", path: "/api/auth/oauth2/authorize"},
		{name: "github callback", fixture: "unsupported_oauth2_github_callback.response.json", path: "/api/auth/oauth2/callback"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := readFixtureObject(t, tc.fixture)
			assertExactKeys(t, body, "path", "message", "errorCode")
			assertString(t, body["path"], tc.path)
			assertString(t, body["message"], "Forbidden")
			assertString(t, body["errorCode"], "A068")
			if _, ok := body["accessToken"]; ok {
				t.Fatalf("unsupported fixture %s exposed accessToken", tc.fixture)
			}
			for _, raw := range body {
				for _, forbidden := range []string{"root", "bearer", "panel_session", "rg_", "telegram"} {
					if strings.Contains(strings.ToLower(string(raw)), forbidden) {
						t.Fatalf("unsupported fixture %s leaked %q in %s", tc.fixture, forbidden, string(raw))
					}
				}
			}
		})
	}
}

func assertBrowserTokenIsPanelOnly(t *testing.T, token string) {
	t.Helper()
	if token != "panel_session_test_token_telegram_actor_123456789" {
		t.Fatalf("unexpected fixture panel session token %q", token)
	}
	if strings.HasPrefix(token, "rg_") {
		t.Fatalf("browser access token must not be a raw RemnaGuard credential token: %q", token)
	}
	lowerToken := strings.ToLower(token)
	for _, forbidden := range []string{"remnawave", "root", "bearer"} {
		if strings.Contains(lowerToken, forbidden) {
			t.Fatalf("browser access token must not expose %q material: %q", forbidden, token)
		}
	}
}

func readFixtureObject(t *testing.T, filename string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(authCompatFixtureDir + "/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&object); err != nil {
		t.Fatalf("decode %s: %v", filename, err)
	}
	if len(object) == 0 {
		t.Fatalf("%s decoded as empty object", filename)
	}
	return object
}

func decodeObject(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode object %s: %v", string(raw), err)
	}
	if object == nil {
		t.Fatalf("expected object, got %s", string(raw))
	}
	return object
}

func assertExactKeys(t *testing.T, object map[string]json.RawMessage, expected ...string) {
	t.Helper()
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("unexpected keys: got %v want %v", actual, want)
	}
}

func assertBool(t *testing.T, raw json.RawMessage, expected bool) {
	t.Helper()
	var actual bool
	if err := json.Unmarshal(raw, &actual); err != nil {
		t.Fatalf("decode bool %s: %v", string(raw), err)
	}
	if actual != expected {
		t.Fatalf("unexpected bool: got %v want %v", actual, expected)
	}
}

func assertString(t *testing.T, raw json.RawMessage, expected string) {
	t.Helper()
	actual := decodeString(t, raw)
	if actual != expected {
		t.Fatalf("unexpected string: got %q want %q", actual, expected)
	}
}

func decodeString(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var actual string
	if err := json.Unmarshal(raw, &actual); err != nil {
		t.Fatalf("decode string %s: %v", string(raw), err)
	}
	return actual
}
