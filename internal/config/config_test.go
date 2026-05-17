package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRejectsNonPositiveCoreLimits(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper-pepper-pepper-pepper-pepper-32")
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{name: "max path", edit: func(cfg *Config) { cfg.Limits.MaxPathLength = 0 }},
		{name: "max query", edit: func(cfg *Config) { cfg.Limits.MaxQueryLength = 0 }},
		{name: "max body", edit: func(cfg *Config) { cfg.Limits.MaxBodyBytes = 0 }},
		{name: "upstream body", edit: func(cfg *Config) { cfg.Limits.UpstreamBodyBytes = 0 }},
		{name: "global concurrency", edit: func(cfg *Config) { cfg.Limits.GlobalConcurrency = 0 }},
		{name: "per token concurrency", edit: func(cfg *Config) { cfg.Limits.PerTokenConcurrency = 0 }},
		{name: "public sub concurrency", edit: func(cfg *Config) { cfg.PublicSubs.PerIPConcurrency = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.BaseURL = "https://example.test"
			cfg.Upstream.Bearer = "root"
			tc.edit(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected non-positive limit to be rejected")
			}
		})
	}
}

func TestValidateRequiresExplicitLocalListenerExposure(t *testing.T) {
	cases := []string{":8081", "0.0.0.0:8081", "[::]:8081"}
	for _, listen := range cases {
		t.Run(listen, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.BaseURL = "https://example.test"
			cfg.Upstream.Bearer = "root"
			cfg.Server.LocalListen = listen
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected non-loopback local listener to require expose_local")
			}
			cfg.Server.ExposeLocal = true
			if err := cfg.Validate(); err != nil {
				t.Fatalf("expected explicit exposure to be accepted: %v", err)
			}
		})
	}
}

func TestValidateRejectsExposeLocalOnLoopback(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8081", "[::1]:8081", "localhost:8081"} {
		t.Run(listen, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.BaseURL = "https://example.test"
			cfg.Upstream.Bearer = "root"
			cfg.Server.LocalListen = listen
			cfg.Server.ExposeLocal = true
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected expose_local on loopback listener to be rejected")
			}
		})
	}
}

func TestValidateRequiresStrongRuntimeSecrets(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "short")
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.Tokens = []TokenPolicy{{ID: "tenant-a", Scopes: []string{"users:read"}, Credentials: []Credential{{ID: "cred", HMACSHA256: "digest"}}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected short token pepper to be rejected")
	}

	cfg = validPanelFacadeConfig(t)
	t.Setenv("PANEL_SESSION_SECRET", "short")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected short panel session secret to be rejected")
	}
}

func TestValidateRejectsProtectedExtraHeaders(t *testing.T) {
	t.Setenv("PUBLIC_SECRET", "secret")
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "upstream forwarded", edit: func(cfg *Config) { cfg.Upstream.ExtraHeaders = map[string]string{"X-Forwarded-For": "1.2.3.4"} }},
		{name: "upstream proxy auth", edit: func(cfg *Config) { cfg.Upstream.ExtraHeaders = map[string]string{"Proxy-Authorization": "secret"} }},
		{name: "public authorization", edit: func(cfg *Config) { cfg.PublicSubs.ExtraHeaders = map[string]string{"Authorization": "Bearer x"} }},
		{name: "public cookie", edit: func(cfg *Config) { cfg.PublicSubs.ExtraHeaders = map[string]string{"Cookie": "sid=x"} }},
		{name: "public allowlist cookie", edit: func(cfg *Config) {
			cfg.PublicSubs.RequestHeaderAllowlist = append(cfg.PublicSubs.RequestHeaderAllowlist, "Cookie")
		}},
		{name: "public auth forwarded", edit: func(cfg *Config) {
			cfg.PublicSubs.AuthHeaderName = "X-Forwarded-For"
			cfg.PublicSubs.AuthHeaderEnv = "PUBLIC_SECRET"
		}},
		{name: "public response framing", edit: func(cfg *Config) {
			cfg.PublicSubs.ExtraResponseHeaders = map[string]string{"Transfer-Encoding": "chunked"}
		}},
		{name: "public response length", edit: func(cfg *Config) { cfg.PublicSubs.ExtraResponseHeaders = map[string]string{"Content-Length": "42"} }},
		{name: "public response allowlist cookie", edit: func(cfg *Config) {
			cfg.PublicSubs.ResponseHeaderAllowlist = append(cfg.PublicSubs.ResponseHeaderAllowlist, "Set-Cookie")
		}},
		{name: "public response allowlist redirect", edit: func(cfg *Config) {
			cfg.PublicSubs.ResponseHeaderAllowlist = append(cfg.PublicSubs.ResponseHeaderAllowlist, "Location")
		}},
		{name: "upstream accept encoding", edit: func(cfg *Config) { cfg.Upstream.ExtraHeaders = map[string]string{"Accept-Encoding": "gzip"} }},
		{name: "public allowlist content length", edit: func(cfg *Config) {
			cfg.PublicSubs.RequestHeaderAllowlist = append(cfg.PublicSubs.RequestHeaderAllowlist, "Content-Length")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.BaseURL = "https://example.test"
			cfg.Upstream.Bearer = "root"
			tc.edit(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected protected extra header to be rejected")
			}
		})
	}
}

func TestValidateRejectsAmbiguousUpstreamBaseURL(t *testing.T) {
	for _, raw := range []string{
		"https://user:pass@example.test",
		"https://example.test?token=secret",
		"https://example.test/#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.BaseURL = raw
			cfg.Upstream.Bearer = "root"
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected ambiguous upstream base URL to be rejected")
			}
		})
	}
}

func TestValidateRejectsAmbiguousBearerSources(t *testing.T) {
	t.Setenv("ROOT_BEARER", "")
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.Upstream.BearerEnv = "ROOT_BEARER"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected configured bearer source ambiguity to be rejected")
	}
}

func TestValidateRejectsUnsetPublicSubscriptionAuthEnv(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.PublicSubs.AuthHeaderName = "X-Remnaguard-Subscription-Auth"
	cfg.PublicSubs.AuthHeaderEnv = "MISSING_PUBLIC_SUB_AUTH"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing public subscription auth env to be rejected")
	}
}

func TestValidateAcceptsTelegramAlerts(t *testing.T) {
	t.Setenv("ALERT_TOKEN", "token")
	t.Setenv("ALERT_CHAT", "123")
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.Alerts.Enabled = true
	cfg.Alerts.Telegram.Enabled = true
	cfg.Alerts.Telegram.BotTokenEnv = "ALERT_TOKEN"
	cfg.Alerts.Telegram.ChatIDEnv = "ALERT_CHAT"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid alerts config: %v", err)
	}
}

func TestValidateRejectsTelegramAlertsWithoutEnv(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.Alerts.Enabled = true
	cfg.Alerts.Telegram.Enabled = true
	cfg.Alerts.Telegram.BotTokenEnv = "MISSING_ALERT_TOKEN"
	cfg.Alerts.Telegram.ChatIDEnv = "MISSING_ALERT_CHAT"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing telegram alert env to be rejected")
	}
}

func TestLoadParsesTelegramAlertDurations(t *testing.T) {
	t.Setenv("ALERT_TOKEN", "token")
	t.Setenv("ALERT_CHAT", "123")
	dir := t.TempDir()
	path := filepath.Join(dir, "remnaguard.yaml")
	if err := os.WriteFile(path, []byte(`
upstream:
  base_url: "https://example.test"
  bearer: "root"
alerts:
  enabled: true
  telegram:
    enabled: true
    bot_token_env: "ALERT_TOKEN"
    chat_id_env: "ALERT_CHAT"
    cooldown: 3m
    timeout: 2s
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Alerts.Telegram.Cooldown != 3*time.Minute {
		t.Fatalf("unexpected cooldown %s", cfg.Alerts.Telegram.Cooldown)
	}
	if cfg.Alerts.Telegram.Timeout != 2*time.Second {
		t.Fatalf("unexpected timeout %s", cfg.Alerts.Telegram.Timeout)
	}
}

func TestValidateRejectsInvalidExtendedConstraints(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper-pepper-pepper-pepper-pepper-32")
	for _, tc := range []struct {
		name string
		edit func(*TokenPolicy)
	}{
		{name: "bad username regex", edit: func(tok *TokenPolicy) { tok.Constraints.UsernameRegex = "[" }},
		{name: "bad telegram range", edit: func(tok *TokenPolicy) { tok.Constraints.TelegramIDRanges = []IDRange{{Min: 10, Max: 1}} }},
		{name: "empty request fields", edit: func(tok *TokenPolicy) { tok.Constraints.AllowedRequestFields = map[string][]string{"user.create": {}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.BaseURL = "https://example.test"
			cfg.Upstream.Bearer = "root"
			cfg.Tokens = []TokenPolicy{{
				ID:          "tenant-a",
				Scopes:      []string{"users:read"},
				Credentials: []Credential{{ID: "cred", HMACSHA256: "digest"}},
			}}
			tc.edit(&cfg.Tokens[0])
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected invalid extended constraint to be rejected")
			}
		})
	}
}

func TestValidateAcceptsDisabledPanelFacadeWithoutPanelEnv(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.PanelFacade.Session.SecretEnv = "MISSING_PANEL_SESSION_SECRET"
	cfg.PanelFacade.Telegram.ClientIDEnv = "MISSING_PANEL_TELEGRAM_CLIENT_ID"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected disabled panel facade to ignore panel env vars: %v", err)
	}
}

func TestValidateAcceptsEnabledPanelFacade(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid panel facade config: %v", err)
	}
}

func TestValidateRejectsPanelFacadeMissingSessionSecretEnv(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Session.SecretEnv = "MISSING_PANEL_SESSION_SECRET"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing panel session secret env to be rejected")
	}
}

func TestValidateRejectsPanelFacadeMissingTelegramClientEnv(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Telegram.ClientIDEnv = "MISSING_PANEL_TELEGRAM_CLIENT_ID"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing panel telegram client env to be rejected")
	}
}

func TestValidateRejectsPanelFacadeRawActorCredential(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Actors.Telegram["123456789"] = PanelFacadeTelegramActor{CredentialID: "rg_", DisplayName: "Alice"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected raw panel actor credential value to be rejected")
	}
}

func TestValidateRejectsPanelFacadeMissingCredential(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Actors.Telegram["123456789"] = PanelFacadeTelegramActor{CredentialID: "missing-cred", DisplayName: "Alice"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing panel actor credential to be rejected")
	}
}

func TestValidateRejectsPanelFacadePrivateHTTPTokenURL(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Telegram.TokenURL = "http://10.0.0.10/token"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected private http panel telegram token url to be rejected")
	}
}

func TestValidateAllowsPanelFacadeLoopbackHTTPTokenURL(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Telegram.TokenURL = "http://127.0.0.1/token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected loopback http panel telegram token url to be allowed for tests/local dev: %v", err)
	}
}

func TestValidateRejectsPanelFacadeNonHTTPLoopbackTokenURL(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.PanelFacade.Telegram.TokenURL = "ftp://localhost/token"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-http loopback panel telegram token url to be rejected")
	}
}

func TestValidateRejectsPanelFacadeDisabledCredential(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.Tokens[0].Credentials[0].Disabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected disabled panel actor credential to be rejected")
	}
}

func TestValidateRejectsPanelFacadeDisabledToken(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	cfg.Tokens[0].Disabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected credential on disabled token to be rejected")
	}
}

func TestValidateRejectsPanelFacadeEmptyTelegramActorID(t *testing.T) {
	cfg := validPanelFacadeConfig(t)
	delete(cfg.PanelFacade.Actors.Telegram, "123456789")
	cfg.PanelFacade.Actors.Telegram[" "] = PanelFacadeTelegramActor{CredentialID: "panel-cred", DisplayName: "Alice"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected empty telegram actor id to be rejected")
	}
}

func validPanelFacadeConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper-pepper-pepper-pepper-pepper-32")
	t.Setenv("PANEL_SESSION_SECRET", "panel-session-secret-panel-session-32")
	t.Setenv("PANEL_TELEGRAM_CLIENT_ID", "telegram-client-id")
	t.Setenv("PANEL_TELEGRAM_CLIENT_SECRET", "telegram-client-secret")
	cfg := Defaults()
	cfg.Upstream.BaseURL = "https://example.test"
	cfg.Upstream.Bearer = "root"
	cfg.Tokens = []TokenPolicy{{
		ID:          "panel-token",
		Scopes:      []string{"users:read"},
		Credentials: []Credential{{ID: "panel-cred", HMACSHA256: "digest"}},
	}}
	cfg.PanelFacade = PanelFacadeConfig{
		Enabled: true,
		Session: PanelFacadeSessionConfig{
			Issuer:    "remnaguard",
			Audience:  "remnawave-panel",
			TokenTTL:  15 * time.Minute,
			SecretEnv: "PANEL_SESSION_SECRET",
		},
		Telegram: PanelFacadeTelegramConfig{
			ClientIDEnv:     "PANEL_TELEGRAM_CLIENT_ID",
			ClientSecretEnv: "PANEL_TELEGRAM_CLIENT_SECRET",
			FrontendDomain:  "restricted.example.com",
			AuthURL:         "https://oauth.telegram.org/auth",
			TokenURL:        "https://oauth.telegram.org/token",
			AuthMaxAge:      5 * time.Minute,
		},
		Actors: PanelFacadeActorsConfig{Telegram: map[string]PanelFacadeTelegramActor{
			"123456789": {CredentialID: "panel-cred", DisplayName: "Alice"},
		}},
	}
	return cfg
}
