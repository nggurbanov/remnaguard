package config

import "testing"

func TestValidateRejectsNonPositiveCoreLimits(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
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

func TestValidateRejectsInvalidExtendedConstraints(t *testing.T) {
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper")
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
