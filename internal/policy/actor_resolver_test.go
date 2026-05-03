package policy

import (
	"errors"
	"testing"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestResolveTelegramActorCredentialMappedActor(t *testing.T) {
	cfg := actorResolverConfig("cred-a", "token-a")
	tok, cred, err := ResolveTelegramActorCredential(cfg, "123456789")
	if err != nil {
		t.Fatal(err)
	}
	if tok.ID != "token-a" || cred.ID != "cred-a" || len(tok.Scopes) != 1 || tok.Scopes[0] != "users:read" {
		t.Fatalf("unexpected resolved policy/credential: %#v %#v", tok, cred)
	}
}

func TestResolveTelegramActorCredentialDenials(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
		want error
	}{
		{
			name: "unmapped actor",
			edit: func(*config.Config) {},
			want: ErrActorResolverUnmappedActor,
		},
		{
			name: "missing credential",
			edit: func(cfg *config.Config) {
				cfg.PanelFacade.Actors.Telegram["987654321"] = config.PanelFacadeTelegramActor{CredentialID: "missing-cred"}
			},
			want: ErrActorResolverMissingCredential,
		},
		{
			name: "disabled credential",
			edit: func(cfg *config.Config) {
				cfg.PanelFacade.Actors.Telegram["987654321"] = config.PanelFacadeTelegramActor{CredentialID: "cred-a"}
				cfg.Tokens[0].Credentials[0].Disabled = true
			},
			want: ErrActorResolverDisabledCredential,
		},
		{
			name: "disabled token",
			edit: func(cfg *config.Config) {
				cfg.PanelFacade.Actors.Telegram["987654321"] = config.PanelFacadeTelegramActor{CredentialID: "cred-a"}
				cfg.Tokens[0].Disabled = true
			},
			want: ErrActorResolverDisabledCredential,
		},
		{
			name: "raw token mapping",
			edit: func(cfg *config.Config) {
				cfg.PanelFacade.Actors.Telegram["987654321"] = config.PanelFacadeTelegramActor{CredentialID: "rg_cred.secret"}
			},
			want: ErrActorResolverInvalidConfig,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := actorResolverConfig("cred-a", "token-a")
			tc.edit(cfg)
			_, _, err := ResolveTelegramActorCredential(cfg, "987654321")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestResolveTelegramActorCredentialUsesCurrentConfig(t *testing.T) {
	first := actorResolverConfig("cred-a", "token-a")
	second := actorResolverConfig("cred-b", "token-b")

	firstTok, firstCred, err := ResolveTelegramActorCredential(first, "123456789")
	if err != nil {
		t.Fatal(err)
	}
	if firstTok.ID != "token-a" || firstCred.ID != "cred-a" {
		t.Fatalf("unexpected first resolution: %#v %#v", firstTok, firstCred)
	}

	secondTok, secondCred, err := ResolveTelegramActorCredential(second, "123456789")
	if err != nil {
		t.Fatal(err)
	}
	if secondTok.ID != "token-b" || secondCred.ID != "cred-b" {
		t.Fatalf("stale resolution after config change: %#v %#v", secondTok, secondCred)
	}

	delete(second.PanelFacade.Actors.Telegram, "123456789")
	if _, _, err := ResolveTelegramActorCredential(second, "123456789"); !errors.Is(err, ErrActorResolverUnmappedActor) {
		t.Fatalf("got %v want unmapped after mapping removal", err)
	}
}

func actorResolverConfig(credentialID, tokenID string) *config.Config {
	return &config.Config{
		PanelFacade: config.PanelFacadeConfig{
			Enabled: true,
			Actors: config.PanelFacadeActorsConfig{Telegram: map[string]config.PanelFacadeTelegramActor{
				"123456789": {CredentialID: credentialID, DisplayName: "Alice"},
			}},
		},
		Tokens: []config.TokenPolicy{{
			ID:          tokenID,
			Scopes:      []string{"users:read"},
			Credentials: []config.Credential{{ID: credentialID, HMACSHA256: "digest"}},
		}},
	}
}
