package policy

import (
	"errors"
	"strings"

	"github.com/nggurbanov/remnaguard/internal/config"
)

var (
	ErrActorResolverInvalidConfig      = errors.New("actor_resolver_invalid_config")
	ErrActorResolverUnmappedActor      = errors.New("actor_resolver_unmapped_actor")
	ErrActorResolverMissingCredential  = errors.New("actor_resolver_missing_credential")
	ErrActorResolverDisabledCredential = errors.New("actor_resolver_disabled_credential")
	ErrActorResolverCacheMiss          = errors.New("actor_resolver_cache_miss")
)

func ResolveTelegramActorCredential(cfg *config.Config, actorID string) (*config.TokenPolicy, *config.Credential, error) {
	if cfg == nil || !cfg.PanelFacade.Enabled || cfg.PanelFacade.Actors.Telegram == nil {
		return nil, nil, ErrActorResolverInvalidConfig
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, nil, ErrActorResolverUnmappedActor
	}
	actor, ok := cfg.PanelFacade.Actors.Telegram[actorID]
	if !ok {
		return nil, nil, ErrActorResolverUnmappedActor
	}
	credentialID := strings.TrimSpace(actor.CredentialID)
	if credentialID == "" || strings.HasPrefix(credentialID, "rg_") {
		return nil, nil, ErrActorResolverInvalidConfig
	}
	tok, cred := cfg.FindCredential(credentialID)
	if tok != nil && cred != nil {
		return tok, cred, nil
	}
	if credentialExistsDisabled(cfg, credentialID) {
		return nil, nil, ErrActorResolverDisabledCredential
	}
	return nil, nil, ErrActorResolverMissingCredential
}

func credentialExistsDisabled(cfg *config.Config, credentialID string) bool {
	for i := range cfg.Tokens {
		for j := range cfg.Tokens[i].Credentials {
			if cfg.Tokens[i].Credentials[j].ID == credentialID {
				return cfg.Tokens[i].Disabled || cfg.Tokens[i].Credentials[j].Disabled
			}
		}
	}
	return false
}
