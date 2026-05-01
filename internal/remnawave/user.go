package remnawave

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/nggurbanov/remnaguard/internal/config"
)

type User struct {
	UUID           string          `json:"uuid"`
	Username       string          `json:"username"`
	InternalSquads []SquadRef      `json:"internalSquads"`
	ExternalSquads []SquadRef      `json:"externalSquads"`
	Raw            json.RawMessage `json:"-"`
}

type SquadRef struct {
	UUID string `json:"uuid"`
}

func DecodeUser(body []byte) (User, error) {
	var envelope struct {
		Response User `json:"response"`
		User     User `json:"user"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		switch {
		case envelope.Response.Username != "":
			envelope.Response.Raw = body
			return envelope.Response, nil
		case envelope.User.Username != "":
			envelope.User.Raw = body
			return envelope.User, nil
		}
	}
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return User{}, err
	}
	if user.Username == "" {
		return User{}, errors.New("unparseable_user_response")
	}
	user.Raw = body
	return user, nil
}

func OwnsUser(tok *config.TokenPolicy, user User) error {
	c := tok.Constraints
	if c.UsernamePrefix != "" && !strings.HasPrefix(user.Username, c.UsernamePrefix) {
		return errors.New("foreign_username")
	}
	if len(c.AllowedInternalSquads) > 0 && !squadsAllowed(user.InternalSquads, c.AllowedInternalSquads) {
		return errors.New("internal_squad_denied")
	}
	if len(c.AllowedExternalSquads) > 0 && !squadsAllowed(user.ExternalSquads, c.AllowedExternalSquads) {
		return errors.New("external_squad_denied")
	}
	return nil
}

func squadsAllowed(squads []SquadRef, allowed []string) bool {
	set := map[string]bool{}
	for _, id := range allowed {
		set[id] = true
	}
	for _, squad := range squads {
		if squad.UUID != "" && !set[squad.UUID] {
			return false
		}
	}
	return true
}
