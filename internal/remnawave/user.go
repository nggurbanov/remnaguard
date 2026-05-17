package remnawave

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nggurbanov/remnaguard/internal/config"
)

type User struct {
	UUID                       string          `json:"uuid"`
	ShortUUID                  string          `json:"shortUuid"`
	Username                   string          `json:"username"`
	TelegramID                 int64           `json:"telegramId"`
	Email                      string          `json:"email"`
	InternalSquads             []SquadRef      `json:"internalSquads"`
	ActiveInternalSquads       []SquadRef      `json:"activeInternalSquads"`
	ExternalSquads             []SquadRef      `json:"externalSquads"`
	ExternalSquad              *SquadRef       `json:"externalSquad"`
	ExternalSquadUUID          string          `json:"externalSquadUuid"`
	SubscriptionPageConfigUUID string          `json:"subscriptionPageConfigUuid"`
	Raw                        json.RawMessage `json:"-"`
}

type SquadRef struct {
	UUID string `json:"uuid"`
}

func DecodeUser(body []byte) (User, error) {
	users, err := DecodeUsers(body)
	if err != nil {
		return User{}, err
	}
	if len(users) != 1 {
		return User{}, errors.New("unparseable_user_response")
	}
	return users[0], nil
}

func IsEmptyUserResponse(body []byte) bool {
	var root any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return false
	}
	return isEmptyUserNode(root)
}

func isEmptyUserNode(v any) bool {
	switch typed := v.(type) {
	case []any:
		return len(typed) == 0
	case map[string]any:
		for _, key := range []string{"response", "user", "users", "items", "data"} {
			if child, ok := typed[key]; ok {
				return isEmptyUserNode(child)
			}
		}
	}
	return false
}

func DecodeUsers(body []byte) ([]User, error) {
	var root any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	users := collectUsers(root)
	if len(users) == 0 {
		return nil, errors.New("unparseable_user_response")
	}
	return users, nil
}

func collectUsers(v any) []User {
	switch typed := v.(type) {
	case []any:
		var out []User
		for _, item := range typed {
			if user, ok := parseUserObject(item); ok {
				out = append(out, user)
			}
		}
		return out
	case map[string]any:
		if user, ok := parseUserObject(typed); ok {
			return []User{user}
		}
		for _, key := range []string{"response", "user", "users", "items", "data"} {
			if child, ok := typed[key]; ok {
				if users := collectUsers(child); len(users) > 0 {
					return users
				}
			}
		}
	}
	return nil
}

func parseUserObject(v any) (User, bool) {
	obj, ok := v.(map[string]any)
	if !ok {
		return User{}, false
	}
	username := stringField(obj, "username")
	uuid := stringField(obj, "uuid")
	if username == "" && uuid == "" {
		return User{}, false
	}
	user := User{
		UUID:                       uuid,
		ShortUUID:                  firstString(obj, "shortUuid", "short_uuid"),
		Username:                   username,
		TelegramID:                 int64Field(obj, "telegramId", "telegram_id"),
		Email:                      stringField(obj, "email"),
		InternalSquads:             squadRefs(obj["internalSquads"]),
		ActiveInternalSquads:       squadRefs(obj["activeInternalSquads"]),
		ExternalSquads:             squadRefs(obj["externalSquads"]),
		ExternalSquadUUID:          firstString(obj, "externalSquadUuid", "external_squad_uuid"),
		SubscriptionPageConfigUUID: firstString(obj, "subscriptionPageConfigUuid", "subscriptionPageConfigUUID", "subscription_page_config_uuid"),
	}
	if ext, ok := parseSquadRef(obj["externalSquad"]); ok {
		user.ExternalSquad = &ext
	}
	raw, _ := json.Marshal(obj)
	user.Raw = raw
	return user, true
}

func OwnsUser(tok *config.TokenPolicy, user User) error {
	if tok == nil {
		return errors.New("missing_token")
	}
	c := tok.Constraints
	if err := ValidateUsername(c, user.Username); err != nil {
		return err
	}
	if err := ValidateEmail(c, user.Email); err != nil {
		return err
	}
	if err := ValidateTelegramID(c, user.TelegramID); err != nil {
		return err
	}
	internal := append([]SquadRef{}, user.InternalSquads...)
	internal = append(internal, user.ActiveInternalSquads...)
	if len(c.AllowedInternalSquads) > 0 {
		if len(internal) == 0 {
			return errors.New("missing_internal_squad")
		}
		if !squadsAllowed(internal, c.AllowedInternalSquads) {
			return errors.New("internal_squad_denied")
		}
	}
	external := append([]SquadRef{}, user.ExternalSquads...)
	if user.ExternalSquad != nil {
		external = append(external, *user.ExternalSquad)
	}
	if user.ExternalSquadUUID != "" {
		external = append(external, SquadRef{UUID: user.ExternalSquadUUID})
	}
	if len(c.AllowedExternalSquads) > 0 {
		if len(external) == 0 {
			return errors.New("missing_external_squad")
		}
		if !squadsAllowed(external, c.AllowedExternalSquads) {
			return errors.New("external_squad_denied")
		}
	}
	if len(c.AllowedSubscriptionPageConfigs) > 0 {
		if user.SubscriptionPageConfigUUID == "" {
			return errors.New("missing_subscription_page_config")
		}
		if !contains(c.AllowedSubscriptionPageConfigs, user.SubscriptionPageConfigUUID) {
			return errors.New("subscription_page_config_denied")
		}
	}
	return nil
}

func ValidateUsername(c config.Constraints, username string) error {
	if username == "" && (c.UsernamePrefix != "" || c.UsernameSuffix != "" || c.UsernameContains != "" || c.UsernameRegex != "") {
		return errors.New("missing_username")
	}
	if c.UsernamePrefix != "" && !strings.HasPrefix(username, c.UsernamePrefix) {
		return errors.New("foreign_username")
	}
	if c.UsernameSuffix != "" && !strings.HasSuffix(username, c.UsernameSuffix) {
		return errors.New("username_suffix_denied")
	}
	if c.UsernameContains != "" && !strings.Contains(username, c.UsernameContains) {
		return errors.New("username_contains_denied")
	}
	if c.UsernameRegex != "" {
		re, err := regexp.Compile(c.UsernameRegex)
		if err != nil {
			return fmt.Errorf("invalid_username_regex")
		}
		if !re.MatchString(username) {
			return errors.New("username_regex_denied")
		}
	}
	return nil
}

func ValidateEmail(c config.Constraints, email string) error {
	if email == "" {
		if c.EmailContains != "" || len(c.EmailDomains) > 0 {
			return errors.New("missing_email")
		}
		return nil
	}
	lower := strings.ToLower(email)
	if c.EmailContains != "" && !strings.Contains(lower, strings.ToLower(c.EmailContains)) {
		return errors.New("email_contains_denied")
	}
	if len(c.EmailDomains) > 0 {
		_, domain, ok := strings.Cut(lower, "@")
		if !ok || !containsFold(c.EmailDomains, domain) {
			return errors.New("email_domain_denied")
		}
	}
	return nil
}

func ValidateTelegramID(c config.Constraints, id int64) error {
	if len(c.TelegramIDRanges) == 0 {
		return nil
	}
	if id == 0 {
		return errors.New("missing_telegram_id")
	}
	for _, r := range c.TelegramIDRanges {
		if id >= r.Min && id <= r.Max {
			return nil
		}
	}
	return errors.New("telegram_id_denied")
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

func squadRefs(v any) []SquadRef {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []SquadRef
	for _, item := range items {
		if ref, ok := parseSquadRef(item); ok {
			out = append(out, ref)
		}
	}
	return out
}

func parseSquadRef(v any) (SquadRef, bool) {
	switch typed := v.(type) {
	case string:
		return SquadRef{UUID: typed}, typed != ""
	case map[string]any:
		uuid := firstString(typed, "uuid", "squadUuid", "squad_uuid", "externalSquadUuid", "external_squad_uuid")
		return SquadRef{UUID: uuid}, uuid != ""
	default:
		return SquadRef{}, false
	}
}

func stringField(obj map[string]any, key string) string {
	if v, ok := obj[key].(string); ok {
		return v
	}
	return ""
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := stringField(obj, key); v != "" {
			return v
		}
	}
	return ""
}

func int64Field(obj map[string]any, keys ...string) int64 {
	for _, key := range keys {
		switch v := obj[key].(type) {
		case json.Number:
			n, _ := v.Int64()
			return n
		case float64:
			return int64(v)
		case string:
			var n int64
			_, _ = fmt.Sscan(v, &n)
			return n
		}
	}
	return 0
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func containsFold(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, want) {
			return true
		}
	}
	return false
}
