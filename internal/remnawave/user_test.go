package remnawave

import (
	"testing"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestOwnsUserUsernamePrefix(t *testing.T) {
	tok := &config.TokenPolicy{Constraints: config.Constraints{UsernamePrefix: "restricted-"}}
	if err := OwnsUser(tok, User{Username: "restricted-alice"}); err != nil {
		t.Fatal(err)
	}
	if err := OwnsUser(tok, User{Username: "other-alice"}); err == nil {
		t.Fatal("expected foreign username denial")
	}
}

func TestDecodeUserEnvelope(t *testing.T) {
	user, err := DecodeUser([]byte(`{"response":{"uuid":"u","username":"restricted-a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "restricted-a" {
		t.Fatalf("unexpected username %q", user.Username)
	}
}

func TestIsEmptyUserResponse(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{"response":[]}`),
		[]byte(`{"response":{"users":[]}}`),
		[]byte(`[]`),
	} {
		if !IsEmptyUserResponse(body) {
			t.Fatalf("expected empty user response for %s", body)
		}
	}
	if IsEmptyUserResponse([]byte(`{"response":{"uuid":"u","username":"tenant-a"}}`)) {
		t.Fatal("single user response must not be treated as empty")
	}
}

func TestDecodeUserRemnawaveShapes(t *testing.T) {
	body := []byte(`{"response":{"users":[{"uuid":"u","username":"tenant-a","telegram_id":123,"email":"a@example.com","activeInternalSquads":[{"uuid":"internal-a"}],"externalSquad":{"uuid":"external-a"},"external_squad_uuid":"external-a","short_uuid":"short-a","subscription_page_config_uuid":"page-a"}]}}`)
	users, err := DecodeUsers(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("expected one user, got %d", len(users))
	}
	user := users[0]
	if user.Username != "tenant-a" || user.TelegramID != 123 || user.ShortUUID != "short-a" || user.SubscriptionPageConfigUUID != "page-a" {
		t.Fatalf("unexpected decoded user: %#v", user)
	}
	tok := &config.TokenPolicy{Constraints: config.Constraints{
		UsernamePrefix:                 "tenant-",
		EmailDomains:                   []string{"example.com"},
		TelegramIDRanges:               []config.IDRange{{Min: 100, Max: 200}},
		AllowedInternalSquads:          []string{"internal-a"},
		AllowedExternalSquads:          []string{"external-a"},
		AllowedSubscriptionPageConfigs: []string{"page-a"},
	}}
	if err := OwnsUser(tok, user); err != nil {
		t.Fatal(err)
	}
}

func TestOwnsUserExtendedConstraintsDenyForeignValues(t *testing.T) {
	tok := &config.TokenPolicy{Constraints: config.Constraints{
		UsernameSuffix:        "-bot",
		UsernameContains:      "tenant",
		UsernameRegex:         `^tenant-[a-z]+-bot$`,
		EmailContains:         "@example.",
		EmailDomains:          []string{"example.com"},
		TelegramIDRanges:      []config.IDRange{{Min: 10, Max: 20}},
		AllowedExternalSquads: []string{"external-a"},
	}}
	if err := OwnsUser(tok, User{Username: "tenant-alice-bot", Email: "alice@example.com", TelegramID: 15, ExternalSquadUUID: "external-b"}); err == nil {
		t.Fatal("expected external squad denial")
	}
	if err := OwnsUser(tok, User{Username: "tenant-alice", Email: "alice@example.com", TelegramID: 15, ExternalSquadUUID: "external-a"}); err == nil {
		t.Fatal("expected username denial")
	}
	if err := OwnsUser(tok, User{Username: "tenant-alice-bot", Email: "alice@other.com", TelegramID: 15, ExternalSquadUUID: "external-a"}); err == nil {
		t.Fatal("expected email denial")
	}
	if err := OwnsUser(tok, User{Username: "tenant-alice-bot", Email: "alice@example.com", TelegramID: 30, ExternalSquadUUID: "external-a"}); err == nil {
		t.Fatal("expected telegram denial")
	}
}

func TestOwnsUserRequiresEvidenceForConfiguredConstraints(t *testing.T) {
	cases := []struct {
		name string
		tok  config.TokenPolicy
		user User
	}{
		{name: "email domain", tok: config.TokenPolicy{Constraints: config.Constraints{EmailDomains: []string{"example.com"}}}, user: User{}},
		{name: "email contains", tok: config.TokenPolicy{Constraints: config.Constraints{EmailContains: "@example."}}, user: User{}},
		{name: "telegram range", tok: config.TokenPolicy{Constraints: config.Constraints{TelegramIDRanges: []config.IDRange{{Min: 10, Max: 20}}}}, user: User{}},
		{name: "internal squad", tok: config.TokenPolicy{Constraints: config.Constraints{AllowedInternalSquads: []string{"internal-a"}}}, user: User{}},
		{name: "external squad", tok: config.TokenPolicy{Constraints: config.Constraints{AllowedExternalSquads: []string{"external-a"}}}, user: User{}},
		{name: "subscription page", tok: config.TokenPolicy{Constraints: config.Constraints{AllowedSubscriptionPageConfigs: []string{"page-a"}}}, user: User{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := OwnsUser(&tc.tok, tc.user); err == nil {
				t.Fatal("expected missing ownership evidence to be denied")
			}
		})
	}
}
