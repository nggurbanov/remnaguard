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
