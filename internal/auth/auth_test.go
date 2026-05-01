package auth

import (
	"testing"

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
	pepper := []byte("pepper")
	cred := config.Credential{ID: "cred", HMACSHA256: Digest("secret", pepper)}
	if !Verify("secret", pepper, cred) {
		t.Fatal("expected secret to verify")
	}
	if Verify("other", pepper, cred) {
		t.Fatal("expected wrong secret to fail")
	}
}
