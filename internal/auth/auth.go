package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/nggurbanov/remnaguard/internal/config"
)

var ErrInvalid = errors.New("invalid bearer token")

type Parsed struct {
	CredentialID string
	Secret       string
}

func ParseBearer(header string) (Parsed, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return Parsed{}, ErrInvalid
	}
	raw := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if !strings.HasPrefix(raw, "rg_") {
		return Parsed{}, ErrInvalid
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, "rg_"), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Parsed{}, ErrInvalid
	}
	return Parsed{CredentialID: parts[0], Secret: parts[1]}, nil
}

func Digest(secret string, pepper []byte) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func Verify(secret string, pepper []byte, cred config.Credential) bool {
	got := Digest(secret, pepper)
	return hmac.Equal([]byte(got), []byte(cred.HMACSHA256))
}
