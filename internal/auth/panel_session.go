package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/nggurbanov/remnaguard/internal/config"
)

const panelSessionPrefix = "panel_"

var ErrInvalidPanelSession = errors.New("invalid panel session token")

type PanelSessionClaims struct {
	Issuer          string `json:"iss"`
	Audience        string `json:"aud"`
	ExpiresAt       int64  `json:"exp"`
	IssuedAt        int64  `json:"iat"`
	TelegramActorID string `json:"telegram_actor_id"`
}

func IssuePanelSession(panel config.PanelFacadeConfig, telegramActorID string, now time.Time) (string, error) {
	if err := validatePanelSessionConfig(panel); err != nil {
		return "", err
	}
	telegramActorID = strings.TrimSpace(telegramActorID)
	if telegramActorID == "" {
		return "", ErrInvalidPanelSession
	}
	claims := PanelSessionClaims{
		Issuer:          panel.Session.Issuer,
		Audience:        panel.Session.Audience,
		ExpiresAt:       now.Add(panel.Session.TokenTTL).Unix(),
		IssuedAt:        now.Unix(),
		TelegramActorID: telegramActorID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := signPanelSession(encodedPayload, []byte(os.Getenv(panel.Session.SecretEnv)))
	return panelSessionPrefix + encodedPayload + "." + signature, nil
}

func ValidatePanelSession(panel config.PanelFacadeConfig, token string, now time.Time) (PanelSessionClaims, error) {
	if err := validatePanelSessionConfig(panel); err != nil {
		return PanelSessionClaims{}, err
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, panelSessionPrefix) {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	parts := strings.Split(strings.TrimPrefix(token, panelSessionPrefix), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	secret := []byte(os.Getenv(panel.Session.SecretEnv))
	expected := signPanelSession(parts[0], secret)
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	var claims PanelSessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	if claims.Issuer != panel.Session.Issuer || claims.Audience != panel.Session.Audience {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	if strings.TrimSpace(claims.TelegramActorID) == "" {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	if claims.ExpiresAt <= now.Unix() {
		return PanelSessionClaims{}, ErrInvalidPanelSession
	}
	return claims, nil
}

func validatePanelSessionConfig(panel config.PanelFacadeConfig) error {
	if !panel.Enabled {
		return ErrInvalidPanelSession
	}
	if strings.TrimSpace(panel.Session.Issuer) == "" || strings.TrimSpace(panel.Session.Audience) == "" || panel.Session.TokenTTL <= 0 {
		return ErrInvalidPanelSession
	}
	if strings.TrimSpace(panel.Session.SecretEnv) == "" || strings.TrimSpace(os.Getenv(panel.Session.SecretEnv)) == "" {
		return ErrInvalidPanelSession
	}
	return nil
}

func signPanelSession(encodedPayload string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(encodedPayload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
