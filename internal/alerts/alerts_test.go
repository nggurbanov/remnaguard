package alerts

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestTelegramAlertSendsDeniedRequestMessage(t *testing.T) {
	requests := make(chan map[string]string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bottest-token/sendMessage" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		requests <- payload
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	t.Setenv("ALERT_TOKEN", "test-token")
	t.Setenv("ALERT_CHAT", "12345")
	m := NewManager(config.AlertsConfig{
		Enabled: true,
		Telegram: config.TelegramAlertsConfig{
			Enabled:     true,
			BotTokenEnv: "ALERT_TOKEN",
			ChatIDEnv:   "ALERT_CHAT",
			Cooldown:    time.Minute,
			QueueSize:   10,
			Timeout:     time.Second,
			APIBaseURL:  ts.URL,
		},
	})
	defer m.Close()

	m.Notify(Event{
		Name:      "request_denied",
		Route:     "user.read.telegram",
		TokenID:   "batconnect-core",
		Reason:    "telegram_id_denied",
		Status:    http.StatusForbidden,
		CreatedAt: time.Date(2026, 5, 3, 1, 18, 22, 0, time.UTC),
	})

	select {
	case payload := <-requests:
		if payload["chat_id"] != "12345" {
			t.Fatalf("unexpected chat_id %q", payload["chat_id"])
		}
		text := payload["text"]
		for _, want := range []string{
			"RemnaGuard deny",
			"token: batconnect-core",
			"route: user.read.telegram",
			"reason: telegram_id_denied",
			"status: 403",
			"count: 1",
			"first: 2026-05-03 01:18:22 UTC",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("message missing %q in:\n%s", want, text)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telegram request")
	}
}

func TestTelegramAlertCooldownSuppressesDuplicateBurst(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	t.Setenv("ALERT_TOKEN", "test-token")
	t.Setenv("ALERT_CHAT", "12345")
	m := NewManager(config.AlertsConfig{
		Enabled: true,
		Telegram: config.TelegramAlertsConfig{
			Enabled:     true,
			BotTokenEnv: "ALERT_TOKEN",
			ChatIDEnv:   "ALERT_CHAT",
			Cooldown:    time.Hour,
			QueueSize:   10,
			Timeout:     time.Second,
			APIBaseURL:  ts.URL,
		},
	})
	defer m.Close()

	now := time.Date(2026, 5, 3, 1, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		m.Notify(Event{
			Name:      "request_denied",
			Route:     "user.read.telegram",
			TokenID:   "batconnect-core",
			Reason:    "telegram_id_denied",
			Status:    http.StatusForbidden,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	time.Sleep(100 * time.Millisecond)
	if count != 1 {
		t.Fatalf("expected one telegram request during cooldown, got %d", count)
	}
}
