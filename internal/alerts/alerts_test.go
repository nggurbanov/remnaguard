package alerts

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
		Method:    http.MethodGet,
		Path:      "/api/users/by-telegram-id/1000000000000001",
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
			"method: GET",
			"path: /api/users/by-telegram-id/1000000000000001",
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
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
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
	if got := count.Load(); got != 1 {
		t.Fatalf("expected one telegram request during cooldown, got %d", got)
	}
}

func TestTelegramAlertStartsNewWindowAfterImmediateSend(t *testing.T) {
	requests := make(chan string, 2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		requests <- payload["text"]
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
			Cooldown:    5 * time.Minute,
			QueueSize:   10,
			Timeout:     time.Second,
			APIBaseURL:  ts.URL,
		},
	})
	defer m.Close()

	first := time.Date(2026, 5, 3, 1, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	for _, createdAt := range []time.Time{first, second} {
		m.Notify(Event{
			Name:      "request_denied",
			Route:     "subscription.read",
			Reason:    "auth_required",
			Status:    http.StatusUnauthorized,
			CreatedAt: createdAt,
		})
	}

	<-requests
	select {
	case text := <-requests:
		if strings.Contains(text, "first: 2026-05-03 01:00:00 UTC") {
			t.Fatalf("second alert reused stale first timestamp:\n%s", text)
		}
		for _, want := range []string{
			"count: 1 in 0s",
			"first: 2026-05-03 02:00:00 UTC",
			"last: 2026-05-03 02:00:00 UTC",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("message missing %q in:\n%s", want, text)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second telegram request")
	}
}

func TestTelegramAlertAggregatesDifferentPathsForSameDenial(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
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

	now := time.Date(2026, 5, 3, 12, 45, 0, 0, time.UTC)
	for i, path := range []string{
		"/api/sub/phpinfo.php/info",
		"/api/sub/server-status.php/info",
		"/api/sub/phpinfo.php.bak/info",
	} {
		m.Notify(Event{
			Name:      "request_denied",
			Method:    http.MethodGet,
			Path:      path,
			Route:     "subscription.read",
			Reason:    "auth_required",
			Status:    http.StatusUnauthorized,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	time.Sleep(100 * time.Millisecond)
	if got := count.Load(); got != 1 {
		t.Fatalf("expected scanner-like paths to aggregate into one telegram request, got %d", got)
	}
}

func TestTelegramAlertSuppressesUnauthenticatedUnknownRoute(t *testing.T) {
	requests := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
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

	m.Notify(Event{
		Name:      "request_denied",
		Method:    http.MethodGet,
		Path:      "/api/sub/secrets.json/info",
		Reason:    "unknown_route",
		Status:    http.StatusNotFound,
		CreatedAt: time.Date(2026, 5, 15, 19, 2, 4, 0, time.UTC),
	})

	select {
	case <-requests:
		t.Fatal("expected unauthenticated unknown_route denial to be suppressed")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTelegramAlertSendsAuthenticatedUnknownRoute(t *testing.T) {
	requests := make(chan map[string]string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			Cooldown:    time.Hour,
			QueueSize:   10,
			Timeout:     time.Second,
			APIBaseURL:  ts.URL,
		},
	})
	defer m.Close()

	m.Notify(Event{
		Name:        "request_denied",
		Method:      http.MethodGet,
		Path:        "/api/new-remnawave-route",
		Reason:      "unknown_route",
		Status:      http.StatusNotFound,
		HasAuthHint: true,
		CreatedAt:   time.Date(2026, 5, 15, 19, 2, 4, 0, time.UTC),
	})

	select {
	case payload := <-requests:
		text := payload["text"]
		for _, want := range []string{
			"path: /api/new-remnawave-route",
			"reason: unknown_route",
			"status: 404",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("message missing %q in:\n%s", want, text)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for authenticated unknown_route telegram request")
	}
}

func TestTelegramAlertSuppressesUnauthenticatedDisabledPublicSubscription(t *testing.T) {
	requests := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
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

	m.Notify(Event{
		Name:      "request_denied",
		Method:    http.MethodGet,
		Path:      "/api/sub/phpinfo.php/info",
		Route:     "sub.client",
		Reason:    "public_subscriptions_disabled",
		Status:    http.StatusForbidden,
		CreatedAt: time.Date(2026, 5, 15, 19, 2, 4, 0, time.UTC),
	})

	select {
	case <-requests:
		t.Fatal("expected unauthenticated disabled public subscription denial to be suppressed")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTelegramAlertSendsAuthenticatedDisabledPublicSubscription(t *testing.T) {
	requests := make(chan map[string]string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			Cooldown:    time.Hour,
			QueueSize:   10,
			Timeout:     time.Second,
			APIBaseURL:  ts.URL,
		},
	})
	defer m.Close()

	m.Notify(Event{
		Name:        "request_denied",
		Method:      http.MethodGet,
		Path:        "/api/sub/new-client/info",
		Route:       "sub.client",
		Reason:      "public_subscriptions_disabled",
		Status:      http.StatusForbidden,
		HasAuthHint: true,
		CreatedAt:   time.Date(2026, 5, 15, 19, 2, 4, 0, time.UTC),
	})

	select {
	case payload := <-requests:
		text := payload["text"]
		for _, want := range []string{
			"path: /api/sub/new-client/info",
			"route: sub.client",
			"reason: public_subscriptions_disabled",
			"status: 403",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("message missing %q in:\n%s", want, text)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for authenticated disabled public subscription telegram request")
	}
}
