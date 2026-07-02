package alerts

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestTelegramAlertSuppressesUnauthenticatedEncodedPHPScannerPath(t *testing.T) {
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
		Path:      "/api/sub/alexusmailer%202.0.php",
		Reason:    "path_normalization_changed",
		Status:    http.StatusBadRequest,
		CreatedAt: time.Date(2026, 7, 2, 17, 20, 28, 0, time.UTC),
	})

	select {
	case <-requests:
		t.Fatal("expected unauthenticated encoded PHP scanner denial to be suppressed")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestScannerLikeSubscriptionPathMatchesPHPAnywhere(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "encoded php suffix",
			path: "/api/sub/alexusmailer%202.0.php",
			want: true,
		},
		{
			name: "php segment before another path segment",
			path: "/api/sub/phpinfo.php/info",
			want: true,
		},
		{
			name: "subscription uuid",
			path: "/api/sub/AUEHeo0wfYu5dqMY",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scannerLikeSubscriptionPath(tt.path); got != tt.want {
				t.Fatalf("scannerLikeSubscriptionPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
