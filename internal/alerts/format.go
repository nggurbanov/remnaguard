package alerts

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func formatMessage(b bucket) string {
	icon := "🚨"
	if b.event.Status == http.StatusTooManyRequests {
		icon = "⚠️"
	}
	return fmt.Sprintf(
		"%s RemnaGuard deny\n\n"+
			"token: %s\n"+
			"method: %s\n"+
			"path: %s\n"+
			"route: %s\n"+
			"reason: %s\n"+
			"status: %d\n\n"+
			"count: %d in %s\n"+
			"first: %s UTC\n"+
			"last: %s UTC",
		icon,
		emptyDash(b.event.TokenID),
		emptyDash(b.event.Method),
		emptyDash(redactAlertPath(b.event.Path)),
		emptyDash(b.event.Route),
		emptyDash(b.event.Reason),
		b.event.Status,
		b.count,
		roundDuration(b.last.Sub(b.first)),
		b.first.UTC().Format("2006-01-02 15:04:05"),
		b.last.UTC().Format("2006-01-02 15:04:05"),
	)
}

func redactAlertPath(path string) string {
	if path == "" {
		return path
	}
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[1] != "api" || parts[2] != "sub" || parts[3] == "" {
		return path
	}
	parts[3] = "<redacted>"
	return strings.Join(parts, "/")
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func roundDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return 0
	}
	return d.Round(time.Second)
}
