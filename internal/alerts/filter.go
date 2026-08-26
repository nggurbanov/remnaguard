package alerts

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func alertKey(ev Event) string {
	return strings.Join([]string{emptyDash(ev.TokenID), emptyDash(ev.Route), emptyDash(ev.Reason), fmt.Sprint(ev.Status)}, "|")
}

func suppressEvent(ev Event) bool {
	if ev.Route == "" && ev.Reason == "unknown_route" && ev.Status == http.StatusNotFound {
		return true
	}
	if ev.HasAuthHint || ev.TokenID != "" {
		return false
	}
	if ev.Route == "" && ev.Status == http.StatusBadRequest && scannerLikeSubscriptionPath(ev.Path) {
		return true
	}
	return strings.HasPrefix(ev.Route, "sub.") && ev.Reason == "public_subscriptions_disabled" && ev.Status == http.StatusForbidden
}

func scannerLikeSubscriptionPath(path string) bool {
	decodedPath, ok := decodedSubscriptionPath(path)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(decodedPath), ".php")
}

func decodedSubscriptionPath(path string) (string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[1] != "api" || parts[2] != "sub" || parts[3] == "" {
		return "", false
	}
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		decodedPath = path
	}
	return decodedPath, true
}
