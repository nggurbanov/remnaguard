package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func safeRequestContext(req *http.Request) (string, string) {
	if req == nil {
		return "", ""
	}
	method := req.Method
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	const maxAlertPath = 256
	if len(path) > maxAlertPath {
		path = path[:maxAlertPath] + "..."
	}
	return method, path
}

func redactSensitiveAuditPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[1] != "api" || parts[2] != "sub" || parts[3] == "" {
		return path
	}
	parts[3] = "<redacted>"
	return strings.Join(parts, "/")
}

func auditSafePath(path string) string {
	return redactSensitiveAuditPath(path)
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func clientIP(req *http.Request) string {
	host := req.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > -1 {
		return host[:i]
	}
	return host
}
