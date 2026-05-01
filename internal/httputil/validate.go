package httputil

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func ValidateRawRequest(r *http.Request, maxPath, maxQuery int) (string, string, error) {
	if r.ProtoMajor >= 2 {
		return "", "", errors.New("http2_disabled")
	}
	if r.Method == http.MethodConnect || (r.Method == http.MethodOptions && r.RequestURI == "*") {
		return "", "", errors.New("unsupported_request_target")
	}
	if r.Host == "" || strings.ContainsAny(r.Host, " \t\r\n") {
		return "", "", errors.New("invalid_host")
	}
	uri := r.RequestURI
	if uri == "" || strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") || !strings.HasPrefix(uri, "/") {
		return "", "", errors.New("invalid_request_target")
	}
	path, rawQuery, _ := strings.Cut(uri, "?")
	if len(path) > maxPath || len(rawQuery) > maxQuery {
		return "", "", errors.New("request_target_too_large")
	}
	lower := strings.ToLower(path)
	if strings.Contains(path, "//") || strings.Contains(path, "\\") || strings.Contains(path, "/./") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") {
		return "", "", errors.New("ambiguous_path")
	}
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") {
		return "", "", errors.New("unsafe_encoded_path")
	}
	unescaped, err := url.PathUnescape(path)
	if err != nil || unescaped != path {
		return "", "", errors.New("path_normalization_changed")
	}
	if _, err := url.ParseQuery(rawQuery); err != nil {
		return "", "", errors.New("invalid_query")
	}
	if r.Header.Get("X-HTTP-Method-Override") != "" || r.Header.Get("X-Method-Override") != "" {
		return "", "", errors.New("method_override_denied")
	}
	if !strings.HasPrefix(path, "/api/") && path != "/api" {
		return "", "", errors.New("outside_api")
	}
	return path, rawQuery, nil
}

func StripHopByHop(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			name := strings.TrimSpace(token)
			if name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		h.Del(name)
	}
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
			h.Del(name)
		}
	}
}

func ValidateQuery(rawQuery string, allowed []string) error {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return errors.New("invalid_query")
	}
	allowedSet := map[string]bool{}
	for _, key := range allowed {
		allowedSet[key] = true
	}
	for key, vals := range values {
		if len(vals) > 1 {
			return errors.New("duplicate_query_param")
		}
		if !allowedSet[key] {
			return errors.New("unknown_query_param")
		}
		for _, val := range vals {
			if strings.ContainsAny(val, "\x00\r\n") {
				return errors.New("unsafe_query_value")
			}
		}
	}
	return nil
}

func ValidateQueryStructural(rawQuery string) error {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return errors.New("invalid_query")
	}
	for _, vals := range values {
		if len(vals) > 1 {
			return errors.New("duplicate_query_param")
		}
		for _, val := range vals {
			if strings.ContainsAny(val, "\x00\r\n") {
				return errors.New("unsafe_query_value")
			}
		}
	}
	return nil
}
