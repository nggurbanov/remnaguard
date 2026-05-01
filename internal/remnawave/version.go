package remnawave

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

func DetectVersion(ctx context.Context, client *http.Client, baseURL, path string) (string, error) {
	if path == "" {
		path = "/api/system"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}
	for _, key := range []string{"version", "remnawaveVersion", "remnawave_version"} {
		if v, ok := body[key].(string); ok {
			return v, nil
		}
	}
	return "", nil
}
