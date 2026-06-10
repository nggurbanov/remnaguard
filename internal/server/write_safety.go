package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/proxy"
	"github.com/nggurbanov/remnaguard/internal/remnawave"
	"github.com/nggurbanov/remnaguard/internal/routes"
)

func (r *Runtime) preflight(req *http.Request, st *runtimeState, route routes.Route, path string, tok *config.TokenPolicy) error {
	if route.Support != routes.PolicyEnforced {
		return nil
	}
	switch route.Name {
	case "hwid.list":
		uuid := pathSegment(path, 3)
		return r.preflightUser(req, st, uuid, tok)
	case "user.update":
		uuid := bodyString(req, "uuid")
		if uuid == "" {
			return fmt.Errorf("missing_user_uuid")
		}
		return r.preflightUser(req, st, uuid, tok)
	case "user.actions.disable", "user.actions.enable", "user.actions.reset_traffic", "user.actions.revoke":
		return r.preflightUser(req, st, pathSegment(path, 2), tok)
	case "hwid.create", "hwid.delete", "hwid.delete_all":
		uuid := bodyString(req, "userUuid")
		if uuid == "" {
			return fmt.Errorf("missing_user_uuid")
		}
		return r.preflightUser(req, st, uuid, tok)
	case "post.nodes.uuid.actions.disable", "post.nodes.uuid.actions.enable", "post.nodes.uuid.actions.restart", "post.nodes.uuid.actions.reset_traffic":
		return requireAllowedUUIDOrAll(pathSegment(path, 2), tok.Constraints.AllowedNodes, tok.Constraints.AllowAllNodes, "node_denied")
	case "squad.internal.read":
		if len(tok.Constraints.AllowedInternalSquads) > 0 && !contains(tok.Constraints.AllowedInternalSquads, pathSegment(path, 2)) {
			return fmt.Errorf("internal_squad_denied")
		}
	case "squad.external.read":
		if len(tok.Constraints.AllowedExternalSquads) > 0 && !contains(tok.Constraints.AllowedExternalSquads, pathSegment(path, 2)) {
			return fmt.Errorf("external_squad_denied")
		}
	}
	return nil
}

func (r *Runtime) preflightUser(req *http.Request, st *runtimeState, uuid string, tok *config.TokenPolicy) error {
	if uuid == "" {
		return fmt.Errorf("missing_user_uuid")
	}
	if len(tok.Constraints.AllowedUsers) > 0 && !contains(tok.Constraints.AllowedUsers, uuid) {
		return fmt.Errorf("user_denied")
	}
	preReq := req.Clone(req.Context())
	preReq.Method = http.MethodGet
	preReq.Body = nil
	preReq.ContentLength = 0
	preReq.GetBody = nil
	preReq.Header.Del("Content-Type")
	res, err := st.proxy.RoundTrip(dummyResponseWriter{}, preReq, "/api/users/"+uuid, "", false)
	if err != nil {
		return fmt.Errorf("preflight_failed")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("preflight_denied")
	}
	user, err := remnawave.DecodeUser(res.Body)
	if err != nil {
		return err
	}
	return remnawave.OwnsUser(tok, user)
}

func (r *Runtime) postWriteVerify(req *http.Request, st *runtimeState, route routes.Route, tok *config.TokenPolicy, res *proxy.Response) error {
	if !isRestrictedWrite(route) || route.Support != routes.PolicyEnforced || res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil
	}
	switch route.Name {
	case "user.create":
		user, err := remnawave.DecodeUser(res.Body)
		if err == nil {
			return remnawave.OwnsUser(tok, user)
		}
		return fmt.Errorf("post_write_unverifiable")
	case "user.update":
		return r.preflightUser(req, st, bodyString(req, "uuid"), tok)
	case "user.actions.disable", "user.actions.enable", "user.actions.reset_traffic", "user.actions.revoke":
		return r.preflightUser(req, st, pathSegment(routeTarget(req), 2), tok)
	case "hwid.create", "hwid.delete", "hwid.delete_all":
		return r.preflightUser(req, st, bodyString(req, "userUuid"), tok)
	default:
		return nil
	}
}

func (r *Runtime) lockResource(key string) func() {
	return r.locks.Lock(key)
}

type keyedLocker struct {
	mu sync.Mutex
	m  map[string]*lockEntry
}

type lockEntry struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedLocker) Lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*lockEntry{}
	}
	entry := k.m[key]
	if entry == nil {
		entry = &lockEntry{}
		k.m[key] = entry
	}
	entry.refs++
	k.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		k.mu.Lock()
		entry.refs--
		if entry.refs == 0 && k.m[key] == entry {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

func (k *keyedLocker) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

func lockKey(route routes.Route, path string, req *http.Request) string {
	switch route.Name {
	case "user.create":
		return "user:create:" + bodyString(req, "username")
	case "user.update", "hwid.create", "hwid.delete", "hwid.delete_all":
		return route.Name + ":" + bodyString(req, "uuid") + ":" + bodyString(req, "userUuid")
	default:
		return route.Name + ":" + path
	}
}

func bodyString(req *http.Request, field string) string {
	bodyAny := req.Context().Value(bodyCacheKey{})
	var body []byte
	if cached, ok := bodyAny.([]byte); ok {
		body = cached
	} else {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return ""
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(obj[field], &s); err == nil {
		return s
	}
	return ""
}

type bodyCacheKey struct{}

func cacheBody(req *http.Request, limit int64) error {
	return bufferRequestBody(req, limit)
}

func routeTarget(req *http.Request) string {
	path, _, _ := strings.Cut(req.RequestURI, "?")
	return path
}

func pathSegment(path string, idx int) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	return parts[idx]
}

type dummyResponseWriter struct{}

func (dummyResponseWriter) Header() http.Header       { return http.Header{} }
func (dummyResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (dummyResponseWriter) WriteHeader(int)           {}
