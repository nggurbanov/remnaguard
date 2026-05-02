package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nggurbanov/remnaguard/internal/audit"
	"github.com/nggurbanov/remnaguard/internal/auth"
	"github.com/nggurbanov/remnaguard/internal/config"
	rghttp "github.com/nggurbanov/remnaguard/internal/httputil"
	"github.com/nggurbanov/remnaguard/internal/jsonpolicy"
	"github.com/nggurbanov/remnaguard/internal/metrics"
	"github.com/nggurbanov/remnaguard/internal/policy"
	"github.com/nggurbanov/remnaguard/internal/proxy"
	"github.com/nggurbanov/remnaguard/internal/ratelimit"
	"github.com/nggurbanov/remnaguard/internal/remnawave"
	"github.com/nggurbanov/remnaguard/internal/routes"
)

type Runtime struct {
	state   atomic.Pointer[runtimeState]
	version string
	commit  string
	audit   *audit.Logger
	metrics *metrics.Registry
	locks   sync.Map
	nextGen atomic.Uint64
}

type runtimeState struct {
	cfg        *config.Config
	proxy      *proxy.Proxy
	limits     *limitState
	generation uint64
	versionOK  atomic.Bool
}

type limitState struct {
	global    *ratelimit.Semaphore
	perToken  *ratelimit.PerKey
	perSubIP  *ratelimit.PerKey
	tokenRate *ratelimit.FixedWindow
	subRate   *ratelimit.FixedWindow
}

func NewRuntime(cfg *config.Config, version, commit string) (*Runtime, error) {
	auditLogger, err := audit.New(cfg.Audit.Stdout, []byte(os.Getenv(cfg.Audit.PepperEnv)), cfg.Audit.SQLitePath)
	if err != nil {
		return nil, err
	}
	st, err := newRuntimeState(cfg, 1)
	if err != nil {
		return nil, err
	}
	r := &Runtime{version: version, commit: commit, audit: auditLogger, metrics: metrics.New()}
	r.nextGen.Store(1)
	r.state.Store(st)
	return r, nil
}

func (r *Runtime) Audit() *audit.Logger { return r.audit }

func (r *Runtime) TestHandler() http.Handler { return r.apiHandler() }

func (r *Runtime) Reload(cfg *config.Config) error {
	st, err := newRuntimeState(cfg, r.nextGen.Add(1))
	if err != nil {
		return err
	}
	r.state.Store(st)
	if cfg.Compatibility.AssumeVersion == "" {
		go r.detectVersion(context.Background(), st)
	}
	return nil
}

func newRuntimeState(cfg *config.Config, generation uint64) (*runtimeState, error) {
	limits, err := newLimitState(cfg)
	if err != nil {
		return nil, err
	}
	px, err := proxy.New(cfg)
	if err != nil {
		return nil, err
	}
	st := &runtimeState{cfg: cfg, proxy: px, limits: limits, generation: generation}
	st.versionOK.Store(cfg.Compatibility.AssumeVersion != "")
	return st, nil
}

func newLimitState(cfg *config.Config) (*limitState, error) {
	tokenRate, err := ratelimit.NewFixedWindow(cfg.Limits.DefaultRate)
	if err != nil {
		return nil, err
	}
	subRate, err := ratelimit.NewFixedWindow(cfg.PublicSubs.PerIPRate)
	if err != nil {
		return nil, err
	}
	return &limitState{
		global:    ratelimit.NewSemaphore(cfg.Limits.GlobalConcurrency),
		perToken:  ratelimit.NewPerKey(cfg.Limits.PerTokenConcurrency),
		perSubIP:  ratelimit.NewPerKey(cfg.PublicSubs.PerIPConcurrency),
		tokenRate: tokenRate,
		subRate:   subRate,
	}, nil
}

func (r *Runtime) Serve(ctx context.Context) error {
	st := r.state.Load()
	cfg := st.cfg
	apiSrv := &http.Server{Addr: cfg.Server.APIListen, Handler: r.apiHandler(), ReadTimeout: cfg.Server.ReadTimeout, WriteTimeout: cfg.Server.WriteTimeout, IdleTimeout: cfg.Server.IdleTimeout, ReadHeaderTimeout: cfg.Server.HeaderTimeout, MaxHeaderBytes: cfg.Server.MaxHeaderBytes}
	localSrv := &http.Server{Addr: cfg.Server.LocalListen, Handler: r.localHandler(), ReadTimeout: cfg.Server.ReadTimeout, WriteTimeout: cfg.Server.WriteTimeout, IdleTimeout: cfg.Server.IdleTimeout, ReadHeaderTimeout: cfg.Server.HeaderTimeout, MaxHeaderBytes: cfg.Server.MaxHeaderBytes}
	go r.detectVersion(ctx, st)
	errc := make(chan error, 2)
	go func() { errc <- apiSrv.ListenAndServe() }()
	go func() { errc <- localSrv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Limits.ShutdownGracePeriod)
		defer cancel()
		_ = apiSrv.Shutdown(shutdownCtx)
		_ = localSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (r *Runtime) detectVersion(ctx context.Context, st *runtimeState) {
	cfg := st.cfg
	if cfg.Compatibility.AssumeVersion != "" {
		st.versionOK.Store(true)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got, err := remnawave.DetectVersion(ctx, st.proxy.Client(), cfg.Upstream.BaseURL, cfg.Upstream.VersionPath)
	if err != nil || got == "" {
		r.audit.Emit("version_detection_failed", "", "", "", "unknown_version", 0)
		return
	}
	ok := got == cfg.Compatibility.RemnawaveVersion || (cfg.Compatibility.AllowVersionMismatch && !isWriteUnsafeMismatch(got, cfg.Compatibility.RemnawaveVersion))
	st.versionOK.Store(ok)
	if !ok {
		r.audit.Emit("version_mismatch", "", "", "", got, 0)
	}
}

func isWriteUnsafeMismatch(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1
}

func (r *Runtime) apiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		st := r.state.Load()
		cfg := st.cfg
		if !st.limits.global.Acquire() {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		defer st.limits.global.Release()
		path, rawQuery, err := rghttp.ValidateRawRequest(req, cfg.Limits.MaxPathLength, cfg.Limits.MaxQueryLength)
		if err != nil {
			r.deny(w, "", "", "", err.Error(), http.StatusBadRequest)
			return
		}
		route, ok := routes.Match(routes.Catalog(cfg.Compatibility.EffectiveVersion()), req.Method, path)
		if !ok {
			r.deny(w, "", "", "", "unknown_route", http.StatusNotFound)
			return
		}
		route = effectiveRoute(cfg, route)
		if !st.versionOK.Load() {
			r.deny(w, route.Name, "", "", "version_guard", http.StatusServiceUnavailable)
			return
		}
		if err := validateRouteQuery(route, rawQuery); err != nil {
			r.deny(w, route.Name, "", "", err.Error(), http.StatusBadRequest)
			return
		}
		if err := bufferRequestBody(req, cfg.Limits.MaxBodyBytes); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			r.deny(w, route.Name, "", "", err.Error(), status)
			return
		}
		if route.Support == routes.PublicSubscription {
			r.handlePublicSub(w, req, st, route, path, rawQuery)
			return
		}
		parsed, err := auth.ParseBearer(req.Header.Get("Authorization"))
		if err != nil {
			r.deny(w, route.Name, "", "", "auth_required", http.StatusUnauthorized)
			return
		}
		tok, cred := cfg.FindCredential(parsed.CredentialID)
		if tok == nil || cred == nil || !auth.Verify(parsed.Secret, []byte(os.Getenv("REMNAGUARD_TOKEN_PEPPER")), *cred) {
			r.deny(w, route.Name, "", parsed.CredentialID, "invalid_token", http.StatusUnauthorized)
			return
		}
		sem := st.limits.perToken.Get(tok.ID)
		if !sem.Acquire() {
			r.deny(w, route.Name, tok.ID, cred.ID, "token_concurrency", http.StatusTooManyRequests)
			return
		}
		defer sem.Release()
		if !st.limits.tokenRate.Allow(tok.ID) {
			r.deny(w, route.Name, tok.ID, cred.ID, "token_rate_limit", http.StatusTooManyRequests)
			return
		}
		dec := policy.Decide(tok, route)
		if !dec.Allow && (!cfg.Report.Enabled || !cfg.Report.UnsafeReportProxy) {
			r.deny(w, route.Name, tok.ID, cred.ID, dec.Reason, http.StatusForbidden)
			return
		}
		if isRestrictedWrite(route) && route.Support == routes.PolicyEnforced {
			if !cfg.WriteSafety.RestrictedWritesEnabled() || !cfg.WriteSafety.SingleWriter {
				r.deny(w, route.Name, tok.ID, cred.ID, "write_safety_not_enabled", http.StatusForbidden)
				return
			}
			if err := cacheBody(req, cfg.Limits.MaxBodyBytes); err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, errBodyTooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				r.deny(w, route.Name, tok.ID, cred.ID, err.Error(), status)
				return
			}
			unlock := r.lockResource(lockKey(route, path, req))
			defer unlock()
		}
		if err := r.preflight(req, st, route, path, tok); err != nil {
			r.deny(w, route.Name, tok.ID, cred.ID, err.Error(), http.StatusForbidden)
			return
		}
		if err := validateBodyPolicy(req, cfg, route, tok); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			r.deny(w, route.Name, tok.ID, cred.ID, err.Error(), status)
			return
		}
		upstreamRes, err := st.proxy.RoundTrip(w, req, path, rawQuery, false)
		if err != nil {
			r.deny(w, route.Name, tok.ID, cred.ID, "upstream_unavailable", http.StatusBadGateway)
			return
		}
		if err := enforceResponsePolicy(route, tok, upstreamRes); err != nil {
			r.deny(w, route.Name, tok.ID, cred.ID, err.Error(), http.StatusForbidden)
			return
		}
		if err := filterResponsePolicy(route, tok, upstreamRes); err != nil {
			r.deny(w, route.Name, tok.ID, cred.ID, err.Error(), http.StatusBadGateway)
			return
		}
		if err := r.postWriteVerify(req, st, route, tok, upstreamRes); err != nil {
			r.deny(w, route.Name, tok.ID, cred.ID, err.Error(), http.StatusForbidden)
			return
		}
		st.proxy.WriteResponse(w, upstreamRes, false)
		r.audit.Emit("proxy_allowed", route.Name, tok.ID, cred.ID, "ok", 0)
	})
}

func validateRouteQuery(route routes.Route, rawQuery string) error {
	if route.Support == routes.Privileged {
		return rghttp.ValidateQueryStructural(rawQuery)
	}
	return rghttp.ValidateQuery(rawQuery, route.QueryAllowed)
}

func effectiveRoute(cfg *config.Config, route routes.Route) routes.Route {
	if !cfg.WriteSafety.RestrictedWritesEnabled() || !cfg.WriteSafety.SingleWriter {
		return route
	}
	switch route.Name {
	case "user.create":
		route.Support = routes.PolicyEnforced
		route.Scopes = []string{"users:create", "user:write"}
	case "user.update":
		route.Support = routes.PolicyEnforced
		route.Scopes = []string{"users:update", "user:write"}
	case "user.actions.disable", "user.actions.enable", "user.actions.reset_traffic", "user.actions.revoke":
		route.Support = routes.PolicyEnforced
		route.Scopes = []string{"users:action", "user:action"}
	case "hwid.create", "hwid.delete", "hwid.delete_all":
		route.Support = routes.PolicyEnforced
		route.Scopes = []string{"hwid:write"}
	}
	return route
}

func isRestrictedWrite(route routes.Route) bool {
	switch route.Name {
	case "user.create", "user.update", "user.actions.disable", "user.actions.enable", "user.actions.reset_traffic", "user.actions.revoke", "hwid.create", "hwid.delete", "hwid.delete_all":
		return true
	default:
		return false
	}
}

func (r *Runtime) handlePublicSub(w http.ResponseWriter, req *http.Request, st *runtimeState, route routes.Route, path, rawQuery string) {
	cfg := st.cfg
	if !cfg.PublicSubs.Enabled {
		r.deny(w, route.Name, "", "", "public_subscriptions_disabled", http.StatusForbidden)
		return
	}
	shortRe := regexp.MustCompile(cfg.PublicSubs.ShortUUIDRegex)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || !shortRe.MatchString(parts[2]) {
		r.deny(w, route.Name, "", "", "invalid_short_uuid", http.StatusBadRequest)
		return
	}
	if len(parts) == 4 && parts[3] != "info" && !contains(cfg.PublicSubs.AllowedClients, parts[3]) {
		r.deny(w, route.Name, "", "", "client_type_denied", http.StatusForbidden)
		return
	}
	ip := clientIP(req)
	sem := st.limits.perSubIP.Get(ip)
	if !sem.Acquire() {
		r.deny(w, route.Name, "", "", "public_subscription_concurrency", http.StatusTooManyRequests)
		return
	}
	defer sem.Release()
	if !st.limits.subRate.Allow(ip) {
		r.deny(w, route.Name, "", "", "public_subscription_rate_limit", http.StatusTooManyRequests)
		return
	}
	st.proxy.ServeHTTP(w, req, path, rawQuery, true)
	r.audit.Emit("public_subscription_proxy", route.Name, "", "", "ok", 0)
}

var errBodyTooLarge = errors.New("body_too_large")

func validateBodyPolicy(req *http.Request, cfg *config.Config, route routes.Route, tok *config.TokenPolicy) error {
	if route.Support == routes.Privileged {
		return nil
	}
	if !route.BodyObject {
		return nil
	}
	ct, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		return fmt.Errorf("json_content_type_required")
	}
	if req.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("content_encoding_denied")
	}
	limit := route.BodyLimit
	if limit <= 0 || limit > cfg.Limits.MaxBodyBytes {
		limit = cfg.Limits.MaxBodyBytes
	}
	body, err := requestBodyBytes(req, limit)
	if err != nil {
		return err
	}
	obj, err := jsonpolicy.DecodeObjectNoDuplicateKeys(bytes.NewReader(body), limit)
	if err != nil {
		return err
	}
	if err := jsonpolicy.ValidateFields(obj, route.AllowedFields); err != nil {
		return err
	}
	if err := validateTokenRequestFields(obj, route, tok); err != nil {
		return err
	}
	if strings.HasPrefix(route.Name, "user.") {
		if err := validateUserConstraints(obj, tok); err != nil {
			return err
		}
	}
	if strings.HasPrefix(route.Name, "hwid.") {
		if _, ok := obj["userUuid"]; !ok {
			return fmt.Errorf("missing_user_uuid")
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return nil
}

func bufferRequestBody(req *http.Request, limit int64) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if limit <= 0 || req.ContentLength > limit {
		return errBodyTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errBodyTooLarge
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	*req = *req.WithContext(context.WithValue(req.Context(), bodyCacheKey{}, body))
	return nil
}

func requestBodyBytes(req *http.Request, limit int64) ([]byte, error) {
	if body, ok := req.Context().Value(bodyCacheKey{}).([]byte); ok {
		if int64(len(body)) > limit {
			return nil, errBodyTooLarge
		}
		return body, nil
	}
	if err := bufferRequestBody(req, limit); err != nil {
		return nil, err
	}
	if body, ok := req.Context().Value(bodyCacheKey{}).([]byte); ok {
		return body, nil
	}
	return nil, nil
}

func validateUserConstraints(obj map[string]json.RawMessage, tok *config.TokenPolicy) error {
	if tok == nil {
		return nil
	}
	c := tok.Constraints
	if raw, ok := obj["username"]; ok {
		var username string
		if err := json.Unmarshal(raw, &username); err != nil {
			return fmt.Errorf("invalid_username")
		}
		if err := remnawave.ValidateUsername(c, username); err != nil {
			return err
		}
	}
	if raw, ok := obj["email"]; ok {
		var email *string
		if err := json.Unmarshal(raw, &email); err != nil {
			return fmt.Errorf("invalid_email")
		}
		if email != nil {
			if err := remnawave.ValidateEmail(c, *email); err != nil {
				return err
			}
		}
	}
	if raw, ok := obj["telegramId"]; ok {
		var id *int64
		if err := json.Unmarshal(raw, &id); err != nil {
			return fmt.Errorf("invalid_telegram_id")
		}
		if id != nil {
			if err := remnawave.ValidateTelegramID(c, *id); err != nil {
				return err
			}
		}
	}
	if raw, ok := obj["description"]; ok && c.MaxDescriptionLength > 0 {
		var desc *string
		if err := json.Unmarshal(raw, &desc); err != nil {
			return fmt.Errorf("invalid_description")
		}
		if desc != nil && len(*desc) > c.MaxDescriptionLength {
			return fmt.Errorf("description_too_long")
		}
	}
	if raw, ok := obj["trafficLimitBytes"]; ok {
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			if string(raw) == "null" {
				return nil
			}
			return fmt.Errorf("invalid_traffic_limit")
		}
		v, err := n.Int64()
		if err != nil {
			return fmt.Errorf("invalid_traffic_limit")
		}
		if c.ForbidUnlimitedTraffic && v <= 0 {
			return fmt.Errorf("unlimited_traffic_denied")
		}
		if c.MaxTrafficLimitBytes > 0 && v > c.MaxTrafficLimitBytes {
			return fmt.Errorf("traffic_limit_too_large")
		}
	}
	if err := validateSquadBodyFields(obj, c); err != nil {
		return err
	}
	if err := validateSubscriptionPageConfig(obj, c); err != nil {
		return err
	}
	return nil
}

func validateTokenRequestFields(obj map[string]json.RawMessage, route routes.Route, tok *config.TokenPolicy) error {
	if tok == nil || len(tok.Constraints.AllowedRequestFields) == 0 {
		return nil
	}
	allowed, ok := tok.Constraints.AllowedRequestFields[route.Name]
	if !ok {
		allowed, ok = tok.Constraints.AllowedRequestFields[route.Method+" "+route.Pattern]
	}
	if !ok {
		return nil
	}
	set := map[string]bool{}
	for _, field := range allowed {
		set[field] = true
	}
	for field := range obj {
		if !set[field] {
			return fmt.Errorf("request_field_denied")
		}
	}
	return nil
}

func validateSquadBodyFields(obj map[string]json.RawMessage, c config.Constraints) error {
	if raw, ok := obj["activeInternalSquads"]; ok && len(c.AllowedInternalSquads) > 0 {
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			var refs []struct {
				UUID string `json:"uuid"`
			}
			if err := json.Unmarshal(raw, &refs); err != nil {
				return fmt.Errorf("invalid_internal_squads")
			}
			for _, ref := range refs {
				ids = append(ids, ref.UUID)
			}
		}
		for _, id := range ids {
			if id != "" && !contains(c.AllowedInternalSquads, id) {
				return fmt.Errorf("internal_squad_denied")
			}
		}
	}
	if raw, ok := obj["externalSquadUuid"]; ok && len(c.AllowedExternalSquads) > 0 {
		var id *string
		if err := json.Unmarshal(raw, &id); err != nil {
			return fmt.Errorf("invalid_external_squad")
		}
		if id != nil && *id != "" && !contains(c.AllowedExternalSquads, *id) {
			return fmt.Errorf("external_squad_denied")
		}
	}
	return nil
}

func validateSubscriptionPageConfig(obj map[string]json.RawMessage, c config.Constraints) error {
	if len(c.AllowedSubscriptionPageConfigs) == 0 {
		return nil
	}
	for _, field := range []string{"subscriptionPageConfigUuid", "subscriptionPageConfigUUID", "subscription_page_config_uuid"} {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		var id *string
		if err := json.Unmarshal(raw, &id); err != nil {
			return fmt.Errorf("invalid_subscription_page_config")
		}
		if id != nil && *id != "" && !contains(c.AllowedSubscriptionPageConfigs, *id) {
			return fmt.Errorf("subscription_page_config_denied")
		}
	}
	return nil
}

func enforceResponsePolicy(route routes.Route, tok *config.TokenPolicy, res *proxy.Response) error {
	if route.Support != routes.PolicyEnforced {
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil
	}
	switch route.Name {
	case "user.read.uuid", "user.read.username", "user.read.telegram":
		user, err := remnawave.DecodeUser(res.Body)
		if err != nil {
			return err
		}
		return remnawave.OwnsUser(tok, user)
	default:
		return nil
	}
}

func filterResponsePolicy(route routes.Route, tok *config.TokenPolicy, res *proxy.Response) error {
	if route.Support != routes.PolicyEnforced || res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil
	}
	switch route.Name {
	case "user.list":
		return filterJSONList(res, func(item any) bool {
			body, err := json.Marshal(item)
			if err != nil {
				return false
			}
			user, err := remnawave.DecodeUser(body)
			return err == nil && remnawave.OwnsUser(tok, user) == nil
		})
	case "squad.internal.list":
		return filterJSONList(res, func(item any) bool {
			if len(tok.Constraints.AllowedInternalSquads) == 0 {
				return true
			}
			return contains(tok.Constraints.AllowedInternalSquads, objectUUID(item))
		})
	case "squad.external.list":
		return filterJSONList(res, func(item any) bool {
			if len(tok.Constraints.AllowedExternalSquads) == 0 {
				return true
			}
			return contains(tok.Constraints.AllowedExternalSquads, objectUUID(item))
		})
	default:
		return nil
	}
}

func filterJSONList(res *proxy.Response, keep func(any) bool) error {
	var root any
	dec := json.NewDecoder(bytes.NewReader(res.Body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return err
	}
	filtered, count, ok := filterListNode(root, keep)
	if !ok {
		return fmt.Errorf("unfilterable_list_response")
	}
	redactCountMetadata(filtered, count)
	body, err := json.Marshal(filtered)
	if err != nil {
		return err
	}
	res.Body = body
	res.Header.Del("Content-Length")
	return nil
}

func filterListNode(node any, keep func(any) bool) (any, int, bool) {
	switch typed := node.(type) {
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			if keep(item) {
				out = append(out, item)
			}
		}
		return out, len(out), true
	case map[string]any:
		for _, key := range []string{"response", "users", "items", "data"} {
			child, ok := typed[key]
			if !ok {
				continue
			}
			filtered, count, ok := filterListNode(child, keep)
			if ok {
				typed[key] = filtered
				return typed, count, true
			}
		}
	}
	return nil, 0, false
}

func redactCountMetadata(node any, visible int) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"total", "count", "totalItems", "total_items", "recordsTotal", "records_total"} {
		if _, ok := obj[key]; ok {
			obj[key] = visible
		}
	}
	for _, key := range []string{"response", "meta", "pagination"} {
		if child, ok := obj[key]; ok {
			redactCountMetadata(child, visible)
		}
	}
}

func objectUUID(item any) string {
	obj, ok := item.(map[string]any)
	if !ok {
		return ""
	}
	if s, ok := obj["uuid"].(string); ok {
		return s
	}
	return ""
}

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
	v, _ := r.locks.LoadOrStore(key, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
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

func (r *Runtime) localHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !r.state.Load().versionOK.Load() {
			http.Error(w, "not ready: version guard closed", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": r.version})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		if !r.state.Load().cfg.Metrics.Enabled {
			http.NotFound(w, req)
			return
		}
		r.metrics.ServeHTTP(w, req)
	})
	return mux
}

func (r *Runtime) deny(w http.ResponseWriter, route, tokenID, credentialID, reason string, status int) {
	r.audit.Emit("request_denied", route, tokenID, credentialID, reason, status)
	http.Error(w, fmt.Sprintf("denied: %s", reason), status)
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
