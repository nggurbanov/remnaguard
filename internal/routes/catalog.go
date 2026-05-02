package routes

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Support string

const (
	PolicyEnforced     Support = "policy-enforced"
	Privileged         Support = "privileged"
	Unsupported        Support = "unsupported"
	PublicSubscription Support = "public-subscription"
)

type Route struct {
	Name              string
	Method            string
	Pattern           string
	Support           Support
	Scopes            []string
	QueryAllowed      []string
	BodyLimit         int64
	BodyObject        bool
	AllowedFields     []string
	Group             string
	UnsupportedReason string
	re                *regexp.Regexp
}

func Catalog(version string) []Route {
	if version != "2.7.4" {
		return nil
	}
	return compile(remnawave274Catalog())
}

func remnawave274Catalog() []Route {
	routes := make([]Route, 0, 185)
	for _, line := range strings.Split(remnawave274Operations, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		method, pattern, _ := strings.Cut(line, " ")
		routes = append(routes, Route{
			Name:    routeName(method, pattern),
			Method:  method,
			Pattern: pattern,
			Support: Privileged,
			Scopes:  []string{"remnawave:*"},
			Group:   routeGroup(pattern),
		})
	}
	overrides := []Route{
		{Name: "user.read.uuid", Method: http.MethodGet, Pattern: "/api/users/{uuid}", Support: PolicyEnforced, Scopes: []string{"users:read"}, QueryAllowed: []string{"includeHwid", "includeSubscription"}, Group: "users"},
		{Name: "user.read.username", Method: http.MethodGet, Pattern: "/api/users/by-username/{username}", Support: PolicyEnforced, Scopes: []string{"users:read"}, QueryAllowed: []string{"includeHwid", "includeSubscription"}, Group: "users"},
		{Name: "user.read.telegram", Method: http.MethodGet, Pattern: "/api/users/by-telegram-id/{telegramId}", Support: PolicyEnforced, Scopes: []string{"users:read"}, QueryAllowed: []string{"includeHwid", "includeSubscription"}, Group: "users"},
		{Name: "user.list", Method: http.MethodGet, Pattern: "/api/users", Support: PolicyEnforced, Scopes: []string{"users:read"}, QueryAllowed: []string{"page", "size", "limit", "offset", "search", "username", "includeHwid", "includeSubscription"}, Group: "users"},
		{Name: "user.create", Method: http.MethodPost, Pattern: "/api/users", Support: Privileged, Scopes: []string{"remnawave:*"}, BodyLimit: 65536, BodyObject: true, AllowedFields: userFields(), Group: "users"},
		{Name: "user.update", Method: http.MethodPatch, Pattern: "/api/users", Support: Privileged, Scopes: []string{"remnawave:*"}, BodyLimit: 65536, BodyObject: true, AllowedFields: userUpdateFields(), Group: "users"},
		{Name: "user.delete", Method: http.MethodDelete, Pattern: "/api/users/{uuid}", Support: Privileged, Scopes: []string{"remnawave:*"}, Group: "users"},
		{Name: "user.actions.disable", Method: http.MethodPost, Pattern: "/api/users/{uuid}/actions/disable", Support: Privileged, Scopes: []string{"remnawave:*"}, Group: "users"},
		{Name: "user.actions.enable", Method: http.MethodPost, Pattern: "/api/users/{uuid}/actions/enable", Support: Privileged, Scopes: []string{"remnawave:*"}, Group: "users"},
		{Name: "user.actions.reset_traffic", Method: http.MethodPost, Pattern: "/api/users/{uuid}/actions/reset-traffic", Support: Privileged, Scopes: []string{"remnawave:*"}, Group: "users"},
		{Name: "user.actions.revoke", Method: http.MethodPost, Pattern: "/api/users/{uuid}/actions/revoke", Support: Privileged, Scopes: []string{"remnawave:*"}, Group: "users"},
		{Name: "hwid.list", Method: http.MethodGet, Pattern: "/api/hwid/devices/{userUuid}", Support: PolicyEnforced, Scopes: []string{"hwid:read"}, Group: "hwid"},
		{Name: "hwid.create", Method: http.MethodPost, Pattern: "/api/hwid/devices", Support: Privileged, Scopes: []string{"remnawave:*"}, BodyLimit: 8192, BodyObject: true, AllowedFields: []string{"hwid", "userUuid", "platform", "osVersion", "deviceModel", "userAgent"}, Group: "hwid"},
		{Name: "hwid.delete", Method: http.MethodPost, Pattern: "/api/hwid/devices/delete", Support: Privileged, Scopes: []string{"remnawave:*"}, BodyLimit: 8192, BodyObject: true, AllowedFields: []string{"userUuid", "hwid"}, Group: "hwid"},
		{Name: "hwid.delete_all", Method: http.MethodPost, Pattern: "/api/hwid/devices/delete-all", Support: Privileged, Scopes: []string{"remnawave:*"}, BodyLimit: 8192, BodyObject: true, AllowedFields: []string{"userUuid"}, Group: "hwid"},
		{Name: "squad.internal.read", Method: http.MethodGet, Pattern: "/api/internal-squads/{uuid}", Support: PolicyEnforced, Scopes: []string{"squads:read"}, Group: "internal-squads"},
		{Name: "squad.external.read", Method: http.MethodGet, Pattern: "/api/external-squads/{uuid}", Support: PolicyEnforced, Scopes: []string{"squads:read"}, Group: "external-squads"},
		{Name: "squad.internal.list", Method: http.MethodGet, Pattern: "/api/internal-squads", Support: PolicyEnforced, Scopes: []string{"squads:read"}, QueryAllowed: []string{"page", "size", "limit", "offset", "search"}, Group: "internal-squads"},
		{Name: "squad.external.list", Method: http.MethodGet, Pattern: "/api/external-squads", Support: PolicyEnforced, Scopes: []string{"squads:read"}, QueryAllowed: []string{"page", "size", "limit", "offset", "search"}, Group: "external-squads"},
		{Name: "system.health", Method: http.MethodGet, Pattern: "/api/system/health", Support: PolicyEnforced, Scopes: []string{"system:read"}, Group: "system"},
		{Name: "system.metadata", Method: http.MethodGet, Pattern: "/api/system/metadata", Support: PolicyEnforced, Scopes: []string{"metadata:read"}, Group: "metadata"},
		{Name: "system.bandwidth", Method: http.MethodGet, Pattern: "/api/system/stats/bandwidth", Support: PolicyEnforced, Scopes: []string{"system:read"}, Group: "bandwidth-stats"},
		{Name: "system.stats", Method: http.MethodGet, Pattern: "/api/system/stats", Support: PolicyEnforced, Scopes: []string{"system:read"}, Group: "system"},
		{Name: "sub.info", Method: http.MethodGet, Pattern: "/api/sub/{shortUuid}/info", Support: PublicSubscription, Group: "subscriptions"},
		{Name: "sub.base", Method: http.MethodGet, Pattern: "/api/sub/{shortUuid}", Support: PublicSubscription, Group: "subscriptions"},
		{Name: "sub.client", Method: http.MethodGet, Pattern: "/api/sub/{shortUuid}/{clientType}", Support: PublicSubscription, Group: "subscriptions"},
		{Name: "subscription_page_config.list", Method: http.MethodGet, Pattern: "/api/subscription-page-configs", Support: PolicyEnforced, Scopes: []string{"subscription-pages:read"}, Group: "subscription-page-configs"},
		{Name: "subscription_page_config.read", Method: http.MethodGet, Pattern: "/api/subscription-page-configs/{uuid}", Support: PolicyEnforced, Scopes: []string{"subscription-pages:read"}, Group: "subscription-page-configs"},
		{Name: "subscription.subpage_config", Method: http.MethodGet, Pattern: "/api/subscriptions/subpage-config/{shortUuid}", Support: PolicyEnforced, Scopes: []string{"subscriptions:read", "subscription:read"}, Group: "subscriptions"},
	}
	byKey := map[string]int{}
	for i := range routes {
		byKey[routeKey(routes[i].Method, routes[i].Pattern)] = i
	}
	for _, override := range overrides {
		if idx, ok := byKey[routeKey(override.Method, override.Pattern)]; ok {
			routes[idx] = override
		} else {
			routes = append(routes, override)
		}
	}
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].Method != routes[j].Method {
			return routes[i].Method < routes[j].Method
		}
		return specificity(routes[i].Pattern) > specificity(routes[j].Pattern)
	})
	return routes
}

const remnawave274Operations = `
DELETE /api/config-profiles/{uuid}
DELETE /api/external-squads/{uuid}
DELETE /api/external-squads/{uuid}/bulk-actions/remove-users
DELETE /api/hosts/{uuid}
DELETE /api/infra-billing/history/{uuid}
DELETE /api/infra-billing/nodes/{uuid}
DELETE /api/infra-billing/providers/{uuid}
DELETE /api/internal-squads/{uuid}
DELETE /api/internal-squads/{uuid}/bulk-actions/remove-users
DELETE /api/node-plugins/torrent-blocker/truncate
DELETE /api/node-plugins/{uuid}
DELETE /api/nodes/{uuid}
DELETE /api/passkeys
DELETE /api/snippets
DELETE /api/subscription-page-configs/{uuid}
DELETE /api/subscription-templates/{uuid}
DELETE /api/tokens/{uuid}
DELETE /api/users/{uuid}
GET /api/auth/passkey/authentication/options
GET /api/auth/status
GET /api/bandwidth-stats/nodes
GET /api/bandwidth-stats/nodes/{uuid}/users
GET /api/bandwidth-stats/nodes/{uuid}/users/legacy
GET /api/bandwidth-stats/users/{uuid}
GET /api/bandwidth-stats/users/{uuid}/legacy
GET /api/config-profiles
GET /api/config-profiles/inbounds
GET /api/config-profiles/{uuid}
GET /api/config-profiles/{uuid}/computed-config
GET /api/config-profiles/{uuid}/inbounds
GET /api/external-squads
GET /api/external-squads/{uuid}
GET /api/hosts
GET /api/hosts/tags
GET /api/hosts/{uuid}
GET /api/hwid/devices
GET /api/hwid/devices/stats
GET /api/hwid/devices/top-users
GET /api/hwid/devices/{userUuid}
GET /api/infra-billing/history
GET /api/infra-billing/nodes
GET /api/infra-billing/providers
GET /api/infra-billing/providers/{uuid}
GET /api/internal-squads
GET /api/internal-squads/{uuid}
GET /api/internal-squads/{uuid}/accessible-nodes
GET /api/ip-control/fetch-ips/result/{jobId}
GET /api/ip-control/fetch-users-ips/result/{jobId}
GET /api/keygen
GET /api/metadata/node/{uuid}
GET /api/metadata/user/{uuid}
GET /api/node-plugins
GET /api/node-plugins/torrent-blocker
GET /api/node-plugins/torrent-blocker/stats
GET /api/node-plugins/{uuid}
GET /api/nodes
GET /api/nodes/tags
GET /api/nodes/{uuid}
GET /api/passkeys
GET /api/passkeys/registration/options
GET /api/remnawave-settings
GET /api/snippets
GET /api/sub/{shortUuid}
GET /api/sub/{shortUuid}/info
GET /api/sub/{shortUuid}/{clientType}
GET /api/subscription-page-configs
GET /api/subscription-page-configs/{uuid}
GET /api/subscription-request-history
GET /api/subscription-request-history/stats
GET /api/subscription-settings
GET /api/subscription-templates
GET /api/subscription-templates/{uuid}
GET /api/subscriptions
GET /api/subscriptions/by-short-uuid/{shortUuid}
GET /api/subscriptions/by-short-uuid/{shortUuid}/raw
GET /api/subscriptions/by-username/{username}
GET /api/subscriptions/by-uuid/{uuid}
GET /api/subscriptions/connection-keys/{uuid}
GET /api/subscriptions/subpage-config/{shortUuid}
GET /api/system/health
GET /api/system/metadata
GET /api/system/nodes/metrics
GET /api/system/stats
GET /api/system/stats/bandwidth
GET /api/system/stats/nodes
GET /api/system/stats/recap
GET /api/system/tools/x25519/generate
GET /api/tokens
GET /api/users
GET /api/users/by-email/{email}
GET /api/users/by-id/{id}
GET /api/users/by-short-uuid/{shortUuid}
GET /api/users/by-tag/{tag}
GET /api/users/by-telegram-id/{telegramId}
GET /api/users/by-username/{username}
GET /api/users/tags
GET /api/users/{uuid}
GET /api/users/{uuid}/accessible-nodes
GET /api/users/{uuid}/subscription-request-history
PATCH /api/config-profiles
PATCH /api/external-squads
PATCH /api/hosts
PATCH /api/infra-billing/nodes
PATCH /api/infra-billing/providers
PATCH /api/internal-squads
PATCH /api/node-plugins
PATCH /api/nodes
PATCH /api/passkeys
PATCH /api/remnawave-settings
PATCH /api/snippets
PATCH /api/subscription-page-configs
PATCH /api/subscription-settings
PATCH /api/subscription-templates
PATCH /api/users
POST /api/auth/login
POST /api/auth/oauth2/authorize
POST /api/auth/oauth2/callback
POST /api/auth/passkey/authentication/verify
POST /api/auth/register
POST /api/config-profiles
POST /api/config-profiles/actions/reorder
POST /api/external-squads
POST /api/external-squads/actions/reorder
POST /api/external-squads/{uuid}/bulk-actions/add-users
POST /api/hosts
POST /api/hosts/actions/reorder
POST /api/hosts/bulk/delete
POST /api/hosts/bulk/disable
POST /api/hosts/bulk/enable
POST /api/hosts/bulk/set-inbound
POST /api/hosts/bulk/set-port
POST /api/hwid/devices
POST /api/hwid/devices/delete
POST /api/hwid/devices/delete-all
POST /api/infra-billing/history
POST /api/infra-billing/nodes
POST /api/infra-billing/providers
POST /api/internal-squads
POST /api/internal-squads/actions/reorder
POST /api/internal-squads/{uuid}/bulk-actions/add-users
POST /api/ip-control/drop-connections
POST /api/ip-control/fetch-ips/{uuid}
POST /api/ip-control/fetch-users-ips/{nodeUuid}
POST /api/node-plugins
POST /api/node-plugins/actions/clone
POST /api/node-plugins/actions/reorder
POST /api/node-plugins/executor
POST /api/nodes
POST /api/nodes/actions/reorder
POST /api/nodes/actions/restart-all
POST /api/nodes/bulk-actions
POST /api/nodes/bulk-actions/profile-modification
POST /api/nodes/bulk-actions/update
POST /api/nodes/{uuid}/actions/disable
POST /api/nodes/{uuid}/actions/enable
POST /api/nodes/{uuid}/actions/reset-traffic
POST /api/nodes/{uuid}/actions/restart
POST /api/passkeys/registration/verify
POST /api/snippets
POST /api/subscription-page-configs
POST /api/subscription-page-configs/actions/clone
POST /api/subscription-page-configs/actions/reorder
POST /api/subscription-templates
POST /api/subscription-templates/actions/reorder
POST /api/system/testers/srr-matcher
POST /api/system/tools/happ/encrypt
POST /api/tokens
POST /api/users
POST /api/users/bulk/all/extend-expiration-date
POST /api/users/bulk/all/reset-traffic
POST /api/users/bulk/all/update
POST /api/users/bulk/delete
POST /api/users/bulk/delete-by-status
POST /api/users/bulk/extend-expiration-date
POST /api/users/bulk/reset-traffic
POST /api/users/bulk/revoke-subscription
POST /api/users/bulk/update
POST /api/users/bulk/update-squads
POST /api/users/resolve
POST /api/users/{uuid}/actions/disable
POST /api/users/{uuid}/actions/enable
POST /api/users/{uuid}/actions/reset-traffic
POST /api/users/{uuid}/actions/revoke
PUT /api/metadata/node/{uuid}
PUT /api/metadata/user/{uuid}
`

func userFields() []string {
	return []string{"username", "status", "shortUuid", "short_uuid", "trojanPassword", "vlessUuid", "ssPassword", "expireAt", "createdAt", "lastTrafficResetAt", "trafficLimitBytes", "trafficLimitStrategy", "telegramId", "telegram_id", "email", "description", "tag", "activeInternalSquads", "hwidDeviceLimit", "uuid", "externalSquadUuid", "external_squad_uuid", "subscriptionPageConfigUuid", "subscriptionPageConfigUUID", "subscription_page_config_uuid"}
}

func userUpdateFields() []string {
	return []string{"username", "uuid", "status", "expireAt", "trafficLimitBytes", "trafficLimitStrategy", "telegramId", "telegram_id", "email", "description", "tag", "activeInternalSquads", "hwidDeviceLimit", "externalSquadUuid", "external_squad_uuid", "subscriptionPageConfigUuid", "subscriptionPageConfigUUID", "subscription_page_config_uuid"}
}

func Match(catalog []Route, method, path string) (Route, bool) {
	for _, r := range catalog {
		if r.Method == method && r.re.MatchString(path) {
			return r, true
		}
	}
	if path != "/api/" && strings.HasSuffix(path, "/") {
		return Match(catalog, method, strings.TrimRight(path, "/"))
	}
	return Route{}, false
}

func compile(in []Route) []Route {
	for i := range in {
		p := regexp.QuoteMeta(in[i].Pattern)
		p = regexp.MustCompile(`\\\{[^}]+\\\}`).ReplaceAllStringFunc(p, func(param string) string {
			name := strings.TrimSuffix(strings.TrimPrefix(param, `\{`), `\}`)
			switch strings.ToLower(name) {
			case "uuid", "useruuid", "nodeuuid":
				return `[0-9a-fA-F-]{36}`
			case "id", "telegramid":
				return `[0-9]{1,32}`
			case "shortuuid":
				return `[A-Za-z0-9_-]{6,64}`
			case "clienttype":
				return `[A-Za-z0-9_-]{1,64}`
			default:
				return `[^/]{1,256}`
			}
		})
		p = strings.ReplaceAll(p, "\\{uuid\\}", `[0-9a-fA-F-]{36}`)
		p = strings.ReplaceAll(p, "\\{username\\}", `[^/]{1,128}`)
		p = strings.ReplaceAll(p, "\\{telegramId\\}", `[0-9]{1,32}`)
		p = strings.ReplaceAll(p, "\\{action\\}", `[^/]{1,64}`)
		p = strings.ReplaceAll(p, "\\{hwid\\}", `[^/]{1,128}`)
		p = strings.ReplaceAll(p, "\\{shortUuid\\}", `[A-Za-z0-9_-]{6,64}`)
		p = strings.ReplaceAll(p, "\\{clientType\\}", `[A-Za-z0-9_-]{1,64}`)
		in[i].re = regexp.MustCompile("^" + p + "$")
	}
	return in
}

type OpenAPIResult struct {
	Covered    []string                      `json:"covered"`
	Unknown    []string                      `json:"unknown"`
	Removed    []string                      `json:"removed"`
	Invalid    []string                      `json:"invalid,omitempty"`
	Ambiguous  []string                      `json:"ambiguous,omitempty"`
	Duplicates []string                      `json:"duplicates,omitempty"`
	Coverage   float64                       `json:"coverage"`
	ByGroup    map[string]OpenAPIGroupResult `json:"by_group,omitempty"`
}

type OpenAPIGroupResult struct {
	Covered int `json:"covered"`
	Unknown int `json:"unknown"`
	Removed int `json:"removed"`
}

func CheckOpenAPI(path string, catalog []Route) (OpenAPIResult, error) {
	if path == "" {
		return OpenAPIResult{}, errors.New("--spec is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return OpenAPIResult{}, err
	}
	if info.Size() > 20<<20 {
		return OpenAPIResult{}, errors.New("spec too large")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return OpenAPIResult{}, err
	}
	var spec struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		return OpenAPIResult{}, err
	}
	res := validateCatalog(catalog)
	want := map[string]bool{}
	shapeToKeys := map[string][]string{}
	for _, r := range catalog {
		key := routeKey(strings.ToUpper(r.Method), normalizeRouteShape(r.Pattern))
		want[key] = false
		shapeToKeys[key] = append(shapeToKeys[key], routeKey(r.Method, r.Pattern))
	}
	got := map[string]bool{}
	for p, methods := range spec.Paths {
		if methods == nil {
			continue
		}
		for m := range methods {
			if !isHTTPMethod(m) {
				continue
			}
			key := strings.ToUpper(m) + " " + normalizeRouteShape(p)
			got[key] = true
			if _, ok := want[key]; ok {
				want[key] = true
			}
			if len(shapeToKeys[key]) > 1 {
				res.Ambiguous = append(res.Ambiguous, key)
			}
		}
	}
	for key, covered := range want {
		if covered {
			res.Covered = append(res.Covered, key)
		} else {
			res.Removed = append(res.Removed, key)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			res.Unknown = append(res.Unknown, key)
		}
	}
	sort.Strings(res.Covered)
	sort.Strings(res.Unknown)
	sort.Strings(res.Removed)
	sort.Strings(res.Invalid)
	sort.Strings(res.Ambiguous)
	sort.Strings(res.Duplicates)
	if len(got) > 0 {
		res.Coverage = float64(len(res.Covered)) / float64(len(got)) * 100
	}
	res.ByGroup = groupOpenAPIResult(res)
	return res, nil
}

func CheckOpenAPIStrict(path string, catalog []Route) (OpenAPIResult, error) {
	res, err := CheckOpenAPI(path, catalog)
	if err != nil {
		return res, err
	}
	if len(res.Unknown) > 0 || len(res.Removed) > 0 || len(res.Invalid) > 0 || len(res.Ambiguous) > 0 || len(res.Duplicates) > 0 {
		return res, errors.New("route catalog is not strict-clean")
	}
	return res, nil
}

func validateCatalog(catalog []Route) OpenAPIResult {
	var res OpenAPIResult
	seen := map[string]bool{}
	for _, r := range catalog {
		key := routeKey(r.Method, normalizeRouteShape(r.Pattern))
		if seen[key] {
			res.Duplicates = append(res.Duplicates, key)
		}
		seen[key] = true
		if r.Name == "" || r.Method == "" || r.Pattern == "" || r.Support == "" {
			res.Invalid = append(res.Invalid, key+": empty required metadata")
		}
		switch r.Support {
		case PolicyEnforced, Privileged, PublicSubscription:
		case Unsupported:
			if r.UnsupportedReason == "" {
				res.Invalid = append(res.Invalid, key+": unsupported route missing reason")
			}
		default:
			res.Invalid = append(res.Invalid, key+": invalid support level")
		}
	}
	return res
}

func normalizeRouteShape(p string) string {
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(p, "{}")
}

func routeKey(method, pattern string) string {
	return strings.ToUpper(method) + " " + pattern
}

func isHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func groupOpenAPIResult(res OpenAPIResult) map[string]OpenAPIGroupResult {
	byGroup := map[string]OpenAPIGroupResult{}
	add := func(key string, fn func(OpenAPIGroupResult) OpenAPIGroupResult) {
		_, path, _ := strings.Cut(key, " ")
		group := routeGroup(path)
		byGroup[group] = fn(byGroup[group])
	}
	for _, key := range res.Covered {
		add(key, func(g OpenAPIGroupResult) OpenAPIGroupResult { g.Covered++; return g })
	}
	for _, key := range res.Unknown {
		add(key, func(g OpenAPIGroupResult) OpenAPIGroupResult { g.Unknown++; return g })
	}
	for _, key := range res.Removed {
		add(key, func(g OpenAPIGroupResult) OpenAPIGroupResult { g.Removed++; return g })
	}
	return byGroup
}

func routeGroup(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return "other"
	}
	if parts[1] == "system" && strings.Contains(path, "/stats/bandwidth") {
		return "bandwidth-stats"
	}
	if parts[1] == "system" && strings.Contains(path, "/tools/") {
		return "keygen-tools"
	}
	if parts[1] == "auth" || parts[1] == "passkeys" {
		return "auth-passkeys"
	}
	if parts[1] == "metadata" || parts[1] == "remnawave-settings" {
		return "metadata"
	}
	if parts[1] == "sub" {
		return "subscriptions"
	}
	return parts[1]
}

func routeName(method, pattern string) string {
	name := strings.TrimPrefix(pattern, "/api/")
	name = strings.ReplaceAll(name, "{", "")
	name = strings.ReplaceAll(name, "}", "")
	name = strings.NewReplacer("/", ".", "-", "_").Replace(name)
	return strings.ToLower(method) + "." + name
}

func specificity(pattern string) int {
	score := len(strings.Split(strings.Trim(pattern, "/"), "/")) * 10
	score += len(pattern)
	score -= strings.Count(pattern, "{") * 20
	return score
}
