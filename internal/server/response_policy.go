package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/proxy"
	"github.com/nggurbanov/remnaguard/internal/remnawave"
	"github.com/nggurbanov/remnaguard/internal/routes"
)

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
			if remnawave.IsEmptyUserResponse(res.Body) {
				return nil
			}
			return err
		}
		return remnawave.OwnsUser(tok, user)
	case "squad.internal.read", "squad.external.read":
		return redactSquadResponse(res)
	case "subscription_page_config.read":
		return enforceSubscriptionPageConfigResponse(tok, res)
	default:
		return nil
	}
}

func filterResponsePolicy(route routes.Route, tok *config.TokenPolicy, res *proxy.Response, req *http.Request, rawQuery string) error {
	if route.Support != routes.PolicyEnforced || res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil
	}
	if tokenHasPrivilegedScope(tok) {
		return nil
	}
	switch route.Name {
	case "user.list":
		return filterJSONListPaged(res, panelResponsePage(req, rawQuery), func(item any) bool {
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
				sanitizeSquadListObject(item)
				return true
			}
			allowed := contains(tok.Constraints.AllowedInternalSquads, objectUUID(item))
			if allowed {
				sanitizeSquadListObject(item)
			}
			return allowed
		})
	case "squad.external.list":
		return filterJSONList(res, func(item any) bool {
			if len(tok.Constraints.AllowedExternalSquads) == 0 {
				sanitizeSquadListObject(item)
				return true
			}
			allowed := contains(tok.Constraints.AllowedExternalSquads, objectUUID(item))
			if allowed {
				sanitizeSquadListObject(item)
			}
			return allowed
		})
	case "subscription_page_config.list":
		return filterJSONList(res, func(item any) bool {
			return subscriptionPageConfigAllowed(tok, objectUUID(item))
		})
	default:
		return nil
	}
}

func tokenHasPrivilegedScope(tok *config.TokenPolicy) bool {
	if tok == nil {
		return false
	}
	for _, scope := range tok.Scopes {
		if scope == "remnawave:*" || scope == "privileged:*" {
			return true
		}
	}
	return false
}

func enforceSubscriptionPageConfigResponse(tok *config.TokenPolicy, res *proxy.Response) error {
	if len(tok.Constraints.AllowedSubscriptionPageConfigs) == 0 {
		return nil
	}
	var root any
	dec := json.NewDecoder(bytes.NewReader(res.Body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return err
	}
	if subscriptionPageConfigNodeAllowed(tok, root) {
		return nil
	}
	return fmt.Errorf("subscription_page_config_denied")
}

func subscriptionPageConfigNodeAllowed(tok *config.TokenPolicy, node any) bool {
	switch typed := node.(type) {
	case map[string]any:
		if subscriptionPageConfigAllowed(tok, objectUUID(typed)) {
			return true
		}
		for _, key := range []string{"subscriptionPageConfigUuid", "subscriptionPageConfigUUID", "subscription_page_config_uuid", "uuid"} {
			if s, ok := typed[key].(string); ok && subscriptionPageConfigAllowed(tok, s) {
				return true
			}
		}
		for _, key := range []string{"response", "config", "subscriptionPageConfig", "subscription_page_config", "subpageConfig", "subpage_config"} {
			child, ok := typed[key]
			if ok && subscriptionPageConfigNodeAllowed(tok, child) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if subscriptionPageConfigNodeAllowed(tok, item) {
				return true
			}
		}
	}
	return false
}

func subscriptionPageConfigAllowed(tok *config.TokenPolicy, uuid string) bool {
	if len(tok.Constraints.AllowedSubscriptionPageConfigs) == 0 {
		return true
	}
	return uuid != "" && contains(tok.Constraints.AllowedSubscriptionPageConfigs, uuid)
}

func redactSquadResponse(res *proxy.Response) error {
	var root any
	dec := json.NewDecoder(bytes.NewReader(res.Body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return err
	}
	if !sanitizeSquadNode(root) {
		return fmt.Errorf("unfilterable_squad_response")
	}
	body, err := json.Marshal(root)
	if err != nil {
		return err
	}
	res.Body = body
	res.Header.Del("Content-Length")
	return nil
}

func sanitizeSquadNode(node any) bool {
	switch typed := node.(type) {
	case map[string]any:
		if objectUUID(typed) != "" {
			sanitizeSquadObject(typed)
			return true
		}
		for _, key := range []string{"response", "squad", "internalSquad", "externalSquad"} {
			child, ok := typed[key]
			if !ok {
				continue
			}
			if sanitizeSquadNode(child) {
				return true
			}
		}
	}
	return false
}

func sanitizeSquadObject(item any) {
	obj, ok := item.(map[string]any)
	if !ok {
		return
	}
	allowed := map[string]bool{"uuid": true, "name": true, "viewPosition": true}
	for key := range obj {
		if !allowed[key] {
			delete(obj, key)
		}
	}
}

func sanitizeSquadListObject(item any) {
	obj, ok := item.(map[string]any)
	if !ok {
		return
	}
	delete(obj, "rawInbound")
	delete(obj, "rawInbounds")
	delete(obj, "raw_inbound")
	delete(obj, "raw_inbounds")
}

func filterJSONList(res *proxy.Response, keep func(any) bool) error {
	return filterJSONListPaged(res, nil, keep)
}

type responsePage struct {
	start int
	size  int
}

func panelResponsePage(req *http.Request, rawQuery string) *responsePage {
	if panelAuditContextFromRequest(req) == nil {
		return nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	size := firstPositiveInt(values, "size", "limit")
	if size <= 0 {
		return nil
	}
	start := firstNonNegativeInt(values, "start", "offset")
	if start == 0 {
		if page := firstPositiveInt(values, "page"); page > 1 {
			start = (page - 1) * size
		}
	}
	return &responsePage{start: start, size: size}
}

func firstPositiveInt(values url.Values, keys ...string) int {
	for _, key := range keys {
		value := strings.TrimSpace(values.Get(key))
		if value == "" {
			continue
		}
		n, err := strconv.Atoi(value)
		if err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func firstNonNegativeInt(values url.Values, keys ...string) int {
	for _, key := range keys {
		value := strings.TrimSpace(values.Get(key))
		if value == "" {
			continue
		}
		n, err := strconv.Atoi(value)
		if err == nil && n >= 0 {
			return n
		}
	}
	return 0
}

func filterJSONListPaged(res *proxy.Response, page *responsePage, keep func(any) bool) error {
	var root any
	dec := json.NewDecoder(bytes.NewReader(res.Body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return err
	}
	filtered, count, ok := filterListNodePaged(root, page, keep)
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

func filterListNodePaged(node any, page *responsePage, keep func(any) bool) (any, int, bool) {
	switch typed := node.(type) {
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			if keep(item) {
				out = append(out, item)
			}
		}
		count := len(out)
		if page != nil {
			out = slicePage(out, page)
		}
		return out, count, true
	case map[string]any:
		for _, key := range []string{"response", "users", "internalSquads", "externalSquads", "subscriptionPageConfigs", "subscription_page_configs", "configs", "items", "data"} {
			child, ok := typed[key]
			if !ok {
				continue
			}
			filtered, count, ok := filterListNodePaged(child, page, keep)
			if ok {
				typed[key] = filtered
				return typed, count, true
			}
		}
	}
	return nil, 0, false
}

func slicePage(items []any, page *responsePage) []any {
	if page == nil || page.size <= 0 {
		return items
	}
	if page.start >= len(items) {
		return []any{}
	}
	end := page.start + page.size
	if end > len(items) {
		end = len(items)
	}
	return items[page.start:end]
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
