package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/jsonpolicy"
	"github.com/nggurbanov/remnaguard/internal/remnawave"
	"github.com/nggurbanov/remnaguard/internal/routes"
)

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
	if len(route.AllowedFields) > 0 {
		if err := jsonpolicy.ValidateFields(obj, route.AllowedFields); err != nil {
			return err
		}
	}
	if err := validateTokenRequestFields(obj, route, tok); err != nil {
		return err
	}
	if strings.HasPrefix(route.Name, "user.") {
		if err := validateUserConstraints(obj, tok); err != nil {
			return err
		}
	}
	if err := validateResourceWriteConstraints(obj, route, tok); err != nil {
		return err
	}
	if err := validateResourceCreateConstraints(route, tok); err != nil {
		return err
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

func validateResourceCreateConstraints(route routes.Route, tok *config.TokenPolicy) error {
	if tok == nil || route.Method != http.MethodPost {
		return nil
	}
	switch route.Name {
	case "post.config_profiles":
		if !tok.Constraints.AllowAllConfigProfiles {
			return fmt.Errorf("config_profile_denied")
		}
	case "post.hosts":
		if !tok.Constraints.AllowAllHosts {
			return fmt.Errorf("host_denied")
		}
	case "post.nodes":
		if !tok.Constraints.AllowAllNodes {
			return fmt.Errorf("node_denied")
		}
	}
	return nil
}

func validateResourceWriteConstraints(obj map[string]json.RawMessage, route routes.Route, tok *config.TokenPolicy) error {
	if tok == nil {
		return nil
	}
	if route.Method != http.MethodPatch {
		return nil
	}
	uuid := objectUUIDFromRaw(obj)
	switch route.Name {
	case "patch.subscription_templates":
		return requireAllowedUUID(uuid, tok.Constraints.AllowedSubscriptionTemplates, "subscription_template_denied")
	case "patch.internal_squads":
		return requireAllowedUUID(uuid, tok.Constraints.AllowedWritableInternalSquads, "internal_squad_denied")
	case "patch.external_squads":
		return requireAllowedUUID(uuid, tok.Constraints.AllowedWritableExternalSquads, "external_squad_denied")
	case "patch.config_profiles":
		return requireAllowedUUIDOrAll(uuid, tok.Constraints.AllowedConfigProfiles, tok.Constraints.AllowAllConfigProfiles, "config_profile_denied")
	case "patch.hosts":
		return requireAllowedUUIDOrAll(uuid, tok.Constraints.AllowedHosts, tok.Constraints.AllowAllHosts, "host_denied")
	case "patch.nodes":
		return requireAllowedUUIDOrAll(uuid, tok.Constraints.AllowedNodes, tok.Constraints.AllowAllNodes, "node_denied")
	default:
		return nil
	}
}

func objectUUIDFromRaw(obj map[string]json.RawMessage) string {
	for _, field := range []string{"uuid", "id"} {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		var uuid string
		if err := json.Unmarshal(raw, &uuid); err == nil {
			return uuid
		}
	}
	return ""
}

func requireAllowedUUID(uuid string, allowed []string, reason string) error {
	if uuid == "" {
		return fmt.Errorf("missing_uuid")
	}
	if !contains(allowed, uuid) {
		return errors.New(reason)
	}
	return nil
}

func requireAllowedUUIDOrAll(uuid string, allowed []string, allowAll bool, reason string) error {
	if allowAll {
		if uuid == "" {
			return fmt.Errorf("missing_uuid")
		}
		return nil
	}
	return requireAllowedUUID(uuid, allowed, reason)
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
	for _, field := range []string{"telegramId", "telegram_id"} {
		raw, ok := obj[field]
		if !ok {
			continue
		}
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
	if len(c.AllowedExternalSquads) > 0 {
		for _, field := range []string{"externalSquadUuid", "external_squad_uuid"} {
			raw, ok := obj[field]
			if !ok {
				continue
			}
			var id *string
			if err := json.Unmarshal(raw, &id); err != nil {
				return fmt.Errorf("invalid_external_squad")
			}
			if id != nil && *id != "" && !contains(c.AllowedExternalSquads, *id) {
				return fmt.Errorf("external_squad_denied")
			}
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
