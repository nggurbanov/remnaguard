package policy

import (
	"fmt"

	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/routes"
)

type Decision struct {
	Allow  bool
	Reason string
	Route  routes.Route
}

func (d Decision) String() string {
	if d.Allow {
		return fmt.Sprintf("allow: %s", d.Route.Name)
	}
	return "deny: " + d.Reason
}

func Decide(tok *config.TokenPolicy, route routes.Route) Decision {
	if tok == nil || tok.Disabled {
		return Decision{Reason: "missing_token", Route: route}
	}
	switch route.Support {
	case routes.Unsupported:
		return Decision{Reason: "unsupported_route", Route: route}
	case routes.Privileged:
		if hasPrivilegedScope(tok.Scopes) {
			return Decision{Allow: true, Route: route}
		}
		return Decision{Reason: "privileged_scope_required", Route: route}
	case routes.PolicyEnforced:
		for _, scope := range route.Scopes {
			if hasScope(tok.Scopes, scope) || hasPrivilegedScope(tok.Scopes) {
				return Decision{Allow: true, Route: route}
			}
		}
		return Decision{Reason: "missing_scope", Route: route}
	case routes.PublicSubscription:
		return Decision{Reason: "public_subscription_not_authenticated", Route: route}
	default:
		return Decision{Reason: "unknown_support", Route: route}
	}
}

func hasScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}

func hasPrivilegedScope(scopes []string) bool {
	return hasScope(scopes, "remnawave:*") || hasScope(scopes, "privileged:*")
}
