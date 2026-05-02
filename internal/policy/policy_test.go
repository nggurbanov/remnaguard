package policy

import (
	"net/http"
	"testing"

	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/routes"
)

func TestPrivilegedRequiresPrivilegedScope(t *testing.T) {
	route, ok := routes.Match(routes.Catalog("2.7.4"), http.MethodGet, "/api/nodes")
	if !ok {
		t.Fatal("route not found")
	}
	tok := &config.TokenPolicy{ID: "restricted", Scopes: []string{"users:read"}}
	if Decide(tok, route).Allow {
		t.Fatal("restricted read scope must not allow privileged infra route")
	}
	tok.Scopes = append(tok.Scopes, "remnawave:*")
	if !Decide(tok, route).Allow {
		t.Fatal("remnawave:* should allow privileged route")
	}
}

func TestPolicyEnforcedAllowsMatchingScope(t *testing.T) {
	route, ok := routes.Match(routes.Catalog("2.7.4"), http.MethodGet, "/api/users/00000000-0000-0000-0000-000000000000")
	if !ok {
		t.Fatal("route not found")
	}
	tok := &config.TokenPolicy{ID: "restricted", Scopes: []string{"users:read"}}
	if !Decide(tok, route).Allow {
		t.Fatal("users:read should allow singleton read")
	}
}
