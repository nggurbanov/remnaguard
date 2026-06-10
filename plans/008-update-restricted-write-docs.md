# Plan 008: Update restricted-write documentation to match runtime behavior

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- docs/policy.md docs/local-staging.md README.md internal/server/server.go internal/server/server_test.go`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: docs
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

`docs/policy.md` currently says bulk user changes, squad writes,
subscription page writes, node/host/infrastructure writes, token management,
and admin management stay privileged. The runtime and tests now allow selected
config-profile, host, node, subscription-template, and squad writes when
restricted write safety and resource allowlists are configured. Stale safety
docs are worse than missing docs because operators may either avoid supported
capability or assume unsupported writes are safe.

## Current state

- Runtime promotes selected write routes to policy-enforced when restricted writes and single-writer mode are enabled.
- Tests cover selected infra/squad/template restricted writes.
- Docs still describe those write areas as privileged-only.

Relevant excerpts:

```markdown
docs/policy.md:66
Restricted write support covers:

- `POST /api/users` ...
- `PATCH /api/users` ...
- selected user actions: disable, enable, reset traffic, revoke;
- HWID create/delete/delete-all with user ownership preflight and `hwid:write`.

Bulk user changes, squad writes, subscription page writes, node/host/infrastructure
writes, token management, and admin management stay privileged.
```

```go
// internal/server/server.go:1230
case "post.config_profiles", "patch.config_profiles":
    route.Support = routes.PolicyEnforced
    route.Scopes = []string{"config-profiles:write"}
case "post.hosts", "patch.hosts":
    route.Support = routes.PolicyEnforced
    route.Scopes = []string{"hosts:write"}
case "post.nodes", "patch.nodes", "post.nodes.uuid.actions.disable", ...:
    route.Support = routes.PolicyEnforced
    route.Scopes = []string{"nodes:write"}
case "patch.subscription_templates":
    route.Support = routes.PolicyEnforced
case "patch.internal_squads":
    route.Support = routes.PolicyEnforced
case "patch.external_squads":
    route.Support = routes.PolicyEnforced
```

```go
// internal/server/server_test.go:689
func TestRestrictedInfraWritesEnforceResourceAllowlists(t *testing.T) {
    cfg.Tokens[0].Scopes = []string{"subscription-templates:write", "internal-squads:write", "nodes:write"}
    // allowed requests pass; denied requests do not reach upstream
}
```

Repo conventions to match:

- Docs are concise and security-oriented.
- They avoid copying Remnawave proprietary docs or schemas.
- They describe support levels and constraints rather than full API reference.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Docs grep | `rg -n "Restricted write support|Bulk user changes|nodes:write|hosts:write|internal-squads:write" docs README.md` | output reflects updated docs |
| Tests | `go test ./...` | exit 0 |
| Whitespace | `git diff --check` | exit 0 |

## Scope

**In scope**:

- `docs/policy.md`
- `docs/local-staging.md` if its restricted-write description is stale
- `README.md` only if its high-level feature bullets need a small clarification

**Out of scope**:

- Do not change Go source in this docs plan.
- Do not add detailed Remnawave request/response schemas.
- Do not document unsupported routes as supported.
- Do not include production tokens, UUIDs, domains, or captured request bodies.

## Git workflow

- Branch: `codex/008-update-restricted-write-docs`
- Commit message style: imperative sentence, for example `Update restricted write policy docs`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Rewrite the restricted-write support list

Update `docs/policy.md` so the restricted write section says support currently covers:

- User create/update with preflight and post-write verification.
- Selected user actions: disable, enable, reset traffic, revoke.
- HWID create/delete/delete-all with user ownership preflight.
- Config profile create/update when `config-profiles:write` is paired with `allowed_config_profiles` or `allow_all_config_profiles`.
- Host create/update when `hosts:write` is paired with `allowed_hosts` or `allow_all_hosts`.
- Node create/update and selected node actions when `nodes:write` is paired with `allowed_nodes` or `allow_all_nodes`.
- Subscription template update when `subscription-templates:write` is paired with `allowed_subscription_templates`.
- Internal/external squad update when the matching write scope is paired with `allowed_writable_internal_squads` or `allowed_writable_external_squads`.

Keep the section concise. Do not list every endpoint shape.

**Verify**: `rg -n "config-profiles:write|hosts:write|nodes:write|subscription-templates:write|allowed_writable_internal_squads" docs/policy.md` -> all terms appear in the updated section.

### Step 2: Correct the privileged-only sentence

Replace the stale privileged-only sentence with a precise one. It should still say these remain privileged-only:

- Bulk user changes.
- Subscription page writes.
- Token management.
- Admin management.
- Any route not explicitly listed as restricted-write supported.

Do not say all node/host/infrastructure writes stay privileged, because selected ones no longer do.

**Verify**: `rg -n "node/host/infrastructure writes.*privileged|squad writes.*privileged" docs/policy.md` -> no stale broad sentence remains.

### Step 3: Check related docs for drift

Read `docs/local-staging.md` and `README.md` for short statements that now conflict with the updated policy docs. Update only direct conflicts.

**Verify**: `rg -n "restricted writes|nodes:write|hosts:write|squad writes|subscription page writes" docs README.md` -> no contradiction with runtime behavior.

### Step 4: Run verification

Run docs whitespace and the test suite.

**Verify**:

- `git diff --check` -> exit 0
- `go test ./...` -> exit 0

## Test plan

- Documentation-only plan. Use grep checks above to verify stale text was removed and supported scopes are mentioned.
- Run `go test ./...` to ensure no accidental source changes broke the build if files drifted.

## Done criteria

- [ ] `docs/policy.md` accurately lists current restricted-write support.
- [ ] Stale "node/host/infrastructure writes stay privileged" wording is removed or narrowed.
- [ ] Related docs do not contradict the updated policy section.
- [ ] `git diff --check` and `go test ./...` exit 0.
- [ ] No Go source files are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Source code behavior has drifted and no longer matches the excerpts.
- You cannot determine whether a route is supported without reading external Remnawave docs.
- The docs update would require publishing real deployment identifiers or request bodies.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

When restricted-write support changes, update `docs/policy.md` in the same PR as the code. Reviewers should compare docs against `effectiveRoute`, `validateRestrictedWriteAllowlists`, and restricted-write tests.
