# Plan 002: Reject unknown `allowed_request_fields` route keys

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- internal/config/config.go internal/config/config_test.go internal/routes/catalog.go internal/server/server.go internal/server/server_test.go`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S/M
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

`allowed_request_fields` is a token-specific body-field allowlist. Today the
config validator only checks that its route keys and field lists are non-empty.
At request time, an unmatched route key is ignored, so a typo can silently turn
off the intended field restriction. A security-facing config should fail closed
when policy keys do not map to a known route.

## Current state

- `internal/config/config.go` validates token constraints.
- `internal/routes/catalog.go` is the authoritative route catalog.
- `internal/server/server.go` currently accepts both `route.Name` and
  `route.Method + " " + route.Pattern` as lookup keys.
- `internal/server/server_test.go` has an existing positive enforcement test.

Relevant excerpts:

```go
// internal/config/config.go:410
for routeName, fields := range tok.Constraints.AllowedRequestFields {
    if strings.TrimSpace(routeName) == "" {
        return fmt.Errorf("empty allowed_request_fields route on token %q", tok.ID)
    }
    if len(fields) == 0 {
        return fmt.Errorf("empty allowed_request_fields for route %q on token %q", routeName, tok.ID)
    }
}
```

```go
// internal/server/server.go:1634
allowed, ok := tok.Constraints.AllowedRequestFields[route.Name]
if !ok {
    allowed, ok = tok.Constraints.AllowedRequestFields[route.Method+" "+route.Pattern]
}
if !ok {
    return nil
}
```

```go
// internal/routes/catalog.go:22
type Route struct {
    Name    string
    Method  string
    Pattern string
}

// internal/routes/catalog.go:44
func remnawave274Catalog() []Route {
    routes := make([]Route, 0, 185)
    // static Remnawave 2.7.4 operations plus explicit overrides
}
```

Repo conventions to match:

- Config validation returns descriptive `fmt.Errorf(...)` errors that include the token ID.
- Tests in `internal/config/config_test.go` use table-driven mutation of `Defaults()`.
- Route names like `user.create` are canonical; method/pattern aliases such as `POST /api/users` are also currently supported by runtime lookup.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Config tests | `go test ./internal/config -count=1` | exit 0 |
| Server focused test | `go test ./internal/server -run TestTokenSpecificAllowedRequestFields -count=1` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |

## Scope

**In scope**:

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/routes/catalog.go` only if a small exported helper avoids duplicating route-key construction
- `internal/server/server.go` only if you choose to share the key construction helper with runtime enforcement
- `internal/server/server_test.go` only if existing tests need a small adjustment

**Out of scope**:

- Do not redesign the policy model.
- Do not remove method/pattern aliases unless a reviewer explicitly approves the breaking change.
- Do not validate request field names against route body schemas in this plan; this plan is only about route-key typos.
- Do not change request-time behavior except to keep it aligned with the validated key forms.

## Git workflow

- Branch: `codex/002-validate-allowed-request-fields-keys`
- Commit message style: imperative sentence, for example `Reject unknown allowed request field routes`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Add known route-key validation

In `internal/config/config.go`, extend validation of `tok.Constraints.AllowedRequestFields` so every key must match one of:

- `route.Name`
- `route.Method + " " + route.Pattern`

Use `routes.Catalog(c.Compatibility.EffectiveVersion())` as the source of truth. It is acceptable for `config` to import `internal/routes` if this does not create an import cycle. If it does create a cycle due to drift, STOP and report.

Implementation target:

- Build a `map[string]bool` of accepted keys once during `Validate()`, outside the token loop.
- Preserve the existing empty-key and empty-field validation.
- Return an error like `unknown allowed_request_fields route %q on token %q`.
- Keep exact matching for method/pattern aliases so runtime lookup and config validation agree.

**Verify**: `go test ./internal/config -run TestValidateRejectsInvalidExtendedConstraints -count=1` -> exits 0.

### Step 2: Add explicit tests for bad and good route keys

In `internal/config/config_test.go`, add or extend tests to cover:

- Unknown route name such as `user.cretae` is rejected.
- Unknown method/pattern alias such as `POST /api/not-real` is rejected.
- Canonical route name `user.create` is accepted.
- Method/pattern alias `POST /api/users` is accepted.

Use the existing `Defaults()` plus `Upstream.BaseURL`, `Upstream.Bearer`, token, credential, and pepper setup pattern from nearby tests. Do not introduce real credentials.

**Verify**: `go test ./internal/config -count=1` -> exits 0.

### Step 3: Keep runtime lookup in sync

If you introduced a helper for route-key construction, use it from `validateTokenRequestFields` in `internal/server/server.go` so config validation and runtime enforcement cannot drift. If you kept the key construction local to config, leave runtime enforcement unchanged.

**Verify**: `go test ./internal/server -run TestTokenSpecificAllowedRequestFields -count=1` -> exits 0.

### Step 4: Run standard gates

Run the full verification set.

**Verify**:

- `go test ./...` -> exit 0
- `go vet ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- Config tests for unknown canonical route key rejection.
- Config tests for unknown method/pattern alias rejection.
- Config tests proving both currently supported valid key forms still work.
- Existing server test proves a valid key still denies an unlisted field before upstream.

## Done criteria

- [ ] Config load/validation fails for any `allowed_request_fields` route key that is not in the current catalog by name or method/pattern alias.
- [ ] Existing valid examples under `configs/` and `examples/` still validate.
- [ ] Runtime enforcement still honors valid `user.create` keys.
- [ ] `go test ./...`, `go vet ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside the in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Importing `internal/routes` from `internal/config` creates a cycle.
- Existing checked-in example configs use keys that are intentionally not catalog route names or method/pattern aliases.
- A reviewer wants field-name validation too; that is a separate policy decision.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

When new catalog routes are added, this validation will automatically accept their canonical names and method/pattern aliases. Reviewers should scrutinize any future change that weakens unknown-key rejection because policy typos should not fail open.
